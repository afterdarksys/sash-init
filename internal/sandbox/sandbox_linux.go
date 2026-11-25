// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// Helper fd layout. The parent places every fd; the helper never infers a
// role from an fd merely being open, since the Go runtime itself opens fds
// (such as the cgroup cpu.max file) at the lowest free number.
const (
	fdReady  = 3 // readiness pipe, only when the spec says notify
	fdExec   = 4 // O_PATH fd of the checked target, run with execveat
	fdSpec   = 5
	fdStatus = 6
	fdCgroup = 7 // sync pipe: one byte once the parent moved the helper into its cgroup
	// fdPass is where Options.Pass sits in the helper; it is moved to fd 3
	// and up just before exec. fds 3 to 7 are always filled when passing,
	// so nothing the Go runtime opens can sit where a passed fd goes.
	fdPass = 8
	// fdHigh is where the exec and status fds move when passed fds take
	// their places.
	fdHigh  = 64
	maxSpec = 64 * 1024
	maxLine = 1024

	// execPathFD runs a script's exec fd on a direct launch.
	execPathFD = "/proc/self/fd/4"
	// execFDMin keeps a binary's exec fd clear of the fds placed in the child.
	execFDMin = 10

	// Landlock ABI 1 file rights. ABI 2 adds REFER, ABI 3 TRUNCATE, ABI 5
	// IOCTL_DEV (ABI 4 adds only network rights).
	accessV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	// accessOptional is granted only when the ABI handles it. An ABI that
	// does not handle a right leaves that operation unrestricted, so a
	// read_write grant still holds without it.
	accessOptional = unix.LANDLOCK_ACCESS_FS_TRUNCATE

	accessRead = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR
	accessWrite = accessRead |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE
	accessHandled = accessWrite |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
		unix.LANDLOCK_ACCESS_FS_REFER |
		unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// errExec is the post-status failure. It is compared with == and never wrapped.
var errExec = errors.New("exec")

var errLines map[string][]byte

// statusFD and execFD are fdStatus and fdExec until passed fds take those
// numbers (placePass); the helper is single-threaded by then.
var (
	statusFD = fdStatus
	execFD   = fdExec
)

var specKeys = map[string]struct{}{
	"no_new_privs": {}, "read_only_paths": {}, "read_write_paths": {}, "caps": {},
	"notify": {}, "sandbox": {}, "cgroup": {}, "pass": {}, "umask": {}, "rlimits": {},
	"stdout_file": {}, "stderr_file": {}, "stderr_stdout": {},
	"setuid_to": {}, "setgid_to": {},
}

var childTokens = map[string]struct{}{
	"sandbox_cap": {}, "sandbox_path": {}, "sandbox_privs": {}, "sandbox_overlap": {},
	"openat2_unavailable": {}, "landlock_unavailable": {}, "landlock_abi": {},
	"exec_relative": {}, "exec_not_file": {}, "failed": {}, "sandbox_root": {},
	"cgroup_join": {}, "stream_denied": {},
	"sandbox_cap_denied": {}, "sandbox_ids": {}, "seccomp_unavailable": {}, "sandbox_proc": {},
}

func okLine(abi int, idFilter bool) []byte {
	claim := SandboxClaim(abi)
	if idFilter {
		claim += idFilterClaim
	}
	return []byte("{\"ok\":true,\"claim\":\"" + claim + "\"}\n")
}

// noneLine is the success status of a helper that only joined a cgroup.
var noneLine = []byte("{\"ok\":true,\"claim\":\"" + claimNone + "\"}\n")

func init() {
	errLines = make(map[string][]byte, len(childTokens)+1)
	for tok := range childTokens {
		errLines[tok] = []byte("{\"ok\":false,\"error\":\"" + tok + "\",\"claim\":\"\"}\n")
	}
	errLines["sandbox_timeout"] = []byte("{\"ok\":false,\"error\":\"sandbox_timeout\",\"claim\":\"\"}\n")
}

type pathFD struct {
	fd int
	rw bool
}

type held struct {
	ruleset int
	paths   []pathFD
}

// ApplyCLI is the re-exec entry. It reads the spec on fd 5, writes one
// setup status on fd 6, then execs the checked target held on fd 4. When the
// spec says cgroup it first writes its own pid to the cgroup.procs on fd 7
// (cgroup_join on failure); when it says no sandbox it applies none and
// claims "none".
// Successful exec closes fd 6; a failed exec appends an error status before
// exiting. A missing handshake fd exits 2 and writes nothing.
//
// Threats: readiness is used only when the spec says notify, and fd 3 must
// then be a pipe. Every other fd from 3 up is marked close-on-exec before
// exec, so nothing the helper or the Go runtime opened reaches the target.
// argv[0] is never looked up; the target is the fd the parent checked. The
// cgroup is joined before anything else, so the target and all it forks
// start inside it.
func ApplyCLI(args []string) int {
	runtime.LockOSThread()
	argv, ok := splitApply(args)
	if !ok {
		return 2
	}
	if !isFIFO(fdSpec) || !isFIFO(fdStatus) {
		return 2
	}
	if err := checkArgv(argv); err != nil {
		return writeStatus(fail.Token(err))
	}
	raw, err := readSpec()
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	sb, notify, join, err := decodeSpec(raw)
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	if notify && !isFIFO(fdReady) {
		return writeStatus("failed")
	}
	pass, umask, limits, err := decodeExtra(raw)
	if err != nil || pass > 0 && (notify || sb == nil) || len(limits) > 0 && sb == nil {
		return writeStatus("failed")
	}
	for fd := fdPass; fd < fdPass+pass; fd++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return writeStatus("failed")
		}
	}
	if join {
		if err := joinCgroup(); err != nil {
			return writeStatus("cgroup_join")
		}
	}
	if sb != nil && (unix.Geteuid() == 0 || unix.Getuid() == 0) {
		return writeStatus("sandbox_root")
	}
	// First, before anything else runs: cut the capability state the
	// supervisor raised down to exactly the granted set.
	if sb != nil && len(sb.Caps) > 0 {
		if err := enterCaps(sb.Caps); err != nil {
			return writeStatus(fail.Token(err))
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fdExec, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o111 == 0 {
		return writeStatus("exec_not_file")
	}
	if err := cloexecFrom(notify); err != nil {
		return writeStatus("failed")
	}
	env := os.Environ()
	if notify {
		env = append(env, "SAHINIT_READY_FD=3")
	}
	argv = append([]string{}, argv...)
	// The umask, then the stream files, as the target's uid and before
	// Landlock, which may not let it write there.
	if umask >= 0 {
		unix.Umask(umask)
	}
	if err := openStreams(raw); err != nil {
		return writeStatus(fail.Token(err))
	}
	status := noneLine
	if sb != nil {
		h, abi, err := restrict(sb)
		cerr := closeHeld(h)
		if err != nil {
			return writeStatus(fail.Token(err))
		}
		if cerr != nil {
			return writeStatus("failed")
		}
		status = okLine(abi, needsIDFilter(sb))
	}
	if err := setRlimits(limits); err != nil {
		return writeStatus("failed")
	}
	if pass > 0 {
		if err := placePass(pass); err != nil {
			return writeStatus("failed")
		}
	}
	if err := writeFD(statusFD, status); err != nil {
		return 1
	}
	if err := execTarget(argv, env, pass == 0); err == errExec {
		return writeStatus("failed")
	}
	return 1
}

// joinCgroup waits on the sync pipe (fd 7) until the parent has written the
// helper's pid into the service cgroup's cgroup.procs and sends one byte.
// End of file means the parent could not move it.
//
// Threats: the helper never holds a cgroup.procs fd, so a process that can
// ptrace it or take its fds (pidfd_getfd) gains nothing to move itself with.
func joinCgroup() error {
	if !isFIFO(fdCgroup) {
		return fail.E("cgroup_join")
	}
	var b [1]byte
	for {
		n, err := unix.Read(fdCgroup, b[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != 1 || b[0] != 1 {
			return fail.E("cgroup_join")
		}
		break
	}
	if err := unix.Close(fdCgroup); err != nil {
		return fail.E("cgroup_join")
	}
	return nil
}

func isFIFO(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFIFO
}

// cloexecFrom marks every fd from 3 up close-on-exec, except the readiness
// fd when notify is set. The fds stay open until exec, so the Go runtime is
// not disturbed. close_range needs Linux 5.11; older kernels get a loop up
// to RLIMIT_NOFILE.
func cloexecFrom(notify bool) error {
	first := uint(fdReady)
	if notify {
		first = fdExec
	}
	err := unix.CloseRange(first, ^uint(0), unix.CLOSE_RANGE_CLOEXEC)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
		return fail.E("failed")
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return fail.E("failed")
	}
	for fd := uint64(first); fd < lim.Cur; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && !errors.Is(err, unix.EBADF) {
			return fail.E("failed")
		}
	}
	return nil
}

func splitApply(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] != "apply" {
		return nil, false
	}
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			if i+1 >= len(args) {
				return nil, false
			}
			return args[i+1:], true
		}
	}
	return nil, false
}

func writeStatus(token string) int {
	if err := writeErr(token); err != nil {
		return 1
	}
	return 1
}

func writeErr(token string) error {
	line, ok := errLines[token]
	if !ok {
		line = errLines["failed"]
	}
	return writeFD(statusFD, line)
}

// decodeExtra reads the optional pass count, umask (-1 when absent) and
// rlimits.
func decodeExtra(raw []byte) (int, int, map[string]uint64, error) {
	obj, err := jsonobj.Decode(raw, specKeys)
	if err != nil {
		return 0, -1, nil, err
	}
	pass, umask := 0, -1
	var limits map[string]uint64
	if v, ok := obj["pass"]; ok {
		if err := jsonobj.Unmarshal(v, &pass); err != nil || pass < 1 || pass > MaxPass {
			return 0, -1, nil, fail.E("failed")
		}
	}
	if v, ok := obj["umask"]; ok {
		if err := jsonobj.Unmarshal(v, &umask); err != nil || umask < 0 || umask > 0o777 {
			return 0, -1, nil, fail.E("failed")
		}
	}
	if v, ok := obj["rlimits"]; ok {
		if err := jsonobj.Unmarshal(v, &limits); err != nil {
			return 0, -1, nil, fail.E("failed")
		}
		for name := range limits {
			if _, known := rlimitOf[name]; !known {
				return 0, -1, nil, fail.E("failed")
			}
		}
	}
	return pass, umask, limits, nil
}

// placePass moves the exec and status fds out of the way, closes the spec
// pipe, and puts the n passed fds on fds 3 and up, not close-on-exec. The
// copies at fdPass stay close-on-exec (cloexecFrom), so the target holds
// each passed fd once.
func placePass(n int) error {
	ex, err := unix.FcntlInt(uintptr(fdExec), unix.F_DUPFD_CLOEXEC, fdHigh)
	if err != nil {
		return err
	}
	st, err := unix.FcntlInt(uintptr(fdStatus), unix.F_DUPFD_CLOEXEC, fdHigh)
	if err != nil {
		return err
	}
	if err := unix.Close(fdSpec); err != nil {
		return err
	}
	execFD, statusFD = ex, st
	for i := 0; i < n; i++ {
		if err := unix.Dup3(fdPass+i, fdReady+i, 0); err != nil {
			return err
		}
	}
	return nil
}

func writeFD(fd int, buf []byte) error {
	for len(buf) > 0 {
		n, err := unix.Write(fd, buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readSpec() ([]byte, error) {
	buf := make([]byte, maxSpec+1)
	n := 0
	for n < len(buf) {
		r, err := unix.Read(fdSpec, buf[n:])
		n += r
		if r == 0 {
			break
		}
		if err != nil {
			return nil, fail.E("failed")
		}
	}
	if n == 0 || n > maxSpec {
		return nil, fail.E("failed")
	}
	return buf[:n], nil
}

// decodeSpec returns the sandbox (nil when the spec says sandbox false),
// whether the parent passed a readiness pipe, and whether the helper must
// join a cgroup. notify, sandbox and cgroup are required; none is inferred.
func decodeSpec(raw []byte) (*unit.Sandbox, bool, bool, error) {
	obj, err := jsonobj.Decode(raw, specKeys)
	if err != nil {
		return nil, false, false, err
	}
	var notify, sandboxed, join bool
	for key, dest := range map[string]*bool{"notify": &notify, "sandbox": &sandboxed, "cgroup": &join} {
		rawBool, ok := obj[key]
		if !ok {
			return nil, false, false, fail.E("failed")
		}
		if err := jsonobj.Unmarshal(rawBool, dest); err != nil {
			return nil, false, false, err
		}
	}
	if !sandboxed {
		return nil, notify, join, nil
	}
	sb, err := decodeSandbox(obj)
	if err != nil {
		return nil, false, false, err
	}
	return sb, notify, join, nil
}

func decodeSandbox(obj map[string]json.RawMessage) (*unit.Sandbox, error) {
	sb := &unit.Sandbox{}
	present := false
	privs := true
	if raw, ok := obj["no_new_privs"]; ok {
		present = true
		if err := jsonobj.Unmarshal(raw, &privs); err != nil {
			return nil, err
		}
	}
	if raw, ok := obj["read_only_paths"]; ok {
		if err := jsonobj.Unmarshal(raw, &sb.ReadOnly); err != nil {
			return nil, err
		}
	}
	if raw, ok := obj["read_write_paths"]; ok {
		if err := jsonobj.Unmarshal(raw, &sb.ReadWrite); err != nil {
			return nil, err
		}
	}
	if raw, ok := obj["caps"]; ok {
		if err := jsonobj.Unmarshal(raw, &sb.Caps); err != nil {
			return nil, err
		}
	}
	for key, dest := range map[string]*[]uint32{"setuid_to": &sb.SetuidTo, "setgid_to": &sb.SetgidTo} {
		if raw, ok := obj[key]; ok {
			if err := jsonobj.Unmarshal(raw, dest); err != nil {
				return nil, err
			}
			if *dest == nil {
				*dest = []uint32{}
			}
		}
	}
	if err := unit.FinishSandbox(sb, present, privs); err != nil {
		return nil, err
	}
	return sb, nil
}

// execTarget runs the fd on fdExec. The status pipe is close-on-exec, so it
// stays open until exec succeeds; on failure the caller sends an error.
func execTarget(argv, env []string, closeSpec bool) error {
	if closeSpec {
		if err := unix.Close(fdSpec); err != nil {
			return errExec
		}
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return errExec
	}
	envp, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return errExec
	}
	// With a close-on-exec fd the kernel runs a binary but refuses a script
	// with ENOENT before the point of no return, since the interpreter could
	// not open /dev/fd/4. Only then is the fd kept for the interpreter.
	if execveat(execFD, argvp, envp) != unix.ENOENT {
		return errExec
	}
	if _, err := unix.FcntlInt(uintptr(execFD), unix.F_SETFD, 0); err != nil {
		return errExec
	}
	execveat(execFD, argvp, envp)
	return errExec
}

// directTarget places the exec fd for a direct launch. A script's fd goes
// to fd 4 and stays open, since the interpreter opens /proc/self/fd/4. A
// binary is run through a close-on-exec copy at fd 10 or above: the forked
// child still holds it when it calls execve on /proc/self/fd/N, and the
// kernel closes it at exec, so the binary keeps no fd. The copy is returned
// for the caller to close after the start.
func directTarget(target string, execF *os.File, script bool, notifyW *os.File) (string, []*os.File, *os.File, error) {
	if execF == nil {
		return "", nil, nil, fail.E("failed")
	}
	if script {
		// A nil entry closes fd 3 in the child when notify is off.
		return execPathFD, []*os.File{notifyW, execF}, nil, nil
	}
	fd, err := unix.FcntlInt(execF.Fd(), unix.F_DUPFD_CLOEXEC, execFDMin)
	if err != nil {
		return "", nil, nil, fail.E("failed")
	}
	held := os.NewFile(uintptr(fd), execF.Name())
	var extra []*os.File
	if notifyW != nil {
		extra = []*os.File{notifyW}
	}
	return "/proc/self/fd/" + strconv.Itoa(fd), extra, held, nil
}

// readHead reads the start of the open target. An O_PATH fd cannot be read
// and has no head. Without an fd (an interpreter) the path is opened.
func readHead(f *os.File, p string) ([]byte, error) {
	if f == nil {
		var err error
		if f, err = os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0); err != nil {
			if errors.Is(err, os.ErrPermission) {
				return nil, nil
			}
			return nil, fail.E("exec_not_file")
		}
		defer f.Close()
	}
	buf := make([]byte, headLen)
	n, err := unix.Pread(int(f.Fd()), buf, 0)
	if errors.Is(err, unix.EBADF) {
		return nil, nil
	}
	if err != nil || n < 0 {
		return nil, fail.E("exec_not_file")
	}
	return buf[:n], nil
}

func execveat(fd int, argv, env []*byte) syscall.Errno {
	empty := [1]byte{}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
		uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])), unix.AT_EMPTY_PATH, 0)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(env)
	return errno
}

// openExec opens the checked target without following a link, then checks
// the open file again, so the file checked is the file run. It is opened for
// reading, so its #! line can be read from the same file; a file the
// supervisor may not read is opened O_PATH, and could not be a runnable
// script anyway.
func openExec(p string) (*os.File, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EACCES) {
		fd, err = unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fail.E("exec_not_file")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o111 == 0 {
		unix.Close(fd)
		return nil, fail.E("exec_not_file")
	}
	if (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0o022 != 0 {
		unix.Close(fd)
		return nil, fail.E("exec_perm")
	}
	return os.NewFile(uintptr(fd), p), nil
}

// landlockABI asks the kernel for its Landlock ABI version.
func landlockABI() int {
	r1, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(r1)
}

// landlockAccess returns the file rights to handle at a kernel ABI, and the
// ABI applied (the kernel's, capped at MaxLandlockABI). Only rights the ABI
// knows are requested, as the Landlock documentation recommends. Each want
// is a set of rights a grant needs; a want the ABI cannot express is
// landlock_abi. No ABI at all is landlock_unavailable.
func landlockAccess(abi int, wants ...uint64) (uint64, int, error) {
	if abi < 1 {
		return 0, 0, fail.E("landlock_unavailable")
	}
	if abi > MaxLandlockABI {
		abi = MaxLandlockABI
	}
	known := uint64(accessV1)
	if abi >= 2 {
		known |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		known |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		known |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	for _, want := range wants {
		if want&^known != 0 {
			return 0, 0, fail.E("landlock_abi")
		}
	}
	return accessHandled & known, abi, nil
}

// restrict opens paths, drops privileges, and landlocks the calling thread.
// no_new_privs is set before landlock_restrict_self. Fds are left open for
// the caller to close before any success status is written. It returns the
// Landlock ABI applied.
//
// Threats: on an older kernel the rights it does not know stay unrestricted
// (for TRUNCATE before ABI 3, truncate(2) anywhere the uid may write); every
// right a grant needs is still enforced or the launch is refused.
func restrict(sb *unit.Sandbox) (*held, int, error) {
	if sb == nil || !sb.NoNewPrivs {
		return nil, 0, fail.E("sandbox_privs")
	}
	h := &held{ruleset: -1}
	for _, p := range sb.ReadOnly {
		fd, err := openNoSym(p)
		if err != nil {
			return h, 0, err
		}
		h.paths = append(h.paths, pathFD{fd: fd, rw: false})
	}
	for _, p := range sb.ReadWrite {
		fd, err := openNoSym(p)
		if err != nil {
			return h, 0, err
		}
		h.paths = append(h.paths, pathFD{fd: fd, rw: true})
		if needsIDFilter(sb) {
			if err := notProc(fd); err != nil {
				return h, 0, err
			}
		}
	}
	if needsIDFilter(sb) {
		if err := noProcInMounts(sb.ReadWrite); err != nil {
			return h, 0, err
		}
	}
	wants := []uint64{accessRead}
	if len(sb.ReadWrite) > 0 {
		wants = append(wants, accessWrite&^accessOptional)
	}
	handled, abi, err := landlockAccess(landlockABI(), wants...)
	if err != nil {
		return h, 0, err
	}
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	r1, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	runtime.KeepAlive(&attr)
	if errno != 0 {
		return h, 0, fail.E("landlock_unavailable")
	}
	h.ruleset = int(r1)
	for _, p := range h.paths {
		access := uint64(accessRead)
		if p.rw {
			access = uint64(accessWrite)
		}
		access &= handled
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(p.fd)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(h.ruleset), uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		runtime.KeepAlive(&rule)
		if errno != 0 {
			return h, 0, fail.E("landlock_unavailable")
		}
	}
	if err := dropCaps(sb.Caps); err != nil {
		return h, 0, err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return h, 0, fail.E("failed")
	}
	// A unit with caps keeps them ambient, or its exec would lose them
	// (capabilities(7)); enterCaps already made the ambient set exactly
	// the granted set.
	if len(sb.Caps) == 0 {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, uintptr(unix.PR_CAP_AMBIENT_CLEAR_ALL), 0, 0, 0); err != nil {
			return h, 0, fail.E("failed")
		}
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(h.ruleset), 0, 0)
	if errno != 0 {
		return h, 0, fail.E("landlock_unavailable")
	}
	if len(sb.Caps) == 0 {
		return h, abi, nil
	}
	if needsIDFilter(sb) {
		if err := installIDFilter(sb); err != nil {
			return h, 0, err
		}
	}
	// The last check before exec: exactly the granted set in all five sets,
	// and no_new_privs on.
	want, err := capMask(sb.Caps)
	if err != nil {
		return h, 0, err
	}
	if err := checkCaps(want); err != nil {
		return h, 0, err
	}
	if nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil || nnp != 1 {
		return h, 0, fail.E("failed")
	}
	return h, abi, nil
}

func openNoSym(p string) (int, error) {
	how := unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, p, &how)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return -1, fail.E("openat2_unavailable")
		}
		return -1, fail.E("sandbox_path")
	}
	return fd, nil
}

func dropCaps(names []string) error {
	var data [2]unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	for _, name := range names {
		bit, ok := unit.LookupCap(name)
		if !ok || bit > 63 {
			return fail.E("sandbox_cap")
		}
		idx := bit >> 5
		data[idx].Effective |= 1 << (bit & 31)
		data[idx].Permitted |= 1 << (bit & 31)
		data[idx].Inheritable |= 1 << (bit & 31)
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fail.E("sandbox_cap")
	}
	return nil
}

func closeHeld(h *held) error {
	if h == nil {
		return nil
	}
	var first error
	if h.ruleset >= 0 {
		if err := unix.Close(h.ruleset); err != nil && first == nil {
			first = err
		}
		h.ruleset = -1
	}
	for i := range h.paths {
		fd := h.paths[i].fd
		if fd < 0 {
			continue
		}
		h.paths[i].fd = -1
		if err := unix.Close(fd); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return fail.E("failed")
	}
	return nil
}

// marshalSpec writes the helper's spec. A nil sb is a helper that only
// joins the cgroup (join must then be set).
func marshalSpec(sb *unit.Sandbox, notify, join bool) ([]byte, error) {
	return marshalSpecPass(sb, notify, join, 0, nil, nil, Options{})
}

// marshalSpecPass is marshalSpec with a count of passed fds, a umask and
// rlimits.
func marshalSpecPass(sb *unit.Sandbox, notify, join bool, pass int, umask *int, limits map[string]uint64, streams Options) ([]byte, error) {
	if sb == nil && !join {
		return nil, fail.E("failed")
	}
	none := sb == nil
	if none {
		sb = &unit.Sandbox{NoNewPrivs: true}
	}
	body := struct {
		NoNewPrivs bool              `json:"no_new_privs"`
		ReadOnly   []string          `json:"read_only_paths"`
		ReadWrite  []string          `json:"read_write_paths"`
		Caps       []string          `json:"caps"`
		SetuidTo   []uint32          `json:"setuid_to,omitempty"`
		SetgidTo   []uint32          `json:"setgid_to,omitempty"`
		Notify     bool              `json:"notify"`
		Sandbox    bool              `json:"sandbox"`
		Cgroup     bool              `json:"cgroup"`
		Pass       int               `json:"pass,omitempty"`
		Umask      *int              `json:"umask,omitempty"`
		Rlimits    map[string]uint64 `json:"rlimits,omitempty"`
		StdoutFile *StreamFile       `json:"stdout_file,omitempty"`
		StderrFile *StreamFile       `json:"stderr_file,omitempty"`
		StderrOut  bool              `json:"stderr_stdout,omitempty"`
	}{
		StdoutFile: streams.StdoutFile,
		StderrFile: streams.StderrFile,
		StderrOut:  streams.StderrToStdout,
		Rlimits:    limits,
		Pass:       pass,
		Umask:      umask,
		Notify:     notify,
		Sandbox:    !none,
		Cgroup:     join,
		NoNewPrivs: sb.NoNewPrivs,
		ReadOnly:   emptyStr(sb.ReadOnly),
		ReadWrite:  emptyStr(sb.ReadWrite),
		Caps:       emptyStr(sb.Caps),
		SetuidTo:   sb.SetuidTo,
		SetgidTo:   sb.SetgidTo,
	}
	buf, err := json.Marshal(body)
	if err != nil || len(buf) == 0 || len(buf) > maxSpec {
		return nil, fail.E("failed")
	}
	return buf, nil
}

func emptyStr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// launchHelper starts the target through a re-exec of self. sb nil means no
// sandbox: the helper then only joins opts.Cgroup (join must be set). With
// join the parent writes the helper's pid to the cgroup's cgroup.procs as
// soon as it starts, then releases it through a sync pipe (fd 7); otherwise
// opts.Cgroup, if set, is joined through clone3.
func launchHelper(ctx context.Context, self string, argv []string, execF *os.File, sb *unit.Sandbox, notify bool, timeout time.Duration, opts Options, join bool) (*exec.Cmd, string, *os.File, error) {
	self, err := unit.ResolveExec(self)
	if err != nil {
		return nil, "", nil, err
	}
	if execF == nil {
		return nil, "", nil, fail.E("failed")
	}
	if join && (opts.Cgroup == nil || opts.Cgroup.Procs == nil) {
		return nil, "", nil, fail.E("failed")
	}
	if len(opts.Pass) > 0 && (sb == nil || notify || len(opts.Pass) > MaxPass) {
		return nil, "", nil, fail.E("failed")
	}
	spec, err := marshalSpecPass(sb, notify, join, len(opts.Pass), opts.Umask, opts.Rlimits, opts)
	if err != nil {
		return nil, "", nil, err
	}
	// The helper starts as the unit's uid holding the granted caps and
	// CAP_SETPCAP in every set but the bounding set (caps_linux.go).
	var ambient []uintptr
	if sb != nil && len(sb.Caps) > 0 {
		if opts.Execution.UID == nil {
			return nil, "", nil, fail.E("sandbox_cap")
		}
		if ambient, err = ambientCaps(sb.Caps); err != nil {
			return nil, "", nil, err
		}
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, "", nil, fail.E("failed")
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		closePair(specR, specW)
		return nil, "", nil, fail.E("failed")
	}
	var notifyR, notifyW *os.File
	if notify {
		notifyR, notifyW, err = os.Pipe()
		if err != nil {
			closePair(specR, specW)
			closePair(statusR, statusW)
			return nil, "", nil, fail.E("failed")
		}
	}
	var syncR, syncW *os.File
	if join {
		syncR, syncW, err = os.Pipe()
		if err != nil {
			closePair(specR, specW)
			closePair(statusR, statusW)
			closePair(notifyR, notifyW)
			return nil, "", nil, fail.E("failed")
		}
	}
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		closePair(specR, specW)
		closePair(statusR, statusW)
		closePair(notifyR, notifyW)
		closePair(syncR, syncW)
		return nil, "", nil, fail.E("failed")
	}
	// fdReady, fdExec, fdSpec, fdStatus, fdCgroup. A nil entry is closed in
	// the child.
	extra := []*os.File{notifyW, execF, specR, statusW}
	if len(opts.Pass) > 0 {
		extra[0] = null
	}
	clone := opts.Cgroup
	if join {
		extra = append(extra, syncR)
		clone = nil
	}
	if len(opts.Pass) > 0 {
		if !join {
			extra = append(extra, null)
		}
		extra = append(extra, opts.Pass...)
	}
	cmd := &exec.Cmd{
		Path:        self,
		Args:        append([]string{self, "apply", "--"}, argv...),
		Dir:         "/",
		Env:         opts.Execution.Env(),
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		ExtraFiles:  extra,
		SysProcAttr: procAttr(clone),
	}
	opts.configure(cmd)
	cmd.SysProcAttr.AmbientCaps = ambient
	if err := cmd.Start(); err != nil {
		null.Close()
		closePair(specR, specW)
		closePair(statusR, statusW)
		closePair(notifyR, notifyW)
		closePair(syncR, syncW)
		return nil, "", nil, startErr(err, self, clone)
	}
	if err := closeChildEnds(null, specR, statusW, notifyW, syncR); err != nil {
		closePair(specW, statusR)
		closePair(notifyR, syncW)
		reap(cmd)
		return nil, "", nil, fail.E("failed")
	}
	if join {
		// The helper waits on the sync pipe, before anything else, until it
		// is in the cgroup; on failure it reads end of file.
		_, werr := opts.Cgroup.Procs.Write([]byte(strconv.Itoa(cmd.Process.Pid)))
		if werr == nil {
			_, werr = syncW.Write([]byte{1})
		}
		if cerr := syncW.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			closePair(specW, statusR)
			closePair(notifyR, nil)
			reap(cmd)
			return nil, "", nil, fail.E("cgroup_join")
		}
	}
	if err := writeFull(specW, spec); err != nil {
		specW.Close()
		closePair(statusR, notifyR)
		reap(cmd)
		return nil, "", nil, fail.E("failed")
	}
	if err := specW.Close(); err != nil {
		closePair(statusR, notifyR)
		reap(cmd)
		return nil, "", nil, fail.E("failed")
	}
	claim, err := readChildStatus(ctx, statusR, timeout, sb != nil)
	if cerr := statusR.Close(); cerr != nil && err == nil {
		err = fail.E("failed")
	}
	if err == nil && sb != nil {
		err = checkClaim(claim, sb)
	}
	if err != nil {
		if notifyR != nil {
			notifyR.Close()
		}
		reap(cmd)
		return nil, "", nil, err
	}
	return cmd, claim, notifyR, nil
}

// checkClaim requires the id filter to be claimed exactly when the unit
// holds setuid or setgid.
func checkClaim(claim string, sb *unit.Sandbox) error {
	if strings.HasSuffix(claim, idFilterClaim) != needsIDFilter(sb) {
		return fail.E("sandbox_cap")
	}
	return nil
}

func closeChildEnds(files ...*os.File) error {
	var first error
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return first
	}
	return nil
}

func writeFull(f *os.File, buf []byte) error {
	for len(buf) > 0 {
		n, err := f.Write(buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readChildStatus(ctx context.Context, f *os.File, timeout time.Duration, sandboxed bool) (string, error) {
	if timeout <= 0 {
		timeout = unit.DefaultTimeout
	}
	if err := f.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", fail.E("failed")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			err := f.SetReadDeadline(time.Now())
			if err != nil {
				return
			}
		case <-done:
		}
	}()
	buf := make([]byte, 0, 128)
	tmp := make([]byte, 128)
	for {
		if ctx.Err() != nil {
			return "", fail.E("failed")
		}
		n, err := f.Read(tmp)
		if n > 0 {
			if len(buf)+n > maxLine {
				return "", fail.E("failed")
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				return parseStatus(buf, sandboxed)
			}
			if ctx.Err() != nil {
				return "", fail.E("failed")
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return "", fail.E("sandbox_timeout")
			}
			return "", fail.E("failed")
		}
	}
}

// parseStatus accepts a sandbox claim from a sandboxing helper and only
// "none" from a helper that applied no sandbox.
func parseStatus(line []byte, sandboxed bool) (string, error) {
	if !bytes.Contains(line, []byte{'\n'}) {
		return "", fail.E("failed")
	}
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimRight(line, "\n")))
	dec.DisallowUnknownFields()
	var st struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Claim string `json:"claim"`
	}
	if err := dec.Decode(&st); err != nil {
		return "", fail.E("failed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fail.E("failed")
	}
	if st.OK {
		if st.Error == "" && sandboxed && IsSandboxClaim(st.Claim) {
			return st.Claim, nil
		}
		if st.Error == "" && !sandboxed && st.Claim == claimNone {
			return st.Claim, nil
		}
		return "", fail.E("failed")
	}
	if st.Claim != "" {
		return "", fail.E("failed")
	}
	if _, ok := childTokens[st.Error]; ok {
		return "", fail.E(st.Error)
	}
	return "", fail.E("failed")
}

var rlimitOf = map[string]int{
	"nofile": unix.RLIMIT_NOFILE, "nproc": unix.RLIMIT_NPROC, "core": unix.RLIMIT_CORE, "memlock": unix.RLIMIT_MEMLOCK,
	"stack": unix.RLIMIT_STACK, "as": unix.RLIMIT_AS, "cpu": unix.RLIMIT_CPU, "fsize": unix.RLIMIT_FSIZE,
}

// setRlimits sets each limit, soft and hard, in the helper before it execs
// the target. It runs as the target's uid, so a limit can only be lowered.
func setRlimits(limits map[string]uint64) error {
	for name, v := range limits {
		res, ok := rlimitOf[name]
		if !ok {
			return fail.E("failed")
		}
		lim := unix.Rlimit{Cur: v, Max: v}
		if err := unix.Setrlimit(res, &lim); err != nil {
			return fail.E("failed")
		}
	}
	return nil
}

// OpenBeneath opens p beneath root with no symlink at any component, the
// last included: root itself is resolved with RESOLVE_NO_SYMLINKS, and p
// relative to it with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS and O_NOFOLLOW.
func OpenBeneath(root, p string, flags int, mode uint32) (int, error) {
	how := unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS}
	rfd, err := unix.Openat2(unix.AT_FDCWD, root, &how)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rfd)
	rel := strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
	if rel == "" {
		rel = "."
	}
	// O_NOFOLLOW with O_PATH would hand back the symlink itself; without
	// it RESOLVE_NO_SYMLINKS refuses a trailing link with ELOOP.
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NOFOLLOW
	}
	how = unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS}
	return unix.Openat2(rfd, rel, &how)
}

// openStreams opens the spec's stream files as the helper's own uid (the
// target's), beneath their roots, and puts them on fds 1 and 2. A file
// that is not a regular file with one link, or that the target's uid may
// not open, is stream_denied.
//
// Threats: sahinit runs as root; a stream it opened itself would let a
// service append to a root-only file under its file_write root. Opened
// here, before Landlock, with the target's credentials, it reaches only
// what the service's own uid may write.
func openStreams(raw []byte) error {
	obj, err := jsonobj.Decode(raw, specKeys)
	if err != nil {
		return fail.E("failed")
	}
	open := func(key string, target int) error {
		v, ok := obj[key]
		if !ok {
			return nil
		}
		var f StreamFile
		if err := jsonobj.Unmarshal(v, &f); err != nil || f.Root == "" || !strings.HasPrefix(f.Path, f.Root+"/") {
			return fail.E("stream_denied")
		}
		fd, err := OpenBeneath(f.Root, f.Path, unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_NONBLOCK, 0o640)
		if err != nil {
			return fail.E("stream_denied")
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			return fail.E("stream_denied")
		}
		if err := unix.Dup3(fd, target, 0); err != nil {
			return fail.E("failed")
		}
		return nil
	}
	if err := open("stdout_file", 1); err != nil {
		return err
	}
	if err := open("stderr_file", 2); err != nil {
		return err
	}
	if v, ok := obj["stderr_stdout"]; ok {
		var on bool
		if err := jsonobj.Unmarshal(v, &on); err != nil {
			return fail.E("failed")
		}
		if on {
			if err := unix.Dup3(1, 2, 0); err != nil {
				return fail.E("failed")
			}
		}
	}
	return nil
}
