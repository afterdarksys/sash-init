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
	maxSpec  = 64 * 1024
	maxLine  = 1024

	// execPathFD runs the exec fd of a direct launch.
	execPathFD = "/proc/self/fd/4"

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

var specKeys = map[string]struct{}{
	"no_new_privs": {}, "read_only_paths": {}, "read_write_paths": {}, "caps": {},
	"notify": {},
}

var childTokens = map[string]struct{}{
	"sandbox_cap": {}, "sandbox_path": {}, "sandbox_privs": {}, "sandbox_overlap": {},
	"openat2_unavailable": {}, "landlock_unavailable": {}, "landlock_abi": {},
	"exec_relative": {}, "exec_not_file": {}, "failed": {}, "sandbox_root": {},
}

func okLine(abi int) []byte {
	return []byte("{\"ok\":true,\"claim\":\"" + SandboxClaim(abi) + "\"}\n")
}

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
// setup status on fd 6, then execs the checked target held on fd 4.
// Successful exec closes fd 6; a failed exec appends an error status before
// exiting. A missing handshake fd exits 2 and writes nothing.
//
// Threats: readiness is used only when the spec says notify, and fd 3 must
// then be a pipe. Every other fd from 3 up is marked close-on-exec before
// exec, so nothing the helper or the Go runtime opened reaches the target.
// argv[0] is never looked up; the target is the fd the parent checked.
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
	sb, notify, err := decodeSpec(raw)
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	if notify && !isFIFO(fdReady) {
		return writeStatus("failed")
	}
	if unix.Geteuid() == 0 || unix.Getuid() == 0 {
		return writeStatus("sandbox_root")
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
	h, abi, err := restrict(sb)
	cerr := closeHeld(h)
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	if cerr != nil {
		return writeStatus("failed")
	}
	if err := writeFD(fdStatus, okLine(abi)); err != nil {
		return 1
	}
	if err := execTarget(argv, env); err == errExec {
		return writeStatus("failed")
	}
	return 1
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
	return writeFD(fdStatus, line)
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

// decodeSpec returns the sandbox and whether the parent passed a readiness
// pipe. notify is required; it is never inferred.
func decodeSpec(raw []byte) (*unit.Sandbox, bool, error) {
	obj, err := jsonobj.Decode(raw, specKeys)
	if err != nil {
		return nil, false, err
	}
	rawNotify, ok := obj["notify"]
	if !ok {
		return nil, false, fail.E("failed")
	}
	var notify bool
	if err := jsonobj.Unmarshal(rawNotify, &notify); err != nil {
		return nil, false, err
	}
	sb, err := decodeSandbox(obj)
	if err != nil {
		return nil, false, err
	}
	return sb, notify, nil
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
	if err := unit.FinishSandbox(sb, present, privs); err != nil {
		return nil, err
	}
	return sb, nil
}

// execTarget runs the fd on fdExec. The status pipe is close-on-exec, so it
// stays open until exec succeeds; on failure the caller sends an error.
func execTarget(argv, env []string) error {
	if err := unix.Close(fdSpec); err != nil {
		return errExec
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
	if execveat(fdExec, argvp, envp) != unix.ENOENT {
		return errExec
	}
	if _, err := unix.FcntlInt(fdExec, unix.F_SETFD, 0); err != nil {
		return errExec
	}
	execveat(fdExec, argvp, envp)
	return errExec
}

func execveat(fd int, argv, env []*byte) syscall.Errno {
	empty := [1]byte{}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
		uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])), unix.AT_EMPTY_PATH, 0)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(env)
	return errno
}

// openExec opens the checked target O_PATH without following a link, then
// checks the open file again, so the file checked is the file run.
func openExec(p string) (*os.File, error) {
	fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, uintptr(unix.PR_CAP_AMBIENT_CLEAR_ALL), 0, 0, 0); err != nil {
		return h, 0, fail.E("failed")
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(h.ruleset), 0, 0)
	if errno != 0 {
		return h, 0, fail.E("landlock_unavailable")
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

func marshalSpec(sb *unit.Sandbox, notify bool) ([]byte, error) {
	body := struct {
		NoNewPrivs bool     `json:"no_new_privs"`
		ReadOnly   []string `json:"read_only_paths"`
		ReadWrite  []string `json:"read_write_paths"`
		Caps       []string `json:"caps"`
		Notify     bool     `json:"notify"`
	}{
		Notify:     notify,
		NoNewPrivs: sb.NoNewPrivs,
		ReadOnly:   emptyStr(sb.ReadOnly),
		ReadWrite:  emptyStr(sb.ReadWrite),
		Caps:       emptyStr(sb.Caps),
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

func launchSandboxed(ctx context.Context, self string, argv []string, execF *os.File, sb *unit.Sandbox, notify bool, timeout time.Duration, opts Options) (*exec.Cmd, string, *os.File, error) {
	self, err := unit.ResolveExec(self)
	if err != nil {
		return nil, "", nil, err
	}
	if execF == nil {
		return nil, "", nil, fail.E("failed")
	}
	spec, err := marshalSpec(sb, notify)
	if err != nil {
		return nil, "", nil, err
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
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		closePair(specR, specW)
		closePair(statusR, statusW)
		closePair(notifyR, notifyW)
		return nil, "", nil, fail.E("failed")
	}
	// fdReady, fdExec, fdSpec, fdStatus. A nil entry is closed in the child.
	extra := []*os.File{notifyW, execF, specR, statusW}
	cmd := &exec.Cmd{
		Path:        self,
		Args:        append([]string{self, "apply", "--"}, argv...),
		Dir:         "/",
		Env:         opts.Execution.Env(),
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		ExtraFiles:  extra,
		SysProcAttr: procAttr(),
	}
	opts.configure(cmd)
	if err := cmd.Start(); err != nil {
		null.Close()
		closePair(specR, specW)
		closePair(statusR, statusW)
		closePair(notifyR, notifyW)
		return nil, "", nil, fail.E("failed")
	}
	if err := closeChildEnds(null, specR, statusW, notifyW); err != nil {
		closePair(specW, statusR)
		closePair(notifyR, nil)
		reap(cmd)
		return nil, "", nil, fail.E("failed")
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
	claim, err := readChildStatus(ctx, statusR, timeout)
	if cerr := statusR.Close(); cerr != nil && err == nil {
		err = fail.E("failed")
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

func readChildStatus(ctx context.Context, f *os.File, timeout time.Duration) (string, error) {
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
				return parseStatus(buf)
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

func parseStatus(line []byte) (string, error) {
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
		if st.Error == "" && IsSandboxClaim(st.Claim) {
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
