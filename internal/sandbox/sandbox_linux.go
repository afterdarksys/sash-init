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

const (
	fdSpec   = 3
	fdStatus = 4
	fdNotify = 5
	maxSpec  = 64 * 1024
	maxLine  = 1024

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

var (
	okLine   []byte
	errLines map[string][]byte
)

var specKeys = map[string]struct{}{
	"no_new_privs": {}, "read_only_paths": {}, "read_write_paths": {}, "caps": {},
}

var childTokens = map[string]struct{}{
	"sandbox_cap": {}, "sandbox_path": {}, "sandbox_privs": {}, "sandbox_overlap": {},
	"openat2_unavailable": {}, "landlock_unavailable": {},
	"exec_relative": {}, "exec_not_file": {}, "failed": {},
}

func init() {
	okLine = []byte("{\"ok\":true,\"claim\":\"" + claimFull + "\"}\n")
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

// ApplyCLI is the re-exec entry. It reads the spec on fd 3, writes one
// status line on fd 4, then execs the target. A missing handshake fd exits 2
// and writes nothing.
func ApplyCLI(args []string) int {
	runtime.LockOSThread()
	argv, ok := splitApply(args)
	if !ok {
		return 2
	}
	var st unix.Stat_t
	if err := unix.Fstat(fdSpec, &st); err != nil {
		return 2
	}
	if err := unix.Fstat(fdStatus, &st); err != nil {
		return 2
	}
	if err := checkArgv(argv); err != nil {
		return writeStatus(fail.Token(err))
	}
	if err := unit.ExecFile(argv[0]); err != nil {
		return writeStatus(fail.Token(err))
	}
	raw, err := readSpec()
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	sb, err := decodeSpec(raw)
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	notify := unix.Fstat(fdNotify, &st) == nil
	env := []string{cleanPATH}
	if notify {
		env = append(env, "SAHINIT_READY_FD=3")
	}
	argv = append([]string{}, argv...)
	h, err := restrict(sb)
	cerr := closeHeld(h)
	if err != nil {
		return writeStatus(fail.Token(err))
	}
	if cerr != nil {
		return writeStatus("failed")
	}
	if err := writeFD(fdStatus, okLine); err != nil {
		return 1
	}
	if err := execTarget(argv, env, notify); err == errExec {
		return 1
	}
	return 1
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

func decodeSpec(raw []byte) (*unit.Sandbox, error) {
	obj, err := jsonobj.Decode(raw, specKeys)
	if err != nil {
		return nil, err
	}
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

func execTarget(argv, env []string, notify bool) error {
	if err := unix.Close(fdStatus); err != nil {
		return errExec
	}
	if err := unix.Close(fdSpec); err != nil {
		return errExec
	}
	if notify {
		if err := unix.Dup2(fdNotify, fdSpec); err != nil {
			return errExec
		}
		if err := unix.Close(fdNotify); err != nil {
			return errExec
		}
	}
	if err := syscall.Exec(argv[0], argv, env); err != nil {
		return errExec
	}
	return errExec
}

// restrict opens paths, drops privileges, and landlocks the calling thread.
// no_new_privs is set before landlock_restrict_self. Fds are left open for
// the caller to close before any success status is written.
func restrict(sb *unit.Sandbox) (*held, error) {
	if sb == nil || !sb.NoNewPrivs {
		return nil, fail.E("sandbox_privs")
	}
	h := &held{ruleset: -1}
	for _, p := range sb.ReadOnly {
		fd, err := openNoSym(p)
		if err != nil {
			return h, err
		}
		h.paths = append(h.paths, pathFD{fd: fd, rw: false})
	}
	for _, p := range sb.ReadWrite {
		fd, err := openNoSym(p)
		if err != nil {
			return h, err
		}
		h.paths = append(h.paths, pathFD{fd: fd, rw: true})
	}
	attr := unix.LandlockRulesetAttr{Access_fs: accessHandled}
	r1, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	runtime.KeepAlive(&attr)
	if errno != 0 {
		return h, fail.E("landlock_unavailable")
	}
	h.ruleset = int(r1)
	for _, p := range h.paths {
		access := uint64(accessRead)
		if p.rw {
			access = uint64(accessWrite)
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(p.fd)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(h.ruleset), uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		runtime.KeepAlive(&rule)
		if errno != 0 {
			return h, fail.E("landlock_unavailable")
		}
	}
	if err := dropCaps(sb.Caps); err != nil {
		return h, err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return h, fail.E("failed")
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, uintptr(unix.PR_CAP_AMBIENT_CLEAR_ALL), 0, 0, 0); err != nil {
		return h, fail.E("failed")
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(h.ruleset), 0, 0)
	if errno != 0 {
		return h, fail.E("landlock_unavailable")
	}
	return h, nil
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

func marshalSpec(sb *unit.Sandbox) ([]byte, error) {
	body := struct {
		NoNewPrivs bool     `json:"no_new_privs"`
		ReadOnly   []string `json:"read_only_paths"`
		ReadWrite  []string `json:"read_write_paths"`
		Caps       []string `json:"caps"`
	}{
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

func launchSandboxed(ctx context.Context, self string, argv []string, sb *unit.Sandbox, notify bool, timeout time.Duration) (*exec.Cmd, string, *os.File, error) {
	if err := unit.ExecFile(self); err != nil {
		return nil, "", nil, err
	}
	spec, err := marshalSpec(sb)
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
	extra := []*os.File{specR, statusW}
	if notifyW != nil {
		extra = append(extra, notifyW)
	}
	cmd := &exec.Cmd{
		Path:        self,
		Args:        append([]string{self, "apply", "--"}, argv...),
		Dir:         "/",
		Env:         []string{cleanPATH},
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		ExtraFiles:  extra,
		SysProcAttr: procAttr(),
	}
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
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				return parseStatus(buf[:i+1])
			}
		}
		if err != nil {
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
		if st.Error == "" && st.Claim == claimFull {
			return claimFull, nil
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
