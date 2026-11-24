// SPDX-License-Identifier: GPL-3.0-or-later

// Package sandbox starts a service process.
//
// Threats: sandbox setup runs in a fresh process so a multithreaded parent
// is not restricted. openat2 failure, landlock rejection, and capset failure
// skip exec. The status claim lists only mechanisms that returned success,
// with the Landlock ABI that was applied.
// No path is granted MAKE_SYM. The spec cannot name the executable.
// Network is not confined in v1.
package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

const (
	claimNone = "none"
	maxArgv   = 32
	maxArg    = 256

	// MaxLandlockABI is the newest Landlock ABI whose access rights this
	// package knows. A newer kernel is used at this ABI.
	MaxLandlockABI = 5
)

// SandboxClaim is the status claim for a sandbox applied at a Landlock ABI.
func SandboxClaim(abi int) string {
	return "no_new_privs,landlock_v" + strconv.Itoa(abi) + ",caps"
}

// IsSandboxClaim reports whether claim is a sandbox claim for a known ABI.
func IsSandboxClaim(claim string) bool {
	for abi := 1; abi <= MaxLandlockABI; abi++ {
		if claim == SandboxClaim(abi) {
			return true
		}
	}
	return false
}

// Launch starts argv[0]. A nil sandbox is a direct exec and claims "none".
// A sandbox is applied in a re-exec of self (the helper), which also joins
// opts.Cgroup when clone3 cannot place the child there. claim is empty when err != nil.
// notify places the ready write end on fd 3 and sets SAHINIT_READY_FD.
// argv[0] is passed to the target as written; the file run is argv[0]
// resolved once (or opts.Path) and checked by unit.CheckExec.
func Launch(ctx context.Context, self string, argv []string, sb *unit.Sandbox, notify bool, timeout time.Duration, options ...Options) (*exec.Cmd, string, *os.File, error) {
	var opts Options
	if len(options) > 1 {
		return nil, "", nil, fail.E("failed")
	}
	if len(options) == 1 {
		opts = options[0]
	}
	if err := opts.Execution.Validate(); err != nil {
		return nil, "", nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, "", nil, fail.E("failed")
	}
	if sb != nil && runsAsRoot(opts.Execution) {
		return nil, "", nil, fail.E("sandbox_root")
	}
	if err := checkArgv(argv); err != nil {
		return nil, "", nil, err
	}
	target := opts.Path
	var err error
	if target == "" {
		target, err = unit.ResolveExec(argv[0])
	} else {
		err = unit.CheckExec(target)
	}
	if err != nil {
		return nil, "", nil, err
	}
	execF, err := openExec(target)
	if err != nil {
		return nil, "", nil, err
	}
	if execF != nil {
		defer execF.Close()
	}
	if opts.SHA256 != "" {
		// Signed execution requires a pinned readable file (Linux). Hash the
		// same inode that execveat/directTarget will execute, on every start.
		if execF == nil {
			return nil, "", nil, fail.E("verified_exec_unavailable")
		}
		h := sha256.New()
		n, err := io.Copy(h, io.NewSectionReader(execF, 0, (64<<20)+1))
		if err != nil || n > 64<<20 || hex.EncodeToString(h.Sum(nil)) != opts.SHA256 {
			return nil, "", nil, fail.E("artifact_digest")
		}
	}
	head, err := readHead(execF, target)
	if err != nil {
		return nil, "", nil, err
	}
	script, err := checkInterp(head)
	if err != nil {
		return nil, "", nil, err
	}
	if opts.Cgroup != nil && !cgroup.Supported() {
		return nil, "", nil, fail.E("cgroup_unavailable")
	}
	join := opts.Cgroup != nil && noClone.Load()
	if (len(opts.Pass) > 0 || opts.Umask != nil || len(opts.Rlimits) > 0 || opts.StdoutFile != nil || opts.StderrFile != nil) && sb == nil {
		return nil, "", nil, fail.E("failed")
	}
	if len(opts.Pass) > MaxPass || len(opts.Pass) > 0 && notify {
		return nil, "", nil, fail.E("failed")
	}
	if sb != nil || join {
		cmd, claim, notifyR, err := launchHelper(ctx, self, argv, execF, sb, notify, timeout, opts, join)
		if err == errNoClone {
			noClone.Store(true)
			return launchHelper(ctx, self, argv, execF, sb, notify, timeout, opts, true)
		}
		return cmd, claim, notifyR, err
	}
	cmd, notifyR, err := direct(self, target, argv, execF, script, notify, opts)
	if err == errNoClone {
		noClone.Store(true)
		return launchHelper(ctx, self, argv, execF, nil, notify, timeout, opts, true)
	}
	if err != nil {
		return nil, "", nil, err
	}
	return cmd, claimNone, notifyR, nil
}

// noClone is set once clone3(CLONE_INTO_CGROUP) is found missing (Linux
// before 5.7, or a seccomp filter that hides clone3). Every later launch
// into a cgroup then goes through the helper, which the supervisor moves
// into the cgroup before the helper may exec.
var noClone atomic.Bool

// errNoClone is compared with == and never wrapped.
var errNoClone = errors.New("no clone3 into cgroup")

// startErr maps a failed Start. Into a cgroup, EBUSY (not a leaf, or
// controllers enabled below it), ENODEV (removed) and EOPNOTSUPP mean the
// child cannot join it (cgroup_join). ENOSYS and E2BIG mean the kernel
// cannot clone into a cgroup (errNoClone) only if a probe confirms it: an
// execve E2BIG (argument list too long) must not switch every later launch
// to the helper.
func startErr(err error, self string, g *cgroup.Group) error {
	if g != nil {
		switch {
		case cloneMissing(err, self, g):
			return errNoClone
		case errors.Is(err, syscall.EBUSY), errors.Is(err, syscall.ENODEV), errors.Is(err, syscall.EOPNOTSUPP):
			return fail.E("cgroup_join")
		}
	}
	return fail.E("failed")
}

// runsAsRoot reports whether the process would run as uid 0: an explicit
// uid 0, or no uid while the supervisor is root.
func runsAsRoot(e unit.Execution) bool {
	if e.UID == nil {
		return os.Geteuid() == 0
	}
	return *e.UID == 0
}

// headLen is the kernel's limit on the #! line (BINPRM_BUF_SIZE).
const headLen = 256

// checkInterp reports whether head starts a #! script, and checks its
// interpreter: an absolute path resolved and checked like the target itself
// (unit.ResolveExec), which must not be a script in turn. A relative
// interpreter, a #! line longer than the kernel reads, or an env-style
// interpreter that looks the real one up in PATH is exec_interp.
//
// Threats: the kernel runs the interpreter by path with the target's
// privileges, so an interpreter in a directory someone else can write would
// let them choose what runs. env lookups depend on a PATH the unit sets.
func checkInterp(head []byte) (bool, error) {
	if !bytes.HasPrefix(head, []byte("#!")) {
		return false, nil
	}
	line, _, found := bytes.Cut(head[2:], []byte{'\n'})
	if !found && len(head) >= headLen {
		return true, fail.E("exec_interp")
	}
	// The kernel splits a #! line on space and tab only: a CR or other
	// whitespace stays part of the interpreter path, and is checked so.
	fields := strings.FieldsFunc(string(line), func(r rune) bool { return r == ' ' || r == '\t' })
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return true, fail.E("exec_interp")
	}
	interp := fields[0]
	// env, or a multi-call binary asked to act as env (busybox env),
	// looks the real interpreter up in PATH.
	if path.Base(interp) == "env" || len(fields) > 1 && fields[1] == "env" {
		return true, fail.E("exec_interp")
	}
	resolved, err := unit.ResolveExec(path.Clean(interp))
	if err != nil {
		return true, err
	}
	inner, err := readHead(nil, resolved)
	if err != nil {
		return true, err
	}
	if bytes.HasPrefix(inner, []byte("#!")) {
		return true, fail.E("exec_interp")
	}
	return true, nil
}

func checkArgv(argv []string) error {
	if len(argv) < 1 || len(argv) > maxArgv {
		return fail.E("failed")
	}
	for _, arg := range argv {
		if len(arg) > maxArg || strings.ContainsRune(arg, 0) {
			return fail.E("failed")
		}
	}
	return unit.ExecPath(argv[0])
}

// direct starts the target without the helper. On Linux the kernel runs the
// checked file through its fd (see directTarget); elsewhere the resolved path
// is run.
func direct(self, target string, argv []string, execF *os.File, script, notify bool, opts Options) (*exec.Cmd, *os.File, error) {
	var notifyR, notifyW *os.File
	if notify {
		var err error
		notifyR, notifyW, err = os.Pipe()
		if err != nil {
			return nil, nil, fail.E("failed")
		}
	}
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		closePair(notifyR, notifyW)
		return nil, nil, fail.E("failed")
	}
	env := opts.Execution.Env()
	if notify {
		env = append(env, "SAHINIT_READY_FD=3")
	}
	target, extra, held, err := directTarget(target, execF, script, notifyW)
	if err != nil {
		null.Close()
		closePair(notifyR, notifyW)
		return nil, nil, fail.E("failed")
	}
	if held != nil {
		defer held.Close()
		// The forked child moves fds through the ones just above its
		// highest passed fd (syscall's nextfd) before execve, which would
		// overwrite held when it is that number. Passing /dev/null as a
		// close-on-exec copy above held puts that scratch range above it.
		hi, err := unix.FcntlInt(null.Fd(), unix.F_DUPFD_CLOEXEC, int(held.Fd())+1)
		null.Close()
		if err != nil {
			closePair(notifyR, notifyW)
			return nil, nil, fail.E("failed")
		}
		null = os.NewFile(uintptr(hi), "/dev/null")
	}
	cmd := &exec.Cmd{
		Path:        target,
		Args:        append([]string{}, argv...),
		Dir:         "/",
		Env:         env,
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		ExtraFiles:  extra,
		SysProcAttr: procAttr(opts.Cgroup),
	}
	opts.configure(cmd)
	if err := cmd.Start(); err != nil {
		null.Close()
		closePair(notifyR, notifyW)
		return nil, nil, startErr(err, self, opts.Cgroup)
	}
	if err := null.Close(); err != nil {
		closePair(notifyR, notifyW)
		reap(cmd)
		return nil, nil, fail.E("failed")
	}
	if notifyW != nil {
		if err := notifyW.Close(); err != nil {
			notifyR.Close()
			reap(cmd)
			return nil, nil, fail.E("failed")
		}
	}
	return cmd, notifyR, nil
}

func closePair(a, b *os.File) {
	if a != nil {
		a.Close()
	}
	if b != nil {
		b.Close()
	}
}

// reap signals the process group and collects the child. A process that
// already exited still counts as collected once Wait records a state.
func reap(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fail.E("failed")
	}
	pid := cmd.Process.Pid
	var killErr error
	if pid > 0 {
		killErr = syscall.Kill(-pid, syscall.SIGKILL)
		if killErr != nil && killErr != syscall.ESRCH {
			err2 := syscall.Kill(pid, syscall.SIGKILL)
			if err2 != nil && err2 != syscall.ESRCH {
				killErr = err2
			} else {
				killErr = nil
			}
		} else {
			killErr = nil
		}
	}
	waitErr := cmd.Wait()
	if cmd.ProcessState != nil {
		return nil
	}
	if waitErr != nil {
		return waitErr
	}
	if killErr != nil {
		return killErr
	}
	return fail.E("failed")
}

// cloneMissing reports whether err, from a Start into g, means clone3 cannot
// place a child in a cgroup here. Only ENOSYS and E2BIG can mean that, and
// both can also come from execve; a probe that starts self ("apply" with no
// handshake, which exits 2 at once) into g with tiny arguments decides.
func cloneMissing(err error, self string, g *cgroup.Group) bool {
	if g == nil || !errors.Is(err, syscall.ENOSYS) && !errors.Is(err, syscall.E2BIG) {
		return false
	}
	probe := &exec.Cmd{Path: self, Args: []string{self, "apply"}, Dir: "/", SysProcAttr: procAttr(g)}
	if perr := probe.Start(); perr != nil {
		return errors.Is(perr, syscall.ENOSYS) || errors.Is(perr, syscall.E2BIG)
	}
	probe.Wait()
	return false
}

// Options supplies execution identity and bounded output sinks. Callers own sinks.
type Options struct {
	// Path is argv[0] already resolved (unit.Service.Path). Empty means
	// Launch resolves argv[0] itself. Either way it is checked again.
	SHA256    string
	Path      string
	Execution unit.Execution
	Stdout    io.Writer
	Stderr    io.Writer
	// Cgroup, when set, is the service cgroup the child joins before it
	// execs: through clone3(CLONE_INTO_CGROUP), or by the helper writing
	// its own pid to cgroup.procs where clone3 cannot. A child that cannot
	// join is cgroup_join.
	Cgroup *cgroup.Group
	// Pass are fds the target receives as fds 3, 4, ... (at most
	// MaxPass), open and not close-on-exec; every other fd is closed at
	// exec as always. Only a sandboxed launch without notify passes fds.
	Pass []*os.File
	// Umask, when not nil, is the target's umask.
	Umask *int
	// StdoutFile and StderrFile, when set, are opened by the helper, as
	// the target's uid and gid, beneath Root with no symlink at any
	// component (stream_denied otherwise), for appending, and made the
	// target's stdout or stderr. StderrToStdout makes stderr the same file
	// as stdout. Only a sandboxed launch has them.
	StdoutFile, StderrFile *StreamFile
	StderrToStdout         bool
	// Rlimits are set by the helper, soft and hard, before it execs (so
	// they can only lower a limit):
	// resource name (nofile, nproc, core, memlock, stack, as, cpu, fsize)
	// to value. Only a sandboxed launch sets them.
	Rlimits map[string]uint64
}

// StreamFile is a file the helper opens for a stream.
type StreamFile struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

// MaxPass is the most fds Options.Pass may hold.
const MaxPass = 4

func (o Options) configure(cmd *exec.Cmd) {
	if o.Execution.Directory != "" {
		cmd.Dir = o.Execution.Directory
	}
	if o.Execution.UID != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: *o.Execution.UID, Gid: *o.Execution.GID, Groups: append([]uint32{}, o.Execution.Groups...)}
	}
	if o.Stdout != nil {
		cmd.Stdout = o.Stdout
	}
	if o.Stderr != nil {
		cmd.Stderr = o.Stderr
	}
	// Descendants may inherit output pipes after the main process exits.
	cmd.WaitDelay = time.Second
}
