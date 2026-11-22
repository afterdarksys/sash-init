// Package sandbox starts a service process.
//
// Threats: sandbox setup runs in a fresh process so a multithreaded parent
// is not restricted. openat2 failure, landlock rejection, and capset failure
// skip exec. The status claim lists only mechanisms that returned success.
// No path is granted MAKE_SYM. The spec cannot name the executable.
// Network is not confined in v1.
package sandbox

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const (
	claimNone = "none"
	claimFull = "no_new_privs,landlock,caps"
	maxArgv   = 32
	maxArg    = 256
)

// Launch starts argv[0]. A nil sandbox is a direct exec and claims "none".
// A sandbox is applied in a re-exec of self. claim is empty when err != nil.
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
	if sb != nil {
		return launchSandboxed(ctx, self, argv, execF, sb, notify, timeout, opts)
	}
	cmd, notifyR, err := direct(target, argv, execF, notify, opts)
	if err != nil {
		return nil, "", nil, err
	}
	return cmd, claimNone, notifyR, nil
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

// direct starts the target without the helper. With an exec fd (Linux) the
// fd sits at fdExec and the kernel runs /proc/self/fd/4, the checked file;
// the target keeps that O_PATH fd, which a script interpreter needs to read
// the script. Elsewhere the resolved path is run.
func direct(target string, argv []string, execF *os.File, notify bool, opts Options) (*exec.Cmd, *os.File, error) {
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
	var extra []*os.File
	if notifyW != nil {
		extra = []*os.File{notifyW}
	}
	if execF != nil {
		// A nil entry closes fd 3 in the child when notify is off.
		extra = []*os.File{notifyW, execF}
		target = execPathFD
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
		SysProcAttr: procAttr(),
	}
	opts.configure(cmd)
	if err := cmd.Start(); err != nil {
		null.Close()
		closePair(notifyR, notifyW)
		return nil, nil, fail.E("failed")
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

// Options supplies execution identity and bounded output sinks. Callers own sinks.
type Options struct {
	// Path is argv[0] already resolved (unit.Service.Path). Empty means
	// Launch resolves argv[0] itself. Either way it is checked again.
	Path      string
	Execution unit.Execution
	Stdout    io.Writer
	Stderr    io.Writer
}

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
