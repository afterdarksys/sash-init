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
	cleanPATH = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
)

// Launch starts argv[0]. A nil sandbox is a direct exec and claims "none".
// A sandbox is applied in a re-exec of self. claim is empty when err != nil.
// notify places the ready write end on fd 3 and sets SAHINIT_READY_FD.
func Launch(ctx context.Context, self string, argv []string, sb *unit.Sandbox, notify bool, timeout time.Duration) (*exec.Cmd, string, *os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", nil, fail.E("failed")
	}
	if err := checkArgv(argv); err != nil {
		return nil, "", nil, err
	}
	if err := unit.ExecFile(argv[0]); err != nil {
		return nil, "", nil, err
	}
	if sb != nil {
		return launchSandboxed(ctx, self, argv, sb, notify, timeout)
	}
	cmd, notifyR, err := direct(argv, notify)
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

func direct(argv []string, notify bool) (*exec.Cmd, *os.File, error) {
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
	env := []string{cleanPATH}
	if notify {
		env = append(env, "SAHINIT_READY_FD=3")
	}
	var extra []*os.File
	if notifyW != nil {
		extra = []*os.File{notifyW}
	}
	cmd := &exec.Cmd{
		Path:        argv[0],
		Args:        append([]string{}, argv...),
		Dir:         "/",
		Env:         env,
		Stdin:       null,
		Stdout:      null,
		Stderr:      null,
		ExtraFiles:  extra,
		SysProcAttr: procAttr(),
	}
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
