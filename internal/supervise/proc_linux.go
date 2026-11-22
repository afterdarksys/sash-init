//go:build linux

package supervise

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// pidfdSignalProcessGroup is PIDFD_SIGNAL_PROCESS_GROUP (Linux 6.9).
const pidfdSignalProcessGroup = 1 << 2

// openPidfd returns a pidfd for an unreaped child, or -1 when the kernel has
// no pidfd_open (before 5.3). Only this process reaps its children, so the
// pid cannot have been reused yet.
func openPidfd(pid int) int {
	fd, err := unix.PidfdOpen(pid, 0) // close-on-exec by default
	if err != nil {
		return -1
	}
	return fd
}

func closePidfd(fd int) {
	if fd >= 0 {
		unix.Close(fd)
	}
}

// pidfdSignalGroup signals the process group whose id is the pidfd's pid.
// The pidfd names that pid object, not its number, so a group that is gone
// gives ESRCH even if the number has been reused. A kernel before 6.9
// rejects the flag with EINVAL.
func pidfdSignalGroup(fd int, sig syscall.Signal) error {
	err := unix.PidfdSendSignal(fd, sig, nil, pidfdSignalProcessGroup)
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return err
}

// waitExited blocks until the child can be reaped, without reaping it.
func waitExited(pid int) {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			return
		}
	}
}
