//go:build darwin

package supervise

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func openPidfd(int) int { return -1 }

func closePidfd(int) {}

func pidfdSignalGroup(int, syscall.Signal) error { return syscall.ENOSYS }

// waitExited blocks until the child has exited, without reaping it, using a
// kqueue NOTE_EXIT event. A process already exiting cannot be registered
// (ESRCH) and counts as exited.
func waitExited(pid int) {
	kq, err := unix.Kqueue()
	if err != nil {
		return
	}
	defer unix.Close(kq)
	ev := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
	out := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(kq, ev, out, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n > 0 {
			return
		}
	}
}
