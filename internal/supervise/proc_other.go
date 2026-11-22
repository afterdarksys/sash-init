//go:build !linux && !darwin

package supervise

import "syscall"

func openPidfd(int) int { return -1 }

func closePidfd(int) {}

func pidfdSignalGroup(int, syscall.Signal) error { return syscall.ENOSYS }

// waitExited cannot wait without reaping here; the reaper then marks the
// service exiting before the process has exited.
func waitExited(int) {}
