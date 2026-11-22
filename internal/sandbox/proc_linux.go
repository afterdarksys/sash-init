//go:build linux

package sandbox

import "syscall"

func procAttr() *syscall.SysProcAttr {
	// Pdeathsig is delivered on the thread that created the child and can
	// fire when the runtime recycles that thread (Go issue 27505). The field
	// is still set so a live parent thread takes the child with it.
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
