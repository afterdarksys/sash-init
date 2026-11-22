//go:build !linux

package sandbox

import "syscall"

func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
