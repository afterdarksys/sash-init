//go:build !linux

package sandbox

import (
	"syscall"

	"github.com/afterdarksys/sahinit/internal/cgroup"
)

// procAttr ignores g: Launch refuses a cgroup here before any start.
func procAttr(*cgroup.Group) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
