// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"syscall"

	"github.com/afterdarksys/sahinit/internal/cgroup"
)

// procAttr places the child in its process group and, when g is set, in
// g's cgroup from the moment it exists (clone3 with CLONE_INTO_CGROUP), so
// no fork of it can happen outside the cgroup.
func procAttr(g *cgroup.Group) *syscall.SysProcAttr {
	// Pdeathsig is delivered on the thread that created the child and can
	// fire when the runtime recycles that thread (Go issue 27505). The field
	// is still set so a live parent thread takes the child with it.
	attr := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if g != nil && g.Dir != nil {
		attr.UseCgroupFD = true
		attr.CgroupFD = int(g.Dir.Fd())
	}
	return attr
}
