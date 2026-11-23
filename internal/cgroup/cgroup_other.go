//go:build !linux

package cgroup

import (
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// Supported reports whether this platform has cgroups. Elsewhere than Linux
// the supervisor keeps process groups and reports cgroups as unsupported.
func Supported() bool { return false }

// Root is never opened on this platform.
type Root struct{}

// Open is cgroup_unavailable on this platform.
func Open(string) (*Root, error) { return nil, fail.E("cgroup_unavailable") }

func (*Root) Supports(unit.Limits) error { return fail.E("cgroup_controller") }

func (*Root) Path(string) string { return "" }

func (*Root) Prepare(string, unit.Limits, time.Duration) (*Group, error) {
	return nil, fail.E("cgroup_unavailable")
}

func (*Root) KillAll(string, time.Duration) error { return fail.E("cgroup_unavailable") }

func (*Root) Kill(string) error { return fail.E("cgroup_unavailable") }

func (*Root) Usage(string) (Usage, bool) { return Usage{}, false }

func (*Root) Supervised(int) bool { return true }
