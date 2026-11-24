// SPDX-License-Identifier: GPL-3.0-or-later

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

func (*Root) Join(string) (*Group, error) { return nil, fail.E("cgroup_unavailable") }

func (*Root) PrepareScratch(string, time.Duration) (*Group, error) {
	return nil, fail.E("cgroup_unavailable")
}

func (*Root) DropScratch(string, time.Duration) error { return fail.E("cgroup_unavailable") }

func (*Root) KillAll(string, time.Duration) error { return fail.E("cgroup_unavailable") }

func (*Root) Kill(string) error { return fail.E("cgroup_unavailable") }

func (*Root) Usage(string) (Usage, bool) { return Usage{}, false }

func (*Root) Supervised(int) bool { return true }

func (*Root) Close() error { return nil }

func (*Root) Protected() bool { return false }

func (*Root) Rel() string { return "" }

func (*Root) CleanLeftovers() ([]string, error) { return nil, nil }

// Sweep is what one sweep found.
type Sweep struct {
	Killed      []int
	Cgroups     []string
	RootMembers []int
}

func (*Root) SweepStrays(map[string]bool) Sweep { return Sweep{} }
