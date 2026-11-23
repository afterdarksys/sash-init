package main

import (
	"testing"

	"github.com/afterdarksys/sahinit/internal/cgroup"
)

// A unit with limits is left out, and named, when there are no cgroups to
// enforce them; the rest of the catalog goes on to the plan.
func TestSuperviseRefusesLimitsWithoutCgroups(t *testing.T) {
	dir := t.TempDir()
	capped := simpleUnit("capped", nil)
	capped["memory_max"] = "64M"
	putUnit(t, dir, capped)
	putUnit(t, dir, simpleUnit("a", []string{"b"}))
	putUnit(t, dir, simpleUnit("b", []string{"a"}))
	sock := sockPath(t, "limits")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--no-cgroups"}, 2, "", "cgroup_controller capped.json\ncycle\n")
	if !cgroup.Supported() {
		wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock}, 2, "", "cgroup_controller capped.json\ncycle\n")
	}
	only := t.TempDir()
	putUnit(t, only, capped)
	wantRun(t, []string{"supervise", "--dir", only, "--socket", sock, "--no-cgroups"}, 2, "", "cgroup_controller capped.json\nempty\n")
	absentSock(t, sock)
}

func TestSuperviseNoCgroupsInUsage(t *testing.T) {
	wantRun(t, []string{"supervise", "--no-cgroups=x"}, 2, "", usageText)
}
