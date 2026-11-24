// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
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

// plan names each unit for which the cgroup guarantees are not promised:
// no sandbox, and root or the supervisor's uid. A sandboxed unit, or one
// running as another uid, is not named.
func TestPlanFlagsTrusted(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("own", nil))
	root := simpleUnit("root", nil)
	root["execution"] = map[string]any{"uid": 0, "gid": 0}
	putUnit(t, dir, root)
	other := simpleUnit("other", nil)
	other["execution"] = map[string]any{"uid": 65534, "gid": 65534}
	putUnit(t, dir, other)
	boxed := simpleUnit("boxed", nil)
	boxed["execution"] = map[string]any{"uid": 65534, "gid": 65534}
	boxed["sandbox"] = map[string]any{}
	putUnit(t, dir, boxed)
	want := "cgroup_trusted own.json\ncgroup_trusted root.json\n"
	if os.Geteuid() == 65534 {
		want = "cgroup_trusted other.json\n" + want
	}
	wantRun(t, []string{"plan", "--dir", dir}, 0, "boxed other own root\n", want)
}
