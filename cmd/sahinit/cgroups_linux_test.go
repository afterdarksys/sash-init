//go:build linux

package main

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Without a writable, delegated cgroup v2, supervise refuses to start
// unless --no-cgroups is given.
func TestSuperviseCgroupUnavailable(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup")
	}
	own := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			own = p
		}
	}
	if own != "" && unix.Access("/sys/fs/cgroup"+own+"/cgroup.procs", unix.W_OK) == nil {
		t.Skip("own cgroup is writable here; run the plain (unprivileged) Docker suite for this test")
	}
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("a", []string{"b"}))
	putUnit(t, dir, simpleUnit("b", []string{"a"}))
	sock := sockPath(t, "nocg")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock}, 2, "", "cgroup_unavailable\n")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--no-cgroups"}, 2, "", "cycle\n")
	absentSock(t, sock)
}
