// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/cgroup/cgtest"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// procCaps reads the capability lines, Seccomp and NoNewPrivs of a running
// process.
func procCaps(t *testing.T, pid int) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && (strings.HasPrefix(k, "Cap") || k == "Seccomp" || k == "NoNewPrivs") {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// A unit with caps through the whole supervise path: loaded from a unit
// file, started into its own cgroup (the cgroup fd, Credential and
// AmbientCaps on one start), then restarted. Each run holds exactly
// net_bind_service and setgid in all five sets, with the id filter on.
func TestSupervisedUnitCaps(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to give caps")
	}
	r, err := cgroup.Open(cgtest.Dir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.CreateTemp("/tmp", "sahinit-caps-helper-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(helper.Name()) })
	if _, err := helper.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := helper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper.Name(), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	body, err := json.Marshal(map[string]any{
		"name": "capped", "exec": []string{"/bin/sh", "-c", "exec sleep 30"},
		"type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox": map[string]any{
			"read_only_paths": []string{"/bin", "/lib", "/usr"},
			"caps":            []string{"net_bind_service", "setgid"}, "setgid_to": []int{65533},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/capped.json", body, 0o644); err != nil {
		t.Fatal(err)
	}
	svcs, refused, err := unit.Load(dir)
	if err != nil || len(refused) != 0 {
		t.Fatal(err, refused)
	}
	sup, err := New(svcs, helper.Name())
	if err != nil {
		t.Fatal(err)
	}
	sup.Cgroups = r
	t.Cleanup(func() { sup.Shutdown(t.Context()) })
	if err := sup.Start(t.Context(), "capped"); err != nil {
		if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
			t.Skipf("kernel lacks sandbox: %v", err)
		}
		t.Fatal(err)
	}
	const bits = "0000000000000440"
	check := func(prev int) int {
		t.Helper()
		row := rowOf(t, sup, "capped")
		if row.State != "running" || row.Pid <= 0 || row.Pid == prev || !strings.HasSuffix(row.Sandbox, ",id_filter") || !sandbox.IsSandboxClaim(row.Sandbox) {
			t.Fatalf("%+v", row)
		}
		if cg, err := cgtest.Cgroup(row.Pid); err != nil || cg != r.Path("capped") {
			t.Fatalf("in %q %v", cg, err)
		}
		got := procCaps(t, row.Pid)
		for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd"} {
			if got[k] != bits {
				t.Errorf("%s=%s, want %s", k, got[k], bits)
			}
		}
		if got["Seccomp"] != "2" || got["NoNewPrivs"] != "1" {
			t.Errorf("%v", got)
		}
		return row.Pid
	}
	first := check(0)
	if err := sup.Restart(t.Context(), "capped"); err != nil {
		t.Fatal(err)
	}
	check(first)
}

// The sash host refuses a spawn that asks for caps, before anything else,
// even though the sash server already refuses it.
func TestSashSpawnCapsRefused(t *testing.T) {
	uid := uint32(65534)
	svc := &unit.Service{Name: "app", Execution: unit.Execution{UID: &uid, GID: &uid}, Sandbox: &unit.Sandbox{NoNewPrivs: true}}
	sup := mustSup(t, map[string]*unit.Service{"app": svc})
	h := &sashHost{sup: sup, s: &runtime{svc: svc}}
	err := h.Spawn(sash.SpawnPlan{Name: "x", Program: "/bin/true", Argv: []string{"/bin/true"}, Caps: []string{"net_bind_service"}}, &sash.Proc{})
	if fail.Token(err) != "caps_unsupported" {
		t.Fatal(err)
	}
}
