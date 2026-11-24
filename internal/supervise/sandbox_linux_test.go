// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// On Debian /bin/sh, /bin and /lib are links. A unit naming them loads,
// runs sandboxed as a non-root uid, and reports the Landlock ABI applied;
// once stopped it reports no sandbox.
func TestSandboxedUnitThroughLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to run the helper as uid 65534")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.CreateTemp("/tmp", "sahinit-sup-helper-*")
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
		"name": "boxed", "exec": []string{"/bin/sh", "-c", "exec sleep 30"},
		"type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": []string{"/bin", "/lib", "/usr"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/boxed.json", body, 0o644); err != nil {
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
	t.Cleanup(func() { sup.Shutdown(t.Context()) })
	if err := sup.Start(t.Context(), "boxed"); err != nil {
		if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
			t.Skipf("kernel lacks sandbox: %v", err)
		}
		t.Fatal(err)
	}
	row := rowOf(t, sup, "boxed")
	if row.State != "running" || row.Pid <= 0 || !sandbox.IsSandboxClaim(row.Sandbox) {
		t.Fatalf("%+v", row)
	}
	if err := sup.Stop(t.Context(), "boxed"); err != nil {
		t.Fatal(err)
	}
	if row := rowOf(t, sup, "boxed"); row.State != "stopped" || row.Sandbox != "" {
		t.Fatalf("%+v", row)
	}
}
