// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// A deployment's admission is asked before a start, and before every
// automatic restart with restart=true; a refusal fails the unit with the
// policy's token.
func TestAdmissionOnStartAndRestart(t *testing.T) {
	svc := newSvc("a", "simple", "exec", "always", false, time.Second, []string{"/bin/sh", "-c", "/bin/sleep 0.2; exit 1"})
	sup := mustSup(t, map[string]*unit.Service{"a": svc})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sup.SetAdmission(func(name string, restart bool) error { return fail.E("policy_unit_denied") })
	if err := sup.Start(ctx, "a"); fail.Token(err) != "policy_unit_denied" {
		t.Fatalf("start: %v", err)
	}
	if row := rowOf(t, sup, "a"); row.State != "failed" || row.LastError != "policy_unit_denied" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	var restarts atomic.Int32
	sup.SetAdmission(func(name string, restart bool) error {
		if restart {
			restarts.Add(1)
			return fail.E("policy_expired")
		}
		return nil
	})
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "a", 5*time.Second, func(r Row) bool { return r.State == "failed" })
	if row.LastError != "policy_expired" || restarts.Load() != 1 {
		t.Fatalf("%+v restarts asked %d", row, restarts.Load())
	}
}

// A process group led by a unit removed in a live catalog change still
// counts as supervised for the peer check while it has members.
func TestRetiredGroupStaysSupervised(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	pid := cmd.Process.Pid
	sup := mustSup(t, map[string]*unit.Service{"a": newSvc("a", "simple", "exec", "no", false, time.Second, []string{"/bin/true"})})
	if sup.supervisedPeer(pid) {
		t.Fatal("an unrelated group counts as supervised")
	}
	gone := &runtime{svc: newSvc("x", "simple", "exec", "no", false, time.Second, []string{"/bin/true"}), group: pid, pidfd: -1}
	sup.catalogMu.Lock()
	sup.retireLocked(map[string]*runtime{"x": gone}, map[string]bool{"x": true})
	sup.catalogMu.Unlock()
	if !sup.supervisedPeer(pid) {
		t.Fatal("a retired unit's live group is not supervised")
	}
}

// In strict boot an essential unit blocked on a provider that failed for
// good is a failure; one blocked on a provider that is restarting is not.
func TestEssentialFailureBlocked(t *testing.T) {
	db := newSvc("db", "simple", "exec", "always", true, time.Second, []string{"/bin/true"})
	app := newSvc("app", "simple", "exec", "no", true, time.Second, []string{"/bin/true"})
	app.Needs, app.Essential = []string{"db"}, true
	sup := mustSup(t, map[string]*unit.Service{"db": db, "app": app})
	d, _ := sup.runtime("db")
	a, _ := sup.runtime("app")
	a.desired, a.state = true, "blocked"
	d.desired, d.state = true, "failed"
	if got := sup.EssentialFailure(false); got != "app" {
		t.Fatalf("provider failed: %q", got)
	}
	d.state = "starting"
	if got := sup.EssentialFailure(false); got != "" {
		t.Fatalf("provider restarting: %q", got)
	}
}
