// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"testing"
	"time"
)

func TestApplyPreservesUnrelatedAndRollsBack(t *testing.T) {
	makeCatalog := func(arg string) map[string]*unit.Service {
		db := newSvc("db", "simple", "exec", "no", true, time.Second, []string{"/bin/sleep", arg})
		app := newSvc("app", "simple", "exec", "no", true, time.Second, []string{"/bin/sleep", "30"})
		app.Needs = []string{"db"}
		other := newSvc("other", "simple", "exec", "no", true, time.Second, []string{"/bin/sleep", "30"})
		return map[string]*unit.Service{"db": db, "app": app, "other": other}
	}
	sup := mustSup(t, makeCatalog("30"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, [][]string{{"db", "other"}, {"app"}}); err != nil {
		t.Fatal(err)
	}
	other := rowOf(t, sup, "other").Pid
	app := rowOf(t, sup, "app").Pid
	diff, err := sup.Apply(ctx, makeCatalog("31"))
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Changed) != 1 || len(diff.Affected) != 2 || rowOf(t, sup, "other").Pid != other || rowOf(t, sup, "app").Pid == app {
		t.Fatalf("%+v", diff)
	}
	if _, err := sup.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if sup.Catalog()["db"].Exec[1] != "30" || rowOf(t, sup, "other").Pid != other {
		t.Fatal("rollback lost catalog/unrelated PID")
	}
	bad := makeCatalog("30")
	bad["db"].Type = "oneshot"
	bad["db"].Ready = "exit"
	bad["db"].Exec = []string{"/bin/false"}
	diff, err = sup.Apply(ctx, bad)
	if fail.Token(err) != "apply_rolled_back" || !diff.RolledBack {
		t.Fatalf("%+v %v", diff, err)
	}
	if rowOf(t, sup, "db").State != "running" || rowOf(t, sup, "app").State != "running" || rowOf(t, sup, "other").Pid != other {
		t.Fatal("failed apply did not recover")
	}
	invalid := makeCatalog("30")
	invalid["db"].Needs = []string{"app"}
	pid := rowOf(t, sup, "db").Pid
	if _, err := sup.Apply(ctx, invalid); fail.Token(err) != "cycle" {
		t.Fatal(err)
	}
	if rowOf(t, sup, "db").Pid != pid {
		t.Fatal("invalid graph changed live service")
	}
}

func TestSignedActivationPreflightAndCommitFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	old := map[string]*unit.Service{"app": {Name: "app", Exec: []string{"/bin/sleep", "30"}, Type: "simple", Ready: "exec", Boot: true}}
	sup := mustSup(t, old)
	defer sup.Shutdown(context.Background())
	allow := func(string, bool) error { return nil }
	sup.SetAdmission(allow)
	if err := sup.Start(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	before, _ := sup.Status("app")
	next := map[string]*unit.Service{"app": {Name: "app", Exec: []string{"/bin/sleep", "31"}, Type: "simple", Ready: "exec", Boot: true}}
	if _, err := sup.ApplyAuthorized(ctx, next, func(string, bool) error { return fail.E("policy_revoked") }, func() error { t.Error("commit called"); return nil }); fail.Token(err) != "policy_revoked" {
		t.Fatal(err)
	}
	after, _ := sup.Status("app")
	if after[0].Pid != before[0].Pid {
		t.Fatal("preflight stopped original")
	}
	d, err := sup.ApplyAuthorized(ctx, next, allow, func() error { return fail.E("disk_full") })
	if fail.Token(err) != "activation_commit" || !d.RolledBack {
		t.Fatal(d, err)
	}
	if sup.Catalog()["app"].Exec[1] != "30" {
		t.Fatal("old catalog not restored")
	}
	d, err = sup.ApplyAuthorized(ctx, next, allow, func() error { return fail.E("deployment_durability") })
	if fail.Token(err) != "deployment_durability" || d.RolledBack || sup.Catalog()["app"].Exec[1] != "31" {
		t.Fatal(d, err)
	}
	if _, err := sup.Apply(ctx, old); fail.Token(err) != "signed_activation_required" {
		t.Fatal(err)
	}
	if _, err := sup.Rollback(ctx); fail.Token(err) != "new_policy_required" {
		t.Fatal(err)
	}
}

// A live catalog change is refused when either catalog has a sash unit: its
// runtime (described script, grant, mounts) is not carried across.
func TestApplyRefusesSash(t *testing.T) {
	plain := func() map[string]*unit.Service {
		return map[string]*unit.Service{"a": newSvc("a", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})}
	}
	withSash := func() map[string]*unit.Service {
		c := plain()
		c["s"] = &unit.Service{Name: "s", Type: "simple", Timeout: time.Second, Sash: &unit.Sash{File: "/s.sash"}}
		return c
	}
	ctx := context.Background()
	sup := mustSup(t, plain())
	if _, err := sup.Apply(ctx, withSash()); fail.Token(err) != "catalog_sash" {
		t.Fatalf("candidate with sash: %v", err)
	}
	sup = mustSup(t, withSash())
	if _, err := sup.Apply(ctx, plain()); fail.Token(err) != "catalog_sash" {
		t.Fatalf("running with sash: %v", err)
	}
}
