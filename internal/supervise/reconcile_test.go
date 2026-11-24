// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"github.com/afterdarksys/sahinit/internal/unit"
	"testing"
	"time"
)

func TestDependencyPauseAndResume(t *testing.T) {
	db := newSvc("db", "simple", "exec", "no", true, time.Second, []string{"/bin/sleep", "30"})
	app := newSvc("app", "simple", "exec", "no", true, time.Second, []string{"/bin/sleep", "30"})
	app.Needs = []string{"db"}
	other := newSvc("other", "simple", "exec", "no", true, time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"db": db, "app": app, "other": other})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, [][]string{{"db", "other"}, {"app"}}); err != nil {
		t.Fatal(err)
	}
	otherPID := rowOf(t, sup, "other").Pid
	if err := sup.Stop(ctx, "db"); err != nil {
		t.Fatal(err)
	}
	if err := sup.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "app")
	if row.State != "blocked" || !row.Desired || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	if rowOf(t, sup, "other").Pid != otherPID {
		t.Fatal("unrelated service restarted")
	}
	if err := sup.Start(ctx, "db"); err != nil {
		t.Fatal(err)
	}
	if err := sup.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if rowOf(t, sup, "app").State != "running" {
		t.Fatal("dependent not resumed")
	}
	if err := sup.Stop(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	if err := sup.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if rowOf(t, sup, "app").Desired || rowOf(t, sup, "app").State != "stopped" {
		t.Fatal("explicit stop undone")
	}
}

func TestEssentialAndRestartDelay(t *testing.T) {
	svc := newSvc("a", "simple", "exec", "no", true, time.Second, []string{"/bin/false"})
	sup := mustSup(t, map[string]*unit.Service{"a": svc})
	s := sup.rt["a"]
	s.state = "failed"
	s.desired = true
	if sup.EssentialFailure(false) != "" {
		t.Fatal("optional failure escalated")
	}
	svc.Essential = true
	if sup.EssentialFailure(false) != "a" {
		t.Fatal("essential failure missed")
	}
	s.state = "starting"
	if sup.EssentialFailure(false) != "" {
		t.Fatal("restart escalated")
	}
	svc.RestartDelay = time.Second
	svc.RestartMaxDelay = 3 * time.Second
	for i := 0; i < 100; i++ {
		if d := restartDelay(svc, 1); d < 800*time.Millisecond || d > time.Second {
			t.Fatal(d)
		}
		if d := restartDelay(svc, 10); d < 2400*time.Millisecond || d > 3*time.Second {
			t.Fatal(d)
		}
	}
	s.state = "stopped"
	s.desired = false
}
