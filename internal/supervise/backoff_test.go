// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func crashSvc(t *testing.T, body string, delay time.Duration) *unit.Service {
	svc := newSvc("a", "simple", "notify", "always", false, 2*time.Second, shExec(writeScript(t, body)))
	svc.RestartDelay, svc.RestartMaxDelay = delay, 5*time.Second
	return svc
}

func backoffOf(s *runtime) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backoff
}

// A notify unit that becomes ready and then crashes inside the stable
// period ends in restart_limit after the burst, even with a window too
// short to ever hold one.
func TestNotifyCrashLoopEndsInRestartLimit(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"a": crashSvc(t, "printf x >&3\n/bin/sleep 0.05\nexit 1\n", 10*time.Millisecond)})
	sup.RestartWindow = time.Millisecond
	sup.stableMin = 2 * time.Second
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "a", 15*time.Second, func(r Row) bool { return r.State == "failed" })
	if row.LastError != "restart_limit" || row.Restarts != defaultBurst {
		t.Fatalf("%+v", row)
	}
}

// The same unit staying ready past the stable period keeps restarting: its
// readiness resets the crash count.
func TestNotifyStableRunsKeepRestarting(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"a": crashSvc(t, "printf x >&3\n/bin/sleep 0.6\nexit 1\n", 10*time.Millisecond)})
	sup.RestartWindow = time.Millisecond
	sup.RestartBurst = 2
	sup.stableMin = 100 * time.Millisecond
	sup.svcTimeoutForTest("a", 300*time.Millisecond)
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "a", 15*time.Second, func(r Row) bool { return r.Restarts >= 3 || r.State == "failed" })
	if row.State == "failed" {
		t.Fatalf("stable runs hit the limit: %+v", row)
	}
	stopRetry(t, sup, "a")
}

// After a real crash the unit is in backoff for its delay, then the flag
// is cleared and it runs again.
func TestBackoffSetAndCleared(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"a": crashSvc(t, "printf x >&3\nexec /bin/sleep 30\n", 600*time.Millisecond)})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	s, _ := sup.runtime("a")
	pid := rowOf(t, sup, "a").Pid
	if err := s.signalGroup(pid, 9); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !backoffOf(s) {
		if time.Now().After(deadline) {
			t.Fatal("no backoff after a crash")
		}
		time.Sleep(5 * time.Millisecond)
	}
	row := waitRow(t, sup, "a", 5*time.Second, func(r Row) bool { return r.State == "running" && r.Pid > 0 && r.Pid != pid })
	if backoffOf(s) {
		t.Fatalf("backoff still set after the restart: %+v", row)
	}
	stopRetry(t, sup, "a")
}

// Consecutive crashes double the delay: 100, 200, 400, 800 ms (each 80-100
// percent), so the last gap between starts is well above the first.
func TestBackoffExponent(t *testing.T) {
	svc := newSvc("a", "simple", "exec", "always", false, 2*time.Second, []string{"/bin/sh", "-c", "exit 1"})
	svc.RestartDelay, svc.RestartMaxDelay = 100*time.Millisecond, 5*time.Second
	sup := mustSup(t, map[string]*unit.Service{"a": svc})
	sup.RestartWindow = time.Millisecond
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	waitRow(t, sup, "a", 15*time.Second, func(r Row) bool { return r.State == "failed" })
	d, err := sup.Diagnostics("a")
	if err != nil {
		t.Fatal(err)
	}
	var starts []time.Time
	for _, e := range d.Events {
		if e.Kind == "started" {
			starts = append(starts, e.Time)
		}
	}
	if len(starts) != defaultBurst+1 {
		t.Fatalf("%d starts", len(starts))
	}
	first, last := starts[1].Sub(starts[0]), starts[5].Sub(starts[4])
	if first > 300*time.Millisecond || last < 1200*time.Millisecond {
		t.Fatalf("gaps first %v last %v", first, last)
	}
}

// A sash unit whose restart delay is longer than its window still ends in
// restart_limit: the crash count does not depend on the window.
func TestSashCrashLoopEndsInRestartLimit(t *testing.T) {
	defer func(old func() time.Time) { clock = old }(clock)
	now := time.Unix(1800000000, 0)
	clock = func() time.Time { return now }
	svc := &unit.Service{Name: "s", Type: "simple", Restart: "always", Timeout: time.Second,
		Sash: &unit.Sash{File: "/s.sash", Desc: &sash.Description{Name: "s", Restart: &sash.Restart{Policy: "always", Delay: time.Millisecond, Burst: 3, Within: time.Nanosecond}}}}
	sup := mustSup(t, map[string]*unit.Service{"s": svc})
	s, _ := sup.runtime("s")
	allowed := 0
	for i := 0; i < 20; i++ {
		s.mu.Lock()
		s.gen++
		gen := s.gen
		s.state, s.ready, s.readyAt = "running", true, now
		s.mu.Unlock()
		now = now.Add(100 * time.Millisecond)
		sup.sashFinish(s, gen, false, "failed", false)
		s.mu.Lock()
		state, backoff := s.state, s.backoff
		s.gen++ // the scheduled relaunch finds itself stale
		s.mu.Unlock()
		if state == "failed" {
			break
		}
		if !backoff {
			t.Fatal("sash restart without backoff")
		}
		allowed++
		now = now.Add(time.Hour)
	}
	if allowed != 3 || s.lastError != "restart_limit" {
		t.Fatalf("%d restarts, last error %q", allowed, s.lastError)
	}
}

// svcTimeoutForTest shortens a unit's timeout, which stableFor also reads.
func (sup *Supervisor) svcTimeoutForTest(name string, d time.Duration) {
	s, _ := sup.runtime(name)
	s.svc.Timeout = d
}

// A manual start while an old restart is still waiting out its delay clears
// the backoff flag, so strict boot does not see a stale one.
func TestManualStartClearsBackoff(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"a": crashSvc(t, "printf x >&3\nexec /bin/sleep 30\n", 3*time.Second)})
	ctx, cancel := ctxFor(t, 10*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	s, _ := sup.runtime("a")
	if err := s.signalGroup(rowOf(t, sup, "a").Pid, 9); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !backoffOf(s) {
		if time.Now().After(deadline) {
			t.Fatal("no backoff after a crash")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := sup.Stop(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if backoffOf(s) {
		t.Fatal("manual start left the backoff flag set")
	}
	stopRetry(t, sup, "a")
}
