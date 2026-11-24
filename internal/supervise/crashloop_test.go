// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
)

// A unit that crashes soon after every start hits restart_limit after the
// burst even when its restart delay (2 s, 10 s) spreads the crashes far
// beyond the 30 s window; a run that stayed ready for the stable period
// resets the count. The clock is virtual.
func TestCrashLoopLimitIgnoresDelay(t *testing.T) {
	defer func(old func() time.Time) { clock = old }(clock)
	for _, delay := range []time.Duration{2 * time.Second, 10 * time.Second} {
		svc := newSvc("a", "simple", "exec", "always", true, time.Second, []string{"/bin/true"})
		sup := mustSup(t, map[string]*unit.Service{"a": svc})
		s, _ := sup.runtime("a")
		now := time.Unix(1800000000, 0)
		clock = func() time.Time { return now }
		allowed := 0
		for i := 0; i < 20; i++ {
			s.readyAt = now                       // started and ready
			now = now.Add(100 * time.Millisecond) // then crashed
			if !sup.allowRestart(s) {
				break
			}
			allowed++
			now = now.Add(delay)
		}
		if allowed != defaultBurst {
			t.Fatalf("delay %v: %d restarts before restart_limit, want %d", delay, allowed, defaultBurst)
		}
		s.crashes, s.restartsAt = 0, nil
		for i := 0; i < 3*defaultBurst; i++ {
			s.readyAt = now
			now = now.Add(11 * time.Second) // stayed up past the stable period
			if !sup.allowRestart(s) {
				t.Fatalf("delay %v: stable runs refused at %d", delay, i)
			}
			now = now.Add(delay)
		}
	}
}

// At the end of boot, an essential unit waiting out a restart delay after a
// crash is not ready.
func TestEssentialFailureBootBackoff(t *testing.T) {
	svc := newSvc("a", "simple", "exec", "always", true, time.Second, []string{"/bin/true"})
	svc.Essential = true
	sup := mustSup(t, map[string]*unit.Service{"a": svc})
	s, _ := sup.runtime("a")
	s.desired, s.state, s.backoff = true, "starting", true
	if got := sup.EssentialFailure(true); got != "a" {
		t.Fatalf("boot: %q", got)
	}
	if got := sup.EssentialFailure(false); got != "" {
		t.Fatalf("runtime: a restart in progress is transient, got %q", got)
	}
	s.backoff = false
	if got := sup.EssentialFailure(true); got != "" {
		t.Fatalf("starting without a crash: %q", got)
	}
}
