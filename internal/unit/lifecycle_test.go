// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestLifecyclePolicy(t *testing.T) {
	base := `{"name":"a","exec":["/bin/true"],"type":"simple","ready":"exec"`
	s := mustParse(t, base+`,"essential":true,"restart_delay":"200ms","restart_max_delay":"10s"}`, "a")
	if !s.Essential || s.RestartDelay.Milliseconds() != 200 {
		t.Fatalf("%+v", s)
	}
	for _, extra := range []string{`,"essential":true,"boot":false`, `,"essential":"yes"`, `,"restart_delay":"0s"`, `,"restart_delay":"1m","restart_max_delay":"1s"`} {
		if _, err := Parse([]byte(base+extra+`}`), "a"); err == nil {
			t.Fatal(extra)
		}
	}
}

// A boot unit is essential unless it opts out with "essential": false, so a
// strict boot fails closed; a unit outside the boot set is never essential.
func TestEssentialDefault(t *testing.T) {
	base := `{"name":"a","exec":["/bin/true"],"type":"simple","ready":"exec"`
	for extra, want := range map[string]bool{`,"boot":true`: true, `,"boot":true,"essential":false`: false, `,"boot":true,"essential":true`: true, `,"boot":false`: false} {
		if s := mustParse(t, base+extra+`}`, "a"); s.Essential != want {
			t.Fatalf("%s: essential %v", extra, s.Essential)
		}
	}
}

// watchdog needs notify readiness: nothing else writes heartbeats.
func TestWatchdogNeedsNotify(t *testing.T) {
	base := `{"name":"a","exec":["/bin/true"],"type":"simple","watchdog":"1s"`
	if s := mustParse(t, base+`,"ready":"notify"}`, "a"); s.Watchdog != time.Second {
		t.Fatalf("%+v", s)
	}
	if _, err := Parse([]byte(base+`,"ready":"exec"}`), "a"); fail.Token(err) != "watchdog_invalid" {
		t.Fatalf("exec readiness: %v", err)
	}
}
