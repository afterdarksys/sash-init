// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"github.com/afterdarksys/sahinit/internal/unit"
	"testing"
	"time"
)

func TestWatchdogKillsUnresponsiveService(t *testing.T) {
	script := writeScript(t, "printf x >&3\n/bin/sleep 30\n")
	svc := newSvc("a", "simple", "notify", "no", true, time.Second, shExec(script))
	svc.Watchdog = 150 * time.Millisecond
	sup := mustSup(t, map[string]*unit.Service{"a": svc})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "a", 2*time.Second, func(r Row) bool { return r.State == "failed" })
	if row.LastError != "watchdog" {
		t.Fatalf("%+v", row)
	}
}
