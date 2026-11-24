// SPDX-License-Identifier: GPL-3.0-or-later

package hostinit

import (
	"strings"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	c, err := Parse(nil)
	if err != nil || c.Units != "/etc/sahinit/units" || c.Recovery != "" || c.ShutdownTimeout != 30*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
	for _, args := range [][]string{{"--dir", "relative"}, {"--socket", "sock"}, {"--recovery", "sh"}, {"--shutdown-timeout", "0s"}, {"--shutdown-timeout", "24h"}, {"unexpected"}, {"--unknown"}, {"--sash", "sash"}, {"--sash-fleet-pub", "fleet.pub"}, {"--sash-floor-dir", "floors"}} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestSuperviseArgs(t *testing.T) {
	c, _ := Parse(nil)
	if got := strings.Join(c.SuperviseArgs(), " "); got != "supervise --dir /etc/sahinit/units --socket /run/sahinit/control.sock --boot-strict" {
		t.Fatalf("default %q", got)
	}
	c, err := Parse([]string{"--sash", "/sash", "--sash-fleet-pub", "/etc/fleet.pub", "--sash-floor-dir", "/var/lib/floors"})
	if got := strings.Join(c.SuperviseArgs(), " "); err != nil || !strings.HasSuffix(got, "--boot-strict --sash /sash --sash-fleet-pub /etc/fleet.pub --sash-floor-dir /var/lib/floors") {
		t.Fatalf("sash %q %v", got, err)
	}
}

func TestRefuseOrdinaryProcess(t *testing.T) {
	if err := Run(nil); err == nil {
		t.Fatal("ordinary process accepted as host init")
	}
}
