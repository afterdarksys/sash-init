package hostinit

import (
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	c, err := Parse(nil)
	if err != nil || c.Units != "/etc/sahinit/units" || c.Recovery != "" || c.ShutdownTimeout != 30*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
	for _, args := range [][]string{{"--dir", "relative"}, {"--socket", "sock"}, {"--recovery", "sh"}, {"--shutdown-timeout", "0s"}, {"--shutdown-timeout", "24h"}, {"unexpected"}, {"--unknown"}} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestRefuseOrdinaryProcess(t *testing.T) {
	if err := Run(nil); err == nil {
		t.Fatal("ordinary process accepted as host init")
	}
}
