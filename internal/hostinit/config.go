// Package hostinit implements the small Linux PID 1 parent. The service
// supervisor runs in a separate process so its exec.Cmd waits cannot race
// with PID 1's collection of adopted orphans.
package hostinit

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

type Config struct {
	Units, Socket, Recovery string
	ShutdownTimeout         time.Duration
	// Sash settings passed to the supervisor when set (supervise's --sash,
	// --sash-fleet-pub and --sash-floor-dir); without them sash units are
	// refused at load, which strict boot treats as a failed boot.
	Sash, SashFleetPub, SashFloorDir string
}

// SuperviseArgs is the supervisor's command line for c.
func (c Config) SuperviseArgs() []string {
	args := []string{"supervise", "--dir", c.Units, "--socket", c.Socket, "--boot-strict"}
	for _, f := range []struct{ name, value string }{{"--sash", c.Sash}, {"--sash-fleet-pub", c.SashFleetPub}, {"--sash-floor-dir", c.SashFloorDir}} {
		if f.value != "" {
			args = append(args, f.name, f.value)
		}
	}
	return args
}

func Parse(args []string) (Config, error) {
	c := Config{}
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.Units, "dir", "/etc/sahinit/units", "")
	f.StringVar(&c.Socket, "socket", "/run/sahinit/control.sock", "")
	f.StringVar(&c.Recovery, "recovery", "", "absolute local console recovery executable; disabled by default")
	f.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", 30*time.Second, "")
	f.StringVar(&c.Sash, "sash", "", "")
	f.StringVar(&c.SashFleetPub, "sash-fleet-pub", "", "")
	f.StringVar(&c.SashFloorDir, "sash-floor-dir", "", "")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 || !filepath.IsAbs(c.Units) || !filepath.IsAbs(c.Socket) ||
		(c.Recovery != "" && !filepath.IsAbs(c.Recovery)) || c.ShutdownTimeout < time.Second || c.ShutdownTimeout > 10*time.Minute {
		return c, fmt.Errorf("invalid init configuration")
	}
	for _, p := range []string{c.Sash, c.SashFleetPub, c.SashFloorDir} {
		if p != "" && !filepath.IsAbs(p) {
			return c, fmt.Errorf("invalid init configuration")
		}
	}
	return c, nil
}
