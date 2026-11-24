// SPDX-License-Identifier: GPL-3.0-or-later

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
	// LogDir, when set, is passed as the supervisor's --log-dir. Empty
	// (the default) means no journal: output stays in the in-memory tails
	// and on the console.
	LogDir string
	// DeploymentRoot and Trust select a verified deployment catalog
	// instead of --dir; TrustClock accepts the system clock as the initial
	// time anchor.
	DeploymentRoot, Trust string
	TrustClock            bool
	// Sash settings passed to the supervisor when set (supervise's --sash,
	// --sash-fleet-pub and --sash-floor-dir); without them sash units are
	// refused at load, which strict boot treats as a failed boot.
	Sash, SashFleetPub, SashFloorDir string
}

// SuperviseArgs is the supervisor's command line for c.
func (c Config) SuperviseArgs() []string {
	args := []string{"supervise", "--dir", c.Units, "--socket", c.Socket, "--boot-strict"}
	if c.DeploymentRoot != "" {
		args = []string{"supervise", "--deployment-root", c.DeploymentRoot, "--trust", c.Trust, "--socket", c.Socket, "--boot-strict"}
		if c.TrustClock {
			args = append(args, "--trust-system-clock")
		}
	}
	for _, f := range []struct{ name, value string }{{"--log-dir", c.LogDir}, {"--sash", c.Sash}, {"--sash-fleet-pub", c.SashFleetPub}, {"--sash-floor-dir", c.SashFloorDir}} {
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
	f.StringVar(&c.LogDir, "log-dir", "", "")
	f.StringVar(&c.DeploymentRoot, "deployment-root", "", "")
	f.StringVar(&c.Trust, "trust", "", "")
	f.BoolVar(&c.TrustClock, "trust-system-clock", false, "")
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
	for _, p := range []string{c.Sash, c.SashFleetPub, c.SashFloorDir, c.LogDir} {
		if p != "" && !filepath.IsAbs(p) {
			return c, fmt.Errorf("invalid init configuration")
		}
	}
	if (c.DeploymentRoot != "" && (!filepath.IsAbs(c.DeploymentRoot) || !filepath.IsAbs(c.Trust))) || (c.DeploymentRoot == "" && (c.Trust != "" || c.TrustClock)) {
		return c, fmt.Errorf("invalid init configuration")
	}
	return c, nil
}
