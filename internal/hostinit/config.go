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
}

func Parse(args []string) (Config, error) {
	c := Config{}
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.Units, "dir", "/etc/sahinit/units", "")
	f.StringVar(&c.Socket, "socket", "/run/sahinit/control.sock", "")
	f.StringVar(&c.Recovery, "recovery", "", "absolute local console recovery executable; disabled by default")
	f.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", 30*time.Second, "")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 || !filepath.IsAbs(c.Units) || !filepath.IsAbs(c.Socket) ||
		(c.Recovery != "" && !filepath.IsAbs(c.Recovery)) || c.ShutdownTimeout < time.Second || c.ShutdownTimeout > 10*time.Minute {
		return c, fmt.Errorf("invalid init configuration")
	}
	return c, nil
}
