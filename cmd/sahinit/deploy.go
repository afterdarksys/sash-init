// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/deploy"
	"github.com/afterdarksys/sahinit/internal/fail"
)

const deployUsage = "usage: sahinit deploy stage|status|bootstrap --root DIR --trust FILE [--trust-system-clock] [--bundle DIR --manifest FILE --document FILE]"

func deployment(root, trustPath string, trustClock bool) (*deploy.Manager, error) {
	raw, err := policyFile(trustPath, 64*1024, true)
	if err != nil {
		return nil, err
	}
	trust, err := bootpolicy.DecodeTrust(raw)
	if err != nil {
		return nil, err
	}
	var clock bootpolicy.Clock = bootpolicy.ClockFunc(func() (time.Time, bool) { return time.Time{}, false })
	if trustClock {
		clock = bootpolicy.NewClock(time.Now())
	}
	return deploy.Open(root, trust, clock)
}
func runDeploy(args []string, out, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "stage" && args[0] != "status" && args[0] != "bootstrap") {
		fmt.Fprintln(stderr, deployUsage)
		return 2
	}
	f := flag.NewFlagSet("deploy", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "", "")
	trust := f.String("trust", "", "")
	clock := f.Bool("trust-system-clock", false, "")
	bundle := f.String("bundle", "", "")
	manifest := f.String("manifest", "", "")
	document := f.String("document", "", "")
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 || *root == "" || *trust == "" {
		fmt.Fprintln(stderr, deployUsage)
		return 2
	}
	stage := *bundle != "" && *manifest != "" && *document != ""
	none := *bundle == "" && *manifest == "" && *document == ""
	if (args[0] == "stage" && !stage) || (args[0] != "stage" && !none) {
		fmt.Fprintln(stderr, deployUsage)
		return 2
	}
	m, err := deployment(*root, *trust, *clock)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 1
	}
	switch args[0] {
	case "stage":
		raw, err := deploy.ReadFile(*manifest, 256*1024)
		if err != nil {
			fmt.Fprintln(stderr, "manifest_read")
			return 1
		}
		doc, err := policyFile(*document, bootpolicy.MaxEnvelope, false)
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
		c, err := m.Stage(doc, raw, *bundle)
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
		if err := json.NewEncoder(out).Encode(map[string]string{"pending": c.ID}); err != nil {
			return 1
		}
	case "status":
		state, err := m.State()
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
		if err := json.NewEncoder(out).Encode(state); err != nil {
			return 1
		}
	case "bootstrap":
		// First offline installation only. Subsequent changes use ctl activate
		// so runtime state and the durable active pointer are coordinated.
		lock, err := m.Lock()
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
		defer lock.Close()
		state, err := m.State()
		if err != nil || state.Active != "" || state.Pending == "" {
			fmt.Fprintln(stderr, "bootstrap_refused")
			return 1
		}
		c, err := m.Load(state.Pending)
		if err == nil {
			err = c.Document.CheckFresh(m.Clock)
		}
		if err == nil {
			for name := range c.Units {
				if err = m.Admit(c, name, false); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = m.CommitActive(c.ID)
		}
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
		if err := json.NewEncoder(out).Encode(map[string]string{"active": c.ID}); err != nil {
			return 1
		}
	}
	return 0
}
