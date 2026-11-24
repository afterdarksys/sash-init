// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/unit"
	"io"
)

func runValidate(args []string, out, stderr io.Writer) int {
	f := flag.NewFlagSet("validate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "", "")
	if err := f.Parse(args); err != nil || *dir == "" || f.NArg() != 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	svcs, refused, err := unit.Load(*dir)
	if err == nil && len(refused) > 0 {
		err = fail.E("catalog_refused")
	}
	var waves [][]string
	if err == nil {
		waves, err = graph.Plan(svcs)
	}
	if err := json.NewEncoder(out).Encode(struct {
		Valid   bool              `json:"valid"`
		Error   string            `json:"error"`
		Refused map[string]string `json:"refused"`
		Waves   [][]string        `json:"waves"`
	}{err == nil, fail.Token(err), refused, waves}); err != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}
