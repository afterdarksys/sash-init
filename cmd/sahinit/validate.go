// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"io"
	"sort"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func runValidate(args []string, out, stderr io.Writer) int {
	f := flag.NewFlagSet("validate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "", "")
	asJSON := f.Bool("json", false, "")
	if err := f.Parse(args); err != nil || *dir == "" || f.NArg() != 0 {
		return usage(args, usageText, out, stderr)
	}
	svcs, refused, err := unit.Load(*dir)
	if err == nil && len(refused) > 0 {
		err = fail.E("catalog_refused")
	}
	var waves [][]string
	if err == nil {
		waves, err = graph.Plan(svcs)
	}
	if *asJSON {
		if !writeJSON(out, catalogJSON(err, waves, refused, svcs)) {
			return 1
		}
	} else if err := json.NewEncoder(out).Encode(struct {
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

// refusedFile is a unit file the loader left out, and why.
type refusedFile struct {
	File string `json:"file"`
	Code string `json:"code"`
}

// catalogResult is the --json object of plan and validate.
type catalogResult struct {
	V             int           `json:"v"`
	OK            bool          `json:"ok"`
	Code          string        `json:"code,omitempty"`
	Message       string        `json:"message,omitempty"`
	Waves         [][]string    `json:"waves"`
	Refused       []refusedFile `json:"refused"`
	CgroupTrusted []string      `json:"cgroup_trusted"`
}

// catalogJSON is the object for a load and plan that ended with err: the
// waves (none on failure), every refused file sorted, and the units that
// are cgroup-trusted. It holds names and codes only, never a unit's
// contents.
func catalogJSON(err error, waves [][]string, refused map[string]string, svcs map[string]*unit.Service) catalogResult {
	r := catalogResult{V: jsonVersion, OK: err == nil, Waves: [][]string{}, Refused: []refusedFile{}, CgroupTrusted: trustedFiles(svcs)}
	if err != nil {
		r.Code = fail.Token(err)
		r.Message = fail.Message(r.Code)
	} else if waves != nil {
		r.Waves = waves
	}
	for file, code := range refused {
		r.Refused = append(r.Refused, refusedFile{file, code})
	}
	sort.Slice(r.Refused, func(i, j int) bool { return r.Refused[i].File < r.Refused[j].File })
	return r
}
