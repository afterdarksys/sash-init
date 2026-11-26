// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/afterdarksys/sahinit/internal/fail"
)

const codesUsage = "usage: sahinit codes [--json]\n"

// runCodes prints the catalog of every stable code (internal/fail), the
// same table docs/reference/codes.md is generated from.
func runCodes(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("codes", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usage(args, codesUsage, stdout, stderr)
	}
	codes := fail.PlainCatalog()
	if *asJSON {
		if !writeJSON(stdout, struct {
			V     int         `json:"v"`
			OK    bool        `json:"ok"`
			Codes []fail.Code `json:"codes"`
		}{jsonVersion, true, codes}) {
			return 1
		}
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "CODE\tMEANING\tFIX")
	for _, c := range codes {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Code, c.Meaning, c.Fix)
	}
	if err := tw.Flush(); err != nil {
		return 1
	}
	return 0
}
