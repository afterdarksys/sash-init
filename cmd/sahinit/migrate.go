// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/afterdarksys/sahinit/internal/migrate"
)

func runMigrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("from", "", "systemd, daemontools, or openrc")
	source := fs.String("source", "", "standalone source catalog directory")
	out := fs.String("out", "", "new output directory; omitted means report only")
	boot := fs.Bool("boot", false, "start converted services on boot (daemontools down overrides this)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *format == "" || *source == "" {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	report, err := migrate.Scan(*format, *source, *boot)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	code := 0
	if report.Blocked() {
		code = 1
	} else if *out != "" {
		if err := report.Write(*out); err != nil {
			fmt.Fprintln(stderr, err)
			code = 2
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return code
}
