// SPDX-License-Identifier: GPL-3.0-or-later

package main

// sahinit --skill prints the usage guide for AI agents, embedded in the
// binary (package skills), so it can be installed with
// sahinit --skill > ~/.claude/skills/sahinit/SKILL.md.
//
// Threats: a print command that turns into something else. --skill is
// recognised only as the whole command line: anything after it is a usage
// error before anything is read, and anywhere else it is an unknown flag
// of that command. It reads nothing from disk or the working directory,
// opens no socket, and writes only to stdout.

import (
	"fmt"
	"io"

	"github.com/afterdarksys/sahinit/skills"
)

const skillUsage = "usage: sahinit --skill\n"

// runSkill prints SKILL.md; rest is what followed --skill and must be empty.
func runSkill(rest []string, stdout, stderr io.Writer) int {
	if len(rest) != 0 {
		return usage(rest, skillUsage, stdout, stderr)
	}
	if _, err := stdout.Write(skills.Main()); err != nil {
		fmt.Fprintln(stderr, "failed")
		return 1
	}
	return 0
}
