// SPDX-License-Identifier: GPL-3.0-or-later

// Package skills holds the usage guide for AI agents (sahinit/SKILL.md
// beside this file), embedded so the binary can print it with
// sahinit --skill. It sits here, and not under internal, because go:embed
// reads only the package's own directory and below.
//
// Threats: a file read from the working directory instead of the binary.
// There is one file and no name to choose: every byte comes from the
// embedded copy, and nothing here opens a host path, runs anything or
// grants anything.
package skills

import _ "embed"

//go:embed sahinit/SKILL.md
var skill []byte

// Path is the skill's path relative to this directory.
const Path = "sahinit/SKILL.md"

// Main returns SKILL.md.
func Main() []byte {
	return append([]byte(nil), skill...)
}
