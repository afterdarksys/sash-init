// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// The --json convention (docs/design/agent-ux-1.md): exactly one JSON
// object and a newline on stdout, keys in struct order, "v" and "ok"
// first; on failure "code" and "message" follow. Exit codes are those of
// the non-JSON form, and the human stderr lines are unchanged.
//
// Threats: an object that leaks what the text form never printed. Every
// object is a fixed struct of names, codes, states and counts: no
// environment value, grant body, key or file content has a field, and
// control bytes in a string are escaped by the encoder, so service output
// in a log line cannot carry terminal escapes onto stdout.

// jsonVersion is "v" of every object. Adding a field keeps it; renaming or
// removing one changes it.
const jsonVersion = 1

// failure is the object of a failed --json command with no other detail.
type failure struct {
	V       int    `json:"v"`
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeJSON writes v as one line. It reports whether the write worked.
func writeJSON(w io.Writer, v any) bool {
	raw, err := json.Marshal(v)
	if err != nil {
		return false
	}
	_, err = w.Write(append(raw, '\n'))
	return err == nil
}

// jsonFail writes the failure object for code, with its catalog message.
func jsonFail(w io.Writer, code string) {
	writeJSON(w, failure{V: jsonVersion, Code: code, Message: fail.Message(code)})
}

// wantsJSON reports whether args ask for --json, for a command line that
// did not parse: a usage error is then also an object (code usage).
func wantsJSON(args []string) bool {
	for _, a := range args {
		switch a {
		case "--json", "-json", "--json=true", "-json=true":
			return true
		}
	}
	return false
}

// usage prints text on stderr, as without --json, and with --json the
// usage object on stdout. It returns the usage exit status, 2.
func usage(args []string, text string, stdout, stderr io.Writer) int {
	fmt.Fprint(stderr, text)
	if wantsJSON(args) {
		jsonFail(stdout, "usage")
	}
	return 2
}
