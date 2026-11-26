// SPDX-License-Identifier: GPL-3.0-or-later

// Package fail is the closed error vocabulary for sahinit.
// Error text is the token and nothing else, so a caller cannot leak a path,
// a request id, or an OS error string onto the control socket.
package fail

import (
	"errors"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Error is a stable machine token.
type Error struct {
	Token string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Token
}

func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other != nil && e.Token == other.Token
}

// E returns a token error. The same token always compares equal.
func E(token string) error {
	Note(token)
	return &Error{Token: token}
}

var (
	recording atomic.Bool
	seen      sync.Map
)

// Note records code when a test has called Record, so that codes built at
// run time can be checked against the catalog; otherwise it does nothing.
// A code passed from a _test.go file is the test's own and is skipped.
func Note(code string) {
	if code == "" || !recording.Load() {
		return
	}
	pcs := make([]uintptr, 8)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if !strings.HasSuffix(f.File, "/internal/fail/fail.go") {
			if strings.HasSuffix(f.File, "_test.go") {
				return
			}
			break
		}
		if !more {
			break
		}
	}
	seen.Store(code, struct{}{})
}

// Record starts recording every code passed to E or Note (tests only).
func Record() { recording.Store(true) }

// wireOnly are error strings of another protocol's contract, not sahinit
// codes: "frame body" is the sash verb wire's answer to a malformed frame
// (internal/sash/frame.go), sent to sash and never shown as a code.
var wireOnly = map[string]bool{"frame body": true}

// Uncatalogued returns, sorted, every recorded code not in the catalog.
func Uncatalogued() []string {
	var out []string
	for _, c := range Recorded() {
		if _, ok := Lookup(c); !ok && !wireOnly[c] {
			out = append(out, c)
		}
	}
	return out
}

// Recorded returns, sorted, every code recorded since Record.
func Recorded() []string {
	var out []string
	seen.Range(func(k, _ any) bool {
		out = append(out, k.(string))
		return true
	})
	sort.Strings(out)
	return out
}

// Token returns the stable token. Errors that are not tokens become "failed"
// so raw OS text never crosses the socket.
func Token(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) && e.Token != "" {
		return e.Token
	}
	return "failed"
}
