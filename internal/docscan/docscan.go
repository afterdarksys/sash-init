// SPDX-License-Identifier: GPL-3.0-or-later

// Package docscan finds, by scanning the Go source as text, the codes the
// source can emit and the flags and usage lines the CLI defines. The docs
// drift tests (internal/fail) and the skill's honesty test (cmd/sahinit)
// use it; nothing at run time does.
package docscan

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// TokenPatterns find tokens the source emits: errors, socket responses,
// status fields, helper statuses, log lines and JSON failure objects.
var TokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`fail\.E\("([a-z][a-z0-9_]*)"\)`),
	regexp.MustCompile(`Fprintln\([^,()]+, "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`logf\("([a-z][a-z0-9_]*)[ "]`),
	regexp.MustCompile(`Error: "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`\bs\.lastError = "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`s\.state, s\.lastError = "[a-z]+", "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`writeStatus\("([a-z][a-z0-9_]*)"\)`),
	regexp.MustCompile(`refuse\("([a-z][a-z0-9_]*)"\)`),
	// One call, on one line: across lines it matched string literals in
	// the function's body.
	regexp.MustCompile(`sashFail\([^"\n]*"([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`return "([a-z]+(?:_[a-z0-9]+)+)"`),
	regexp.MustCompile(`eventLocked\("([a-z][a-z0-9_]*)",`),
	regexp.MustCompile(`jsonFail\([^,()]+, "([a-z][a-z0-9_]*)"`),
}

// FlagPattern finds flag definitions in a flag.FlagSet.
var FlagPattern = regexp.MustCompile(`\.(?:String|Bool|Duration|Int|Uint|Uint64|Int64|Func|StringVar|BoolVar|DurationVar|IntVar)\((?:&[^,]+, )?"([a-z][a-z0-9-]*)"`)

// UsagePattern finds usage lines in the CLI's usage text.
var UsagePattern = regexp.MustCompile(`"usage: sahinit ([^"\\]+)`)

// SourceFiles reads every non-test .go file below each dir of root.
func SourceFiles(root string, dirs ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[p] = string(raw)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no source files found")
	}
	return out, nil
}

// SortedKeys returns m's keys in order.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Matches maps each first submatch of any pattern to one file holding it.
func Matches(files map[string]string, patterns ...*regexp.Regexp) map[string]string {
	found := map[string]string{}
	for _, p := range SortedKeys(files) {
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(files[p], -1) {
				if _, ok := found[m[1]]; !ok {
					found[m[1]] = p
				}
			}
		}
	}
	return found
}

// Tokens maps each code the source below root emits to one file emitting it.
func Tokens(root string) (map[string]string, error) {
	files, err := SourceFiles(root, "cmd", "internal")
	if err != nil {
		return nil, err
	}
	return Matches(files, TokenPatterns...), nil
}

// CLI returns the flags and usage lines the CLI defines, each mapped to a
// file defining it.
func CLI(root string) (flags, usage map[string]string, err error) {
	files, err := SourceFiles(root, "cmd/sahinit", "internal/hostinit")
	if err != nil {
		return nil, nil, err
	}
	return Matches(files, FlagPattern), Matches(files, UsagePattern), nil
}
