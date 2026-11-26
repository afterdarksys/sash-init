// SPDX-License-Identifier: GPL-3.0-or-later

package fail

import (
	"sort"
	"strings"
)

// Code is one catalog entry: the stable code, what it means and what to do.
type Code struct {
	Code    string `json:"code"`
	Meaning string `json:"meaning"`
	Fix     string `json:"fix"`
}

// Group is a titled section of the catalog, as codes.md shows it.
type Group struct {
	Title string
	Intro string
	Codes []Code
}

// Groups returns the catalog in its document order.
func Groups() []Group {
	out := make([]Group, len(groups))
	for i, g := range groups {
		out[i] = Group{Title: g.Title, Intro: g.Intro, Codes: append([]Code(nil), g.Codes...)}
	}
	return out
}

// Catalog returns every entry, sorted by code.
func Catalog() []Code {
	var out []Code
	for _, g := range groups {
		out = append(out, g.Codes...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Lookup returns the entry for code.
func Lookup(code string) (Code, bool) {
	for _, g := range groups {
		for _, c := range g.Codes {
			if c.Code == code {
				return c, true
			}
		}
	}
	return Code{}, false
}

// Message is one human sentence for code: the first sentence of its
// meaning, without markdown backticks. An unknown code is "failed"'s.
func Message(code string) string {
	c, ok := Lookup(code)
	if !ok {
		c, _ = Lookup("failed")
	}
	m := strings.ReplaceAll(c.Meaning, "`", "")
	for i := 0; i+1 < len(m); i++ {
		if m[i] == '.' && m[i+1] == ' ' && !strings.HasSuffix(m[:i], "e.g") && !strings.HasSuffix(m[:i], "i.e") {
			return m[:i+1]
		}
	}
	return m
}
