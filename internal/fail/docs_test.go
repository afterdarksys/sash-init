// SPDX-License-Identifier: GPL-3.0-or-later

package fail

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/docscan"
)

// The reference documentation must not drift from the code: every token the
// source can emit must be in the catalog (catalog_table.go), codes.md must
// be the catalog's rendering, and every flag and subcommand a flag set
// defines must be listed in docs/reference/cli.md. The source is scanned as
// text, so a new token or flag fails these tests until it is catalogued or
// documented.

const repoRoot = "../.."

var update = flag.Bool("update", false, "rewrite the generated region of docs/reference/codes.md")

func readDoc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "docs", "reference", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCodesDocumented(t *testing.T) {
	tokens, err := docscan.Tokens(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	// A sanity floor, so a broken pattern cannot pass by finding nothing.
	for _, must := range []string{"failed", "unit_perm", "peer_supervised", "cgroup_stray", "sash_grant", "sash_file_perm", "restart_limit", "policy_refresh_stale", "usage"} {
		if _, ok := tokens[must]; !ok {
			t.Errorf("scanner did not find %s in the source", must)
		}
	}
	for _, tok := range docscan.SortedKeys(tokens) {
		if _, ok := Lookup(tok); !ok {
			t.Errorf("token %s (emitted in %s) is not in the catalog (internal/fail/catalog_table.go)", tok, tokens[tok])
		}
	}
}

const (
	beginCatalog = "<!-- BEGIN CATALOG: generated from internal/fail/catalog_table.go by go test ./internal/fail -run TestCodesDocGenerated -update; do not edit by hand -->\n"
	endCatalog   = "<!-- END CATALOG -->\n"
)

// renderCatalog is the generated region of codes.md: one table per group.
func renderCatalog() string {
	var b strings.Builder
	b.WriteString(beginCatalog)
	for _, g := range Groups() {
		b.WriteString("\n## " + g.Title + "\n\n")
		if g.Intro != "" {
			b.WriteString(g.Intro + "\n\n")
		}
		b.WriteString("| Code | Meaning | What to do |\n| --- | --- | --- |\n")
		for _, c := range g.Codes {
			b.WriteString("| `" + c.Code + "` | " + c.Meaning + " | " + c.Fix + " |\n")
		}
	}
	b.WriteString("\n" + endCatalog)
	return b.String()
}

func TestCodesDocGenerated(t *testing.T) {
	path := filepath.Join(repoRoot, "docs", "reference", "codes.md")
	doc := readDoc(t, "codes.md")
	start := strings.Index(doc, beginCatalog)
	end := strings.Index(doc, endCatalog)
	if start < 0 || end < start {
		t.Fatalf("codes.md has no generated catalog region (%q ... %q)", beginCatalog, endCatalog)
	}
	want := doc[:start] + renderCatalog() + doc[end+len(endCatalog):]
	if want == doc {
		return
	}
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("docs/reference/codes.md differs from the catalog; run go test ./internal/fail -run TestCodesDocGenerated -update")
}

var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestCatalogShape(t *testing.T) {
	all := Catalog()
	if len(all) < 200 {
		t.Fatalf("catalog has %d codes", len(all))
	}
	seen := map[string]bool{}
	for i, c := range all {
		if !codeRE.MatchString(c.Code) || seen[c.Code] {
			t.Errorf("code %q is malformed or repeated", c.Code)
		}
		seen[c.Code] = true
		if i > 0 && all[i-1].Code >= c.Code {
			t.Errorf("catalog not sorted at %q", c.Code)
		}
		for _, s := range []string{c.Meaning, c.Fix} {
			if len(s) < 6 || !(strings.HasSuffix(s, ".") || strings.HasSuffix(s, ".)")) || strings.Contains(s, "\n") || strings.Contains(s, " | ") {
				t.Errorf("%s: %q is not a table-safe sentence ending in a period", c.Code, s)
			}
		}
		m := Message(c.Code)
		if len(m) < 8 || !strings.HasSuffix(m, ".") || strings.Contains(m, "`") || strings.Contains(m[:len(m)-1], ". ") {
			t.Errorf("%s: message %q is not one sentence", c.Code, m)
		}
	}
	if Message("no_such_code") != Message("failed") {
		t.Fatal("an unknown code must read as failed")
	}
}

func TestCLIDocumented(t *testing.T) {
	doc := readDoc(t, "cli.md")
	flags, usage, err := docscan.CLI(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) < 20 || len(usage) < 7 {
		t.Fatalf("scanner found %d flags and %d usage lines; the patterns are broken", len(flags), len(usage))
	}
	for _, f := range docscan.SortedKeys(flags) {
		if !strings.Contains(doc, "`--"+f+"`") {
			t.Errorf("flag --%s (defined in %s) is not documented in docs/reference/cli.md", f, flags[f])
		}
	}
	for _, line := range docscan.SortedKeys(usage) {
		words := strings.Fields(line)
		if !strings.Contains(doc, "## sahinit "+words[0]) {
			t.Errorf("command %q (%s) has no section in docs/reference/cli.md", words[0], usage[line])
		}
		// Operations: the bare words after the command, split on |.
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "[") || strings.ToUpper(w) == w {
				continue
			}
			for _, op := range strings.Split(w, "|") {
				if !strings.Contains(doc, "`"+op+"`") && !strings.Contains(doc, " "+op+" ") {
					t.Errorf("operation %q of sahinit %s is not documented in docs/reference/cli.md", op, words[0])
				}
			}
		}
	}
}
