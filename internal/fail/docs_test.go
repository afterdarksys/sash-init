// SPDX-License-Identifier: GPL-3.0-or-later

package fail

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The reference documentation must not drift from the code: every token the
// source can emit must be explained in docs/reference/codes.md, and every flag
// and subcommand a flag set defines must be listed in docs/reference/cli.md.
// The source is scanned as text, so a new token or flag fails this test until
// it is documented.

const repoRoot = "../.."

// tokenPatterns find tokens the source emits: errors, socket responses,
// status fields, helper statuses and log lines.
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`fail\.E\("([a-z][a-z0-9_]*)"\)`),
	regexp.MustCompile(`Fprintln\([^,()]+, "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`logf\("([a-z][a-z0-9_]*)[ "]`),
	regexp.MustCompile(`Error: "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`\bs\.lastError = "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`s\.state, s\.lastError = "[a-z]+", "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`writeStatus\("([a-z][a-z0-9_]*)"\)`),
	regexp.MustCompile(`refuse\("([a-z][a-z0-9_]*)"\)`),
	regexp.MustCompile(`sashFail\([^"]*"([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`return "([a-z]+(?:_[a-z0-9]+)+)"`),
	regexp.MustCompile(`eventLocked\("([a-z][a-z0-9_]*)",`),
}

// flagPattern finds flag definitions in a flag.FlagSet.
var flagPattern = regexp.MustCompile(`\.(?:String|Bool|Duration|Int|Uint|Uint64|Int64|Func|StringVar|BoolVar|DurationVar|IntVar)\((?:&[^,]+, )?"([a-z][a-z0-9-]*)"`)

// usagePattern finds usage lines in the CLI's usage text.
var usagePattern = regexp.MustCompile(`"usage: sahinit ([^"\\]+)`)

func sourceFiles(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range dirs {
		root := filepath.Join(repoRoot, dir)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no source files found")
	}
	return out
}

func readDoc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "docs", "reference", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sourceTokens maps each token to one file that emits it.
func sourceTokens(t *testing.T) map[string]string {
	t.Helper()
	tokens := map[string]string{}
	files := sourceFiles(t, "cmd", "internal")
	for _, p := range sortedKeys(files) {
		for _, re := range tokenPatterns {
			for _, m := range re.FindAllStringSubmatch(files[p], -1) {
				if _, ok := tokens[m[1]]; !ok {
					tokens[m[1]] = p
				}
			}
		}
	}
	return tokens
}

func TestCodesDocumented(t *testing.T) {
	doc := readDoc(t, "codes.md")
	tokens := sourceTokens(t)
	// A sanity floor, so a broken pattern cannot pass by finding nothing.
	for _, must := range []string{"failed", "unit_perm", "peer_supervised", "cgroup_stray", "sash_grant", "sash_file_perm", "restart_limit", "policy_refresh_stale"} {
		if _, ok := tokens[must]; !ok {
			t.Errorf("scanner did not find %s in the source", must)
		}
	}
	for _, tok := range sortedKeys(tokens) {
		if !strings.Contains(doc, "`"+tok+"`") {
			t.Errorf("token %s (emitted in %s) is not documented in docs/reference/codes.md", tok, tokens[tok])
		}
	}
}

func TestCLIDocumented(t *testing.T) {
	doc := readDoc(t, "cli.md")
	files := sourceFiles(t, "cmd/sahinit", "internal/hostinit")
	flags := map[string]string{}
	usage := map[string]string{}
	for _, p := range sortedKeys(files) {
		for _, m := range flagPattern.FindAllStringSubmatch(files[p], -1) {
			flags[m[1]] = p
		}
		for _, m := range usagePattern.FindAllStringSubmatch(files[p], -1) {
			usage[m[1]] = p
		}
	}
	if len(flags) < 20 || len(usage) < 7 {
		t.Fatalf("scanner found %d flags and %d usage lines; the patterns are broken", len(flags), len(usage))
	}
	for _, f := range sortedKeys(flags) {
		if !strings.Contains(doc, "`--"+f+"`") {
			t.Errorf("flag --%s (defined in %s) is not documented in docs/reference/cli.md", f, flags[f])
		}
	}
	for _, line := range sortedKeys(usage) {
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
