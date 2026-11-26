// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/docscan"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"github.com/afterdarksys/sahinit/skills"
)

// --skill prints the embedded skill and nothing else; with anything after
// it, or after another command, it is a usage error that prints nothing on
// stdout.
func TestSkillCommand(t *testing.T) {
	wantRun(t, []string{"--skill"}, 0, string(skills.Main()), "")
	wantRun(t, []string{"--skill", "--json"}, 2, usageJSON(skillUsage), skillUsage)
	for _, args := range [][]string{
		{"--skill", "x"}, {"--skill", "--skill"}, {"--skill", ""}, {"--skill", "/etc/passwd"},
		{"--skill", "plan", "--dir", "/tmp"}, {"--skill", "ctl", "--socket", "/tmp/s", "stop", "web"},
	} {
		wantRun(t, args, 2, "", skillUsage)
	}
	for _, args := range [][]string{{"plan", "--skill"}, {"codes", "--skill"}, {"version", "--skill"}, {"ctl", "--skill", "--socket", "/tmp/s", "status"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "usage:") {
			t.Errorf("%q: %d %q %q", args, code, out.String(), errb.String())
		}
	}
}

// The built binary prints the embedded copy, whatever is in its working
// directory.
func TestBinarySkill(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "sahinit")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(cwd, "skills", "sahinit"), 0o700))
	must(os.WriteFile(filepath.Join(cwd, "skills", "sahinit", "SKILL.md"), []byte("DECOY\n"), 0o600))
	must(os.WriteFile(filepath.Join(cwd, "SKILL.md"), []byte("DECOY\n"), 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--skill")
	cmd.Dir = cwd
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil || !bytes.Equal(out.Bytes(), skills.Main()) || errb.Len() != 0 {
		t.Fatalf("%v %q", err, errb.String())
	}
}

var backtick = regexp.MustCompile("`([^`\n]+)`")

// jsonKeys are the field names of every documented --json shape.
func jsonKeys() map[string]bool {
	keys := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
				keys[name] = true
			}
			walk(f.Type)
		}
	}
	for _, v := range []any{catalogResult{}, ctlResult{}, logsResult{}, logRecord{}, eventRecord{}, versionInfo{}, failure{}, fail.Code{}} {
		walk(reflect.TypeOf(v))
	}
	return keys
}

// skillVocabulary is every bare word the skill may put in backticks: a
// catalog code, a unit field, a command or operation, a JSON key, a
// grantable capability or a feature.
func skillVocabulary(t *testing.T) (map[string]bool, map[string]string) {
	t.Helper()
	flags, usageLines, err := docscan.CLI(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	// JSON literals and the binary's own name.
	words := map[string]bool{"true": true, "false": true, "sahinit": true}
	for _, c := range fail.Catalog() {
		words[c.Code] = true
	}
	for _, f := range unit.Fields() {
		words[f] = true
		_, bare, _ := strings.Cut(f, ".")
		words[bare] = true
	}
	for line := range usageLines {
		for _, w := range strings.Fields(line) {
			for _, op := range strings.Split(w, "|") {
				if !strings.HasPrefix(op, "-") && !strings.HasPrefix(op, "[") && strings.ToUpper(op) != op {
					words[op] = true
				}
			}
		}
	}
	for _, op := range ctlOps {
		words[op] = true
	}
	for k := range jsonKeys() {
		words[k] = true
	}
	for _, c := range unit.GrantableCaps() {
		words[c] = true
	}
	for _, f := range features() {
		words[f] = true
	}
	return words, flags
}

const repoRoot = "../.."

// commands are the first words a span may run as an example.
var commands = map[string]bool{"plan": true, "validate": true, "ctl": true, "logs": true, "events": true, "codes": true, "version": true}

// readOnlyCommands and readOnlyCtl are the commands and ctl operations that
// change nothing: ctlJSONOps plus diagnostics.
var readOnlyCommands = map[string]bool{"plan": true, "validate": true, "logs": true, "events": true, "codes": true, "version": true}

func readOnlyExample(line string) bool {
	f := strings.Fields(line)[1:]
	if f[0] != "ctl" {
		return readOnlyCommands[f[0]] && !contains(f, "--follow")
	}
	for _, w := range f[1:] {
		if contains(ctlOps, w) {
			return contains(ctlJSONOps, w) || w == "diagnostics"
		}
	}
	return false
}

// placeholders makes a prose span runnable: S, D and DIR become absolute
// paths, NAME a unit name, and a journal or catalog command without --dir
// gets one.
func placeholders(f []string) string {
	out := []string{}
	for _, w := range f {
		switch w {
		case "S", "D", "DIR":
			w = "/placeholder"
		case "NAME":
			w = "web"
		}
		out = append(out, w)
	}
	if (f[0] == "logs" || f[0] == "events" || f[0] == "plan" || f[0] == "validate") && !contains(f, "--dir") {
		out = append(out, "--dir", "/placeholder")
	}
	return strings.Join(out, " ")
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)

// The honesty test: every flag, code, unit field, command and JSON key the
// skill names in backticks exists, and every example command (each line of
// a sh block) parses. A skill that
// mentions something the binary does not have fails here.
func TestSkillIsHonest(t *testing.T) {
	text := string(skills.Main())
	words, flags := skillVocabulary(t)
	checkWord := func(where, w string) {
		t.Helper()
		switch {
		case strings.HasPrefix(w, "--"):
			name, _, _ := strings.Cut(strings.TrimPrefix(w, "--"), "=")
			if _, ok := flags[name]; !ok && w != "--skill" {
				t.Errorf("%s: flag %s is not defined by any command", where, w)
			}
		case identifier.MatchString(w):
			if !words[w] {
				t.Errorf("%s: %q is not a code, unit field, command, operation, JSON key, cap or feature", where, w)
			}
		}
	}
	spans := 0
	for _, m := range backtick.FindAllStringSubmatch(text, -1) {
		span := m[1]
		spans++
		for _, w := range strings.Fields(span) {
			checkWord("`"+span+"`", w)
		}
		// A command with flags is run, so a flag borrowed from another
		// command is a usage error here.
		if f := strings.Fields(span); len(f) > 1 && commands[f[0]] && strings.Contains(span, "--") {
			checkExample(t, "sahinit "+placeholders(f))
		}
	}
	examples := 0
	inBlock := false
	mark := ""
	for _, line := range strings.Split(text, "\n") {
		switch {
		case line == "<!-- read-only -->" || line == "<!-- changes-state -->":
			mark = line
		case line == "```sh":
			inBlock = true
			if mark == "" {
				t.Errorf("a sh block is not marked read-only or changes-state")
			}
		case line == "```":
			inBlock, mark = false, ""
		case inBlock:
			if !strings.HasPrefix(line, "sahinit ") {
				t.Errorf("example %q does not start with sahinit", line)
				continue
			}
			examples++
			checkExample(t, line)
			// The split is checked against the operation table: an
			// example in the read-only block must be read-only, and one in
			// the changes-state block must not be.
			if ro := readOnlyExample(line); ro != (mark == "<!-- read-only -->") {
				t.Errorf("example %q is under %s but read-only is %v", line, mark, ro)
			}
		}
	}
	// A floor, so a broken extractor cannot pass by finding nothing.
	if spans < 80 || examples < 15 {
		t.Fatalf("found %d backticked spans and %d examples", spans, examples)
	}
}

// checkExample runs an example command line with every absolute path moved
// under a fresh temporary directory, where nothing exists: it must not be a
// usage error or an unknown operation, and with --json it must print one
// v1 object. Nothing real is read, connected to or changed.
func checkExample(t *testing.T, line string) {
	t.Helper()
	tmp := t.TempDir()
	args := strings.Fields(line)[1:]
	for i, a := range args {
		if strings.HasPrefix(a, "/") {
			args[i] = filepath.Join(tmp, "absent", a)
		}
		if a == "|" || a == ">" || a == ";" || a == "&&" {
			t.Errorf("example %q is not a single command", line)
			return
		}
	}
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	if (code == 2 && strings.Contains(errb.String(), "usage:")) || strings.Contains(errb.String(), "unknown_op") {
		t.Errorf("example %q does not parse: %d %q", line, code, errb.String())
		return
	}
	if wantsJSON(args) {
		var obj struct {
			V    int    `json:"v"`
			Code string `json:"code"`
		}
		if bytes.Count(out.Bytes(), []byte("\n")) != 1 || json.Unmarshal(out.Bytes(), &obj) != nil || obj.V != 1 || obj.Code == "usage" {
			t.Errorf("example %q: not one v1 object: %q", line, out.String())
		}
	}
}
