// SPDX-License-Identifier: GPL-3.0-or-later

package skills

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded copy is the file on disk, byte for byte, and it is the only
// file in the skill directory.
func TestEmbedMatchesDisk(t *testing.T) {
	want, err := os.ReadFile(Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Main(), want) {
		t.Fatal("embedded SKILL.md differs from the file on disk")
	}
	ents, err := os.ReadDir(filepath.Dir(Path))
	if err != nil || len(ents) != 1 || ents[0].Name() != "SKILL.md" {
		t.Fatalf("skill directory: %v %v", ents, err)
	}
	// Main returns a copy: a caller cannot change the embedded bytes.
	b := Main()
	b[0] ^= 0xff
	if !bytes.Equal(Main(), want) {
		t.Fatal("Main returned the embedded slice itself")
	}
}

// install.sh copies the skill, resolves a relative target against the
// caller's directory, overwrites only its own file, and refuses a symlink,
// a hard link, or a directory where the file goes.
func TestInstallScript(t *testing.T) {
	script, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(Path)
	if err != nil {
		t.Fatal(err)
	}
	run := func(dir string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), code
	}
	same := func(dir string) {
		t.Helper()
		got, err := os.ReadFile(filepath.Join(dir, "sahinit", "SKILL.md"))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("installed copy differs (%v)", err)
		}
	}
	cwd := t.TempDir()
	out, code := run(cwd, "rel")
	if code != 0 || out != "wrote "+filepath.Join(cwd, "rel", "sahinit", "SKILL.md")+"\n" {
		t.Fatalf("relative target: %d %q", code, out)
	}
	same(filepath.Join(cwd, "rel"))
	extra := filepath.Join(cwd, "rel", "sahinit", "mine.md")
	must(t, os.WriteFile(extra, []byte("mine\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(cwd, "rel", "sahinit", "SKILL.md"), []byte("old\n"), 0o600))
	if out, code := run(cwd, filepath.Join(cwd, "rel")); code != 0 {
		t.Fatalf("rerun: %d %q", code, out)
	}
	same(filepath.Join(cwd, "rel"))
	if b, err := os.ReadFile(extra); err != nil || string(b) != "mine\n" {
		t.Fatalf("another file changed: %q %v", b, err)
	}

	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "victim")
	must(t, os.WriteFile(victim, []byte("keep\n"), 0o600))
	cases := map[string]func(dest string){
		"symlinked target": func(dest string) { must(t, os.Symlink(elsewhere, dest)) },
		"symlinked sahinit": func(dest string) {
			must(t, os.Mkdir(dest, 0o700))
			must(t, os.Symlink(elsewhere, filepath.Join(dest, "sahinit")))
		},
		"symlinked file": func(dest string) {
			must(t, os.MkdirAll(filepath.Join(dest, "sahinit"), 0o700))
			must(t, os.Symlink(victim, filepath.Join(dest, "sahinit", "SKILL.md")))
		},
		"hard-linked file": func(dest string) {
			must(t, os.MkdirAll(filepath.Join(dest, "sahinit"), 0o700))
			must(t, os.Link(victim, filepath.Join(dest, "sahinit", "SKILL.md")))
		},
		"directory for the file": func(dest string) {
			must(t, os.MkdirAll(filepath.Join(dest, "sahinit", "SKILL.md"), 0o700))
		},
		"target is a file": func(dest string) { must(t, os.WriteFile(dest, []byte("x"), 0o600)) },
		"sahinit is a file": func(dest string) {
			must(t, os.Mkdir(dest, 0o700))
			must(t, os.WriteFile(filepath.Join(dest, "sahinit"), []byte("x"), 0o600))
		},
	}
	for name, setup := range cases {
		dir := t.TempDir()
		setup(filepath.Join(dir, "skills"))
		out, code := run(dir, "skills")
		if code != 1 || strings.Contains(out, "wrote ") {
			t.Errorf("%s: %d %q", name, code, out)
		}
		if b, err := os.ReadFile(victim); err != nil || string(b) != "keep\n" {
			t.Fatalf("%s: wrote through to %s: %q %v", name, victim, b, err)
		}
		if ents, err := os.ReadDir(elsewhere); err != nil || len(ents) != 1 {
			t.Fatalf("%s: wrote into the link target: %v %v", name, ents, err)
		}
	}
	if out, code := run(cwd, "a", "b"); code != 2 {
		t.Fatalf("two targets: %d %q", code, out)
	}
	if out, code := run(cwd, ""); code != 2 {
		t.Fatalf("empty target: %d %q", code, out)
	}
	for _, arg := range []string{"--", "-h", "--help", "-x"} {
		dir := t.TempDir()
		out, code := run(dir, arg)
		ents, err := os.ReadDir(dir)
		if code != 2 || !strings.Contains(out, "usage") || err != nil || len(ents) != 0 {
			t.Errorf("%q: %d %q, created %v %v", arg, code, out, ents, err)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
