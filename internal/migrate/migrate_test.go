// SPDX-License-Identifier: GPL-3.0-or-later

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/unit"
)

func put(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureCatalogs(t *testing.T) {
	for _, format := range []string{"systemd", "daemontools", "openrc"} {
		t.Run(format, func(t *testing.T) {
			r, err := Scan(format, filepath.Join("../../tests/migration/fixtures", format), true)
			if err != nil {
				t.Fatal(err)
			}
			if r.Blocked() || len(r.Units) != 1 {
				t.Fatalf("%+v", r)
			}
			u := r.Units[0]
			if u.Name != "demo" || !u.Boot || strings.Join(u.Exec, " ") != "/bin/sleep 300" {
				t.Fatalf("%+v", u)
			}
			out := filepath.Join(t.TempDir(), "units")
			if err := r.Write(out); err != nil {
				t.Fatal(err)
			}
			catalog, _, err := unit.Load(out)
			if err != nil || len(catalog) != 1 {
				t.Fatalf("catalog: %v %v", catalog, err)
			}
			if err := r.Write(out); err == nil {
				t.Fatal("overwrote existing output")
			}
			if !r.Written {
				t.Fatal("missing written marker")
			}
		})
	}
}

func TestUnsupportedBehaviorBlocksWholeCatalog(t *testing.T) {
	cases := []struct{ format, name, body string }{
		{"systemd", "demo.service", "[Service]\nExecStart=/bin/sleep 300\nUser=nobody\n"},
		{"systemd", "demo.service", "[Service]\nExecStart=/bin/sleep 300\nEnvironment=SECRET=value\n"},
		{"systemd", "demo.service", "[Service]\nType=notify\nExecStart=/bin/sleep 300\n"},
		{"systemd", "demo.service", "[Service]\nExecStart=/bin/sleep 300\nExecStart=\n"},
		{"systemd", "demo.service", "[Service]\nExecStart=/bin/echo $HOME\n"},
		{"systemd", "demo.service", "[Unit]\nRequires=db.service\n[Service]\nExecStart=/bin/sleep 300\n"},
		{"systemd", "demo.service", "[Unit]\nAfter=network.target\n[Service]\nExecStart=/bin/sleep 300\n"},
		{"systemd", "demo.service", "[Service]\nType=oneshot\nExecStart=/bin/true\n"},
		{"daemontools", "demo/run", "#!/bin/sh\ncd /somewhere\nexec /bin/sleep 300\n"},
		{"daemontools", "demo/run", "#!/bin/sh\nexec /bin/echo *\n"},
		{"openrc", "demo", "command=/bin/sleep\nstart_pre() {\n touch /tmp/should-not-run\n}\n"},
		{"openrc", "demo", "command=/bin/sleep\ncommand_user=nobody\n"},
		{"openrc", "demo", "command=/bin/sleep\ncommand_args=\"$(touch /tmp/should-not-run)\"\n"},
		{"openrc", "demo", "command=/bin/sleep\ndepend() {\nneed net\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.format+"/"+tc.body, func(t *testing.T) {
			src := t.TempDir()
			body := tc.body
			if tc.format == "openrc" {
				body = "#!/sbin/openrc-run\n" + body
			}
			put(t, src, tc.name, body)
			r, err := Scan(tc.format, src, false)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Blocked() {
				t.Fatalf("accepted unsupported behavior: %+v", r)
			}
			out := filepath.Join(t.TempDir(), "units")
			if err := r.Write(out); err == nil {
				t.Fatal("wrote blocked migration")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("output exists: %v", err)
			}
		})
	}
}

func TestOrderingAndCycleValidation(t *testing.T) {
	src := t.TempDir()
	put(t, src, "a.service", "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n")
	put(t, src, "b.service", "[Unit]\nAfter=a.service\n[Service]\nExecStart=/bin/echo 'repeat' 'repeat'\n")
	r, err := Scan("systemd", src, true)
	if err != nil || r.Blocked() {
		t.Fatalf("%+v %v", r, err)
	}
	if len(r.Units[1].Exec) != 3 || r.Units[1].Exec[1] != r.Units[1].Exec[2] {
		t.Fatal(r.Units)
	}
	put(t, src, "a.service", "[Unit]\nAfter=b.service\n[Service]\nExecStart=/bin/true\n")
	r, err = Scan("systemd", src, true)
	if err != nil || !r.Blocked() {
		t.Fatalf("cycle accepted: %+v %v", r, err)
	}
}

func TestDaemontoolsDownAndLog(t *testing.T) {
	src := t.TempDir()
	put(t, src, "demo/run", "#!/bin/sh\nexec /bin/sleep 300\n")
	put(t, src, "demo/down", "")
	r, err := Scan("daemontools", src, true)
	if err != nil || r.Blocked() || r.Units[0].Boot {
		t.Fatalf("%+v %v", r, err)
	}
	put(t, src, "demo/log/run", "exec /bin/cat\n")
	r, err = Scan("daemontools", src, true)
	if err != nil || !r.Blocked() {
		t.Fatalf("log pipeline discarded: %+v %v", r, err)
	}
}

func TestSymlinkAndDropInRejected(t *testing.T) {
	src := t.TempDir()
	put(t, src, "demo.service", "[Service]\nExecStart=/bin/true\n")
	if err := os.Symlink("demo.service", filepath.Join(src, "alias.service")); err != nil {
		t.Fatal(err)
	}
	r, err := Scan("systemd", src, false)
	if err != nil || !r.Blocked() {
		t.Fatalf("symlink accepted: %+v %v", r, err)
	}
	src = t.TempDir()
	put(t, src, "demo.service.d/override.conf", "[Service]\nUser=nobody\n")
	r, err = Scan("systemd", src, false)
	if err != nil || !r.Blocked() {
		t.Fatalf("drop-in accepted: %+v %v", r, err)
	}
}

func TestUnknownAndEmptySource(t *testing.T) {
	if _, err := Scan("other", t.TempDir(), false); err == nil {
		t.Fatal("unknown format")
	}
	if _, err := Scan("systemd", t.TempDir(), false); err == nil {
		t.Fatal("empty source")
	}
}

func TestOpenRCLiteralArgumentsAndOrdering(t *testing.T) {
	src := t.TempDir()
	put(t, src, "first", "#!/sbin/openrc-run\ncommand=/bin/sleep\ncommand_args=300\n")
	put(t, src, "second", "#!/sbin/openrc-run\ncommand=/bin/echo\ncommand_args=\"one 'two words' one\"\ndepend() {\nafter first\n}\n")
	r, err := Scan("openrc", src, true)
	if err != nil || r.Blocked() {
		t.Fatalf("%+v %v", r, err)
	}
	args := r.Units[1].Exec
	if len(args) != 4 || args[2] != "two words" || args[1] != args[3] {
		t.Fatalf("argv: %q", args)
	}
	if len(r.Units[1].After) != 1 || r.Units[1].After[0] != "first" {
		t.Fatal(r.Units[1])
	}
}

func TestForeignScriptInterpreterBlocked(t *testing.T) {
	src := t.TempDir()
	put(t, src, "demo/run", "#!/usr/bin/python3\nexec /bin/sleep 300\n")
	r, err := Scan("daemontools", src, false)
	if err != nil || !r.Blocked() {
		t.Fatalf("foreign script accepted: %+v %v", r, err)
	}
}
