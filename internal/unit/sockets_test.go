// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// A socket path must be at or beneath a read_write path, by whole path
// components; a read-only path does not count. It keeps the path grammar,
// is unique and counts in the 64-path total.
func TestSocketPathsRules(t *testing.T) {
	many := make([]string, 63)
	for i := range many {
		many[i] = fmt.Sprintf("/srv/p%d", i)
	}
	for _, tc := range []struct {
		sb    map[string]any
		token string
	}{
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a"}}, ""},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a/s", "/run/a/t/u"}}, ""},
		{map[string]any{"read_write_paths": []string{"/srv/x", "/run/a"}, "socket_paths": []string{"/run/a/s"}}, ""},
		{map[string]any{"read_write_paths": []string{"/"}, "socket_paths": []string{"/run/x"}}, ""},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{}}, ""},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/ab"}}, "sandbox_socket"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run"}}, "sandbox_socket"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a/s", "/tmp"}}, "sandbox_socket"},
		{map[string]any{"socket_paths": []string{"/run/a"}}, "sandbox_socket"},
		{map[string]any{"read_only_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a"}}, "sandbox_socket"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"run/a"}}, "sandbox_path"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a/"}}, "sandbox_path"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a/../b"}}, "sandbox_path"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": []string{"/run/a", "/run/a"}}, "duplicate_field"},
		{map[string]any{"read_write_paths": []string{"/run/a"}, "socket_paths": "/run/a"}, "failed"},
		{map[string]any{"read_write_paths": append([]string{"/run/a"}, many...), "socket_paths": []string{"/run/a"}}, "failed"},
		{map[string]any{"read_write_paths": append([]string{"/run/a"}, many[1:]...), "socket_paths": []string{"/run/a"}}, ""},
	} {
		if tok := capsToken(t, tc.sb); tok != tc.token {
			t.Errorf("%v: %q, want %q", tc.sb, tok, tc.token)
		}
	}
	// The helper decodes its spec through FinishSandbox, which checks the
	// same rules without the JSON field parser.
	for _, tc := range []struct {
		sb    *Sandbox
		token string
	}{
		{&Sandbox{ReadWrite: []string{"/run/a"}, Sockets: []string{"/run/a", "/run/a"}}, "duplicate_field"},
		{&Sandbox{ReadWrite: []string{"/run/a"}, Sockets: []string{"/run/b"}}, "sandbox_socket"},
		{&Sandbox{ReadWrite: []string{"/run/a"}, Sockets: []string{"/run/a/x"}}, ""},
	} {
		if err := FinishSandbox(tc.sb, false, true); fail.Token(err) != tc.token {
			t.Errorf("%v: %v, want %q", tc.sb.Sockets, err, tc.token)
		}
	}
}

// A socket path cannot reach /proc for a setuid/setgid unit: outside every
// read_write path it is sandbox_socket, and the read_write path that would
// hold it is sandbox_proc.
func TestSocketPathsProcRule(t *testing.T) {
	for _, caps := range []map[string]any{
		{"caps": []string{"setuid"}, "setuid_to": []int{70001}},
		{"caps": []string{"setgid"}, "setgid_to": []int{70001}},
	} {
		for _, tc := range []struct {
			rw, sock []string
			token    string
		}{
			{[]string{"/run/a"}, []string{"/run/a"}, ""},
			{[]string{"/run/a"}, []string{"/proc"}, "sandbox_socket"},
			{[]string{"/run/a"}, []string{"/proc/1"}, "sandbox_socket"},
			{[]string{"/proc"}, []string{"/proc"}, "sandbox_proc"},
			{[]string{"/"}, []string{"/proc/sys"}, "sandbox_proc"},
		} {
			sb := map[string]any{"read_write_paths": tc.rw, "socket_paths": tc.sock}
			for k, v := range caps {
				sb[k] = v
			}
			if tok := capsToken(t, sb); tok != tc.token {
				t.Errorf("%v %v %v: %q, want %q", caps["caps"], tc.rw, tc.sock, tok, tc.token)
			}
		}
	}
}

// The beneath rule runs again after Load resolves links: a socket path that
// is a link out of its read_write path is refused by plan, and one that
// resolves inside it loads.
func TestLoadSocketPathResolved(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rw, out := filepath.Join(root, "rw"), filepath.Join(root, "out")
	for _, d := range []string{rw, out, filepath.Join(rw, "real")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(out, filepath.Join(rw, "away")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(rw, "real"), filepath.Join(root, "in")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rw, sock, token string
	}{
		{rw, filepath.Join(rw, "away"), "sandbox_socket"},
		{rw, filepath.Join(rw, "real"), ""},
		// As written the link is outside: refused before resolving.
		{rw, filepath.Join(root, "in"), "sandbox_socket"},
	} {
		sb := map[string]any{"read_write_paths": []string{tc.rw}, "socket_paths": []string{tc.sock}}
		dir := t.TempDir()
		writeRaw(t, dir, "a.json", string(capsUnit(t, sb)))
		_, _, err := Load(dir)
		if fail.Token(err) != tc.token {
			t.Errorf("%s: %v, want %q", tc.sock, err, tc.token)
		}
	}
	// The link out passes Parse (as written it is beneath rw): only Load sees it.
	if tok := capsToken(t, map[string]any{"read_write_paths": []string{rw}, "socket_paths": []string{filepath.Join(rw, "away")}}); tok != "" {
		t.Fatal(tok)
	}
}

// A sash unit may list socket paths like any sandboxed unit.
func TestSashSocketPaths(t *testing.T) {
	raw := strings.Replace(sashUnit, `"sandbox":{}`, `"sandbox":{"read_write_paths":["/srv/app"],"socket_paths":["/srv/app/run"]}`, 1)
	if raw == sashUnit {
		t.Fatal("edit did not apply")
	}
	svc, err := Parse([]byte(raw), "app")
	if err != nil || len(svc.Sandbox.Sockets) != 1 || svc.Sandbox.Sockets[0] != "/srv/app/run" {
		t.Fatalf("%v %+v", err, svc)
	}
	raw = strings.Replace(sashUnit, `"sandbox":{}`, `"sandbox":{"socket_paths":["/srv/app/run"]}`, 1)
	if _, err := Parse([]byte(raw), "app"); fail.Token(err) != "sandbox_socket" {
		t.Fatal(err)
	}
}
