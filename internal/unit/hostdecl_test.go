// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestLoadHostDecl(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.Mkdir(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(etc, "host.json")
	if h, err := LoadHostDecl(p, false); err != nil || h != nil {
		t.Fatalf("missing, not required: %v %v", h, err)
	}
	if _, err := LoadHostDecl(p, true); fail.Token(err) != "host_decl_perm" {
		t.Fatalf("missing, required: %v", err)
	}
	doc := `{"devices": {"data": {"path": "/dev/vdb", "kind": "block", "match": {"serial": "X"}}}}`
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := LoadHostDecl(p, true)
	if err != nil || h.Devices["data"].Path != "/dev/vdb" {
		t.Fatalf("%+v %v", h, err)
	}
	for _, c := range []struct {
		name string
		path string
		mode os.FileMode
	}{{"group-writable file", p, 0o664}, {"other-writable file", p, 0o646}, {"other-writable directory", etc, 0o757}} {
		orig := os.FileMode(0o644)
		if c.path == etc {
			orig = 0o755
		}
		if err := os.Chmod(c.path, c.mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadHostDecl(p, true); fail.Token(err) != "host_decl_perm" {
			t.Errorf("%s: %v", c.name, err)
		}
		if err := os.Chmod(c.path, orig); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(etc, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostDecl(link, true); fail.Token(err) != "host_decl_perm" {
		t.Errorf("symlink: %v", err)
	}
	if _, err := LoadHostDecl("relative/host.json", false); fail.Token(err) != "host_decl_perm" {
		t.Errorf("relative: %v", err)
	}
	if err := os.WriteFile(p, []byte(`{"devices": {}, "devices": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostDecl(p, true); fail.Token(err) != "host_decl_invalid" {
		t.Errorf("duplicate key: %v", err)
	}
}
