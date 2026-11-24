// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func streamSpec(t *testing.T, root, p string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"notify": false, "sandbox": false, "cgroup": false, "stdout_file": StreamFile{Root: root, Path: p}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// openStreams refuses a hard-linked stream file (it could be a link to a
// file outside the root) and a path outside its root, even one whose text
// starts with the root's.
func TestOpenStreamsRefusals(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "r")
	for _, d := range []string{root, filepath.Join(root, "x"), filepath.Join(base, "rx")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(base, "secret.log")
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "linked.log")); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"hard link":         filepath.Join(root, "linked.log"),
		"sibling directory": filepath.Join(base, "rx", "out.log"),
		"root itself":       root,
	} {
		if err := openStreams(streamSpec(t, root, p)); fail.Token(err) != "stream_denied" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "x", "out.log")); err == nil {
		t.Fatal("the sibling path was opened beneath the root")
	}
}
