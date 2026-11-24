// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Options.SHA256 is checked against the opened executable on every launch:
// the right digest runs, a wrong one is artifact_digest, and bytes changed
// in place after a launch that passed are caught at the next one.
func TestLaunchChecksExecDigest(t *testing.T) {
	src, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip("no /bin/true")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "app")
	if err := os.WriteFile(exe, src, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(src)
	good := hex.EncodeToString(sum[:])
	launch := func(digest string) error {
		cmd, _, _, err := Launch(context.Background(), "/bin/sh", []string{exe}, nil, false, 5*time.Second, Options{Path: exe, SHA256: digest})
		if err != nil {
			return err
		}
		return cmd.Wait()
	}
	if err := launch(good); err != nil {
		t.Fatalf("matching digest: %v", err)
	}
	bad := sha256.Sum256([]byte("other"))
	if err := launch(hex.EncodeToString(bad[:])); fail.Token(err) != "artifact_digest" {
		t.Fatalf("wrong digest: %v", err)
	}
	f, err := os.OpenFile(exe, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0})
	f.Close()
	if err := launch(good); fail.Token(err) != "artifact_digest" {
		t.Fatalf("changed in place: %v", err)
	}
}
