//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
)

func TestLinuxPolicyCLI(t *testing.T) {
	dir := t.TempDir()
	trustFile := filepath.Join(dir, "trust.json")
	docFile := filepath.Join(dir, "document.json")
	cache := filepath.Join(dir, "cache")
	trust, err := os.ReadFile("../../internal/bootpolicy/testdata/trust.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustFile, trust, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../internal/bootpolicy/testdata/payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var p bootpolicy.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.IssuedAt = time.Now().Unix() - 10
	p.NotBefore = p.IssuedAt
	p.ExpiresAt = p.IssuedAt + 300
	p.OfflineUntil = p.ExpiresAt + 300
	p.RefreshAfterSeconds = 30
	payload, _ := json.Marshal(p)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)) // Public test seed.
	envelope, _ := json.Marshal(map[string]string{"key_id": "test-key", "payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(bootpolicy.Domain), payload...)))})
	if err := os.WriteFile(docFile, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"verify", "cache", "status"} {
		args := []string{"policy", op, "--trust", trustFile, "--trust-system-clock"}
		if op != "status" {
			args = append(args, "--document", docFile)
		}
		if op != "verify" {
			args = append(args, "--cache", cache)
		}
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr); code != 0 {
			t.Fatal(op, code, stderr.String(), out.String())
		}
		var report policyReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.State != bootpolicy.Valid || report.Sequence != 1 || report.Enforcement != "metadata_only" {
			t.Fatal(out.String())
		}
	}
	// A writable trust root must not become an authorization input.
	if err := os.Chmod(trustFile, 0666); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"policy", "verify", "--trust", trustFile, "--document", docFile, "--trust-system-clock"}, &out, &stderr); code != 1 || stderr.String() != "policy_bad_trust\n" {
		t.Fatal(code, stderr.String())
	}
}
