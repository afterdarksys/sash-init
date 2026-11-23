//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
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

// signedNow is the fixture policy, currently valid, signed with the public test seed.
func signedNow(t *testing.T, refreshAfter int64) []byte {
	t.Helper()
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
	p.ExpiresAt = p.IssuedAt + 2*refreshAfter
	p.OfflineUntil = p.ExpiresAt
	p.RefreshAfterSeconds = refreshAfter
	payload, _ := json.Marshal(p)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)) // Public test seed.
	envelope, _ := json.Marshal(map[string]string{"key_id": "test-key", "payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(bootpolicy.Domain), payload...)))})
	return envelope
}

// With a trusted clock the worker contacts the endpoint, refuses a server the
// system roots do not trust, reports the retry and stops cleanly on SIGTERM.
func TestLinuxPolicyRefreshCLI(t *testing.T) {
	trust, cache, endpoint, conns := refreshFixture(t, "renew")
	cred := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(cred, bytes.Repeat([]byte("c"), 40), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"policy", "refresh", "--trust", trust, "--cache", cache, "--endpoint", endpoint, "--credential", cred, "--trust-system-clock"}
	withRefreshContext(t)
	var out, stderr bytes.Buffer
	if code := run(append(append([]string{}, args...), "--once"), &out, &stderr); code != 1 || stderr.String() != "policy_refresh_transport\n" || out.Len() != 0 || conns.Load() != 1 {
		t.Fatal(code, out.String(), stderr.String(), conns.Load())
	}
	w := &cancelWriter{cancel: withRefreshContext(t)}
	stderr.Reset()
	if code := run(args, w, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatal(code, stderr.String())
	}
	var event bootpolicy.RefreshResult
	if err := json.Unmarshal(w.Bytes(), &event); err != nil || event.Event != "attempt" || event.OK || event.Error != "policy_refresh_transport" || event.NextAttemptSeconds < 23 || event.NextAttemptSeconds > 36 {
		t.Fatal(w.String())
	}
	// An output failure stops the worker at once instead of waiting to retry.
	withRefreshContext(t)
	f := &failWriter{}
	if code := run(args, f, &stderr); code != 1 || f.writes != 1 {
		t.Fatal(code)
	}
	if bytes.Contains(w.Bytes(), []byte("ccccc")) || bytes.Contains(stderr.Bytes(), []byte("ccccc")) {
		t.Fatal("credential printed")
	}
	// A cached policy that is not yet due is reported before the wait, with no request.
	doc := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(doc, signedNow(t, 3600), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"policy", "cache", "--trust", trust, "--cache", cache, "--document", doc, "--trust-system-clock"}, io.Discard, io.Discard); code != 0 {
		t.Fatal(code)
	}
	before := conns.Load()
	w = &cancelWriter{cancel: withRefreshContext(t)}
	if code := run(args, w, &stderr); code != 0 {
		t.Fatal(code)
	}
	if err := json.Unmarshal(w.Bytes(), &event); err != nil || event.Event != "scheduled" || !event.OK || event.Sequence != 1 || event.NextAttemptSeconds < 2800 || event.NextAttemptSeconds > 3600 || conns.Load() != before {
		t.Fatal(w.String())
	}
}
