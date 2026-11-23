package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestPolicyCLI(t *testing.T) {
	trust := "../../internal/bootpolicy/testdata/trust.json"
	doc := "../../internal/bootpolicy/testdata/policy.json"
	var out, stderr bytes.Buffer
	code := run([]string{"policy", "verify", "--trust", trust, "--document", doc}, &out, &stderr)
	var report policyReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err, stderr.String())
	}
	if code != 1 || !report.Verified || report.State != bootpolicy.ClockUncertain || report.Error != "policy_clock_uncertain" || report.Enforcement != "metadata_only" {
		t.Fatal(code, out.String(), stderr.String())
	}
	cache := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	code = run([]string{"policy", "cache", "--trust", trust, "--document", doc, "--cache", cache}, &out, &stderr)
	if code != 1 || stderr.String() != "policy_clock_uncertain\n" {
		t.Fatal(code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(cache, "policy.json")); !os.IsNotExist(err) {
		t.Fatal("cached without clock confidence")
	}
	// Status can inspect previously installed metadata even without trusted time.
	raw, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "policy.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	code = run([]string{"policy", "status", "--trust", trust, "--cache", cache}, &out, &stderr)
	if code != 0 || !bytes.Contains(out.Bytes(), []byte(`"state":"clock_uncertain"`)) {
		t.Fatal(code, out.String(), stderr.String())
	}
	for _, args := range [][]string{{"policy"}, {"policy", "sign"}, {"policy", "verify", "--trust", trust}, {"policy", "status", "--trust", trust, "--cache", cache, "--document", doc}} {
		out.Reset()
		stderr.Reset()
		if got := run(args, &out, &stderr); got != 2 {
			t.Fatal(args, got)
		}
	}
}

func TestPolicyCLILifetimeAndFloor(t *testing.T) {
	trust := "../../internal/bootpolicy/testdata/trust.json"
	never := "../../internal/bootpolicy/testdata/policy-never.json"
	floor := "../../internal/bootpolicy/testdata/floor.json"
	cache := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) (int, string, string) {
		var out, stderr bytes.Buffer
		code := run(append([]string{"policy"}, args...), &out, &stderr)
		return code, out.String(), stderr.String()
	}
	// A never-policy caches and reports valid without any clock.
	if code, out, errs := call("cache", "--trust", trust, "--document", never, "--cache", cache); code != 0 || !bytes.Contains([]byte(out), []byte(`"state":"valid"`)) || !bytes.Contains([]byte(out), []byte(`"lifetime":"never"`)) {
		t.Fatal(code, out, errs)
	}
	if code, _, errs := call("floor-show", "--trust", trust, "--cache", cache); code != 1 || errs != "policy_floor_missing\n" {
		t.Fatal(code, errs)
	}
	code, out, errs := call("floor-install", "--trust", trust, "--document", floor, "--cache", cache)
	var fr floorReport
	if err := json.Unmarshal([]byte(out), &fr); err != nil || code != 0 || !fr.Verified || fr.MinSequence != 2 || len(fr.FloorSHA256) != 64 {
		t.Fatal(code, out, errs)
	}
	if code, out, _ := call("floor-show", "--trust", trust, "--cache", cache); code != 0 || !bytes.Contains([]byte(out), []byte(`"min_sequence":2`)) {
		t.Fatal(code, out)
	}
	// The cached sequence-1 policy is now below the floor.
	code, out, _ = call("status", "--trust", trust, "--cache", cache)
	var report policyReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || code != 1 || report.Verified || report.State != bootpolicy.Revoked || report.Error != "policy_revoked" || report.FloorMinSequence != 2 {
		t.Fatal(code, out)
	}
	if code, _, errs := call("cache", "--trust", trust, "--document", never, "--cache", cache); code != 1 || errs != "policy_revoked\n" {
		t.Fatal(code, errs)
	}
	// A policy document is not a floor.
	if code, _, errs := call("floor-install", "--trust", trust, "--document", never, "--cache", cache); code != 1 || errs != "policy_bad_signature\n" {
		t.Fatal(code, errs)
	}
	for _, args := range [][]string{{"floor-install", "--trust", trust, "--cache", cache}, {"floor-install", "--trust", trust, "--document", floor}, {"floor-show", "--trust", trust, "--cache", cache, "--document", floor}, {"floor-show", "--trust", trust}} {
		if got, _, _ := call(args...); got != 2 {
			t.Fatal(args, got)
		}
	}
}

// refreshFixture is a cache directory, a trust file with the given cap, and a
// TLS server that counts connections; the certificate is not in system roots.
func refreshFixture(t *testing.T, maxLifetime string) (trust, cache, endpoint string, conns *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	raw, err := os.ReadFile("../../internal/bootpolicy/testdata/trust.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"max_lifetime": "never"`), []byte(`"max_lifetime": "`+maxLifetime+`"`), 1)
	trust = filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trust, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cache = filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	conns = new(atomic.Int32)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return trust, cache, server.URL + "/renew", conns
}

// withRefreshContext replaces the signal context; the returned cancel stops
// every later worker as SIGTERM would. Each run gets its own child context.
func withRefreshContext(t *testing.T) context.CancelFunc {
	t.Helper()
	parent, cancel := context.WithCancel(context.Background())
	old := refreshContext
	refreshContext = func() (context.Context, context.CancelFunc) { return context.WithCancel(parent) }
	t.Cleanup(func() { refreshContext = old; cancel() })
	return cancel
}

type failWriter struct{ writes int }

func (w *failWriter) Write([]byte) (int, error) { w.writes++; return 0, errors.New("closed") }

type cancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelWriter) Write(b []byte) (int, error) { w.cancel(); return w.Buffer.Write(b) }

func TestPolicyRefreshCLIArgs(t *testing.T) {
	trust, cache, endpoint, conns := refreshFixture(t, "never")
	cred := filepath.Join(t.TempDir(), "credential")
	base := []string{"policy", "refresh", "--trust", trust, "--cache", cache, "--endpoint", endpoint, "--credential", cred}
	for _, args := range [][]string{
		{"policy", "refresh", "--trust", trust, "--cache", cache, "--endpoint", endpoint},
		{"policy", "refresh", "--trust", trust, "--cache", cache, "--credential", cred},
		{"policy", "refresh", "--trust", trust, "--endpoint", endpoint, "--credential", cred},
		{"policy", "refresh", "--cache", cache, "--endpoint", endpoint, "--credential", cred},
		append(append([]string{}, base...), "--document", cred),
		append(append([]string{}, base...), "extra"),
		append(append([]string{}, base...), "--once=maybe"),
		{"policy", "status", "--trust", trust, "--cache", cache, "--once"},
		{"policy", "status", "--trust", trust, "--cache", cache, "--endpoint", endpoint},
		{"policy", "verify", "--trust", trust, "--document", cred, "--credential", cred},
	} {
		var out, stderr bytes.Buffer
		if got := run(args, &out, &stderr); got != 2 || out.Len() != 0 {
			t.Fatal(args, got)
		}
	}
	for _, bad := range []string{"http://issuer.invalid/renew", "https://issuer.invalid/renew?token=secret"} {
		var out, stderr bytes.Buffer
		args := []string{"policy", "refresh", "--trust", trust, "--cache", cache, "--endpoint", bad, "--credential", cred}
		if got := run(args, &out, &stderr); got != 1 || stderr.String() != "policy_refresh_config\n" {
			t.Fatal(bad, got, stderr.String())
		}
	}
	if conns.Load() != 0 {
		t.Fatal("connected")
	}
}

// never-mode needs no clock, credential or network, in both run and --once.
func TestPolicyRefreshCLINever(t *testing.T) {
	for _, cached := range []bool{true, false} {
		trust, cache, endpoint, conns := refreshFixture(t, "never")
		if cached {
			if code := run([]string{"policy", "cache", "--trust", trust, "--cache", cache, "--document", "../../internal/bootpolicy/testdata/policy-never.json"}, io.Discard, io.Discard); code != 0 {
				t.Fatal(code)
			}
		}
		args := []string{"policy", "refresh", "--trust", trust, "--cache", cache, "--endpoint", endpoint, "--credential", "/nonexistent"}
		for _, extra := range [][]string{nil, {"--once"}} {
			withRefreshContext(t)
			var out, stderr bytes.Buffer
			code := run(append(append([]string{}, args...), extra...), &out, &stderr)
			if code != 0 || out.String() != `{"event":"not_renewing","ok":true,"error":"","enforcement":"metadata_only","lifetime":"never"}`+"\n" || stderr.Len() != 0 {
				t.Fatal(cached, extra, code, out.String(), stderr.String())
			}
			// Output failure stops the worker with exit 1.
			w := &failWriter{}
			if code := run(append(append([]string{}, args...), extra...), w, &stderr); code != 1 || w.writes != 1 {
				t.Fatal("output failure", extra, code)
			}
		}
		if conns.Load() != 0 {
			t.Fatal("never-mode connected")
		}
	}
}

// A renew host without a trusted clock refuses before any request, and a
// stop before the first attempt is a clean exit.
func TestPolicyRefreshCLIRenewWithoutClock(t *testing.T) {
	trust, cache, endpoint, conns := refreshFixture(t, "renew")
	args := []string{"policy", "refresh", "--trust", trust, "--cache", cache, "--endpoint", endpoint, "--credential", "/nonexistent"}
	for _, extra := range [][]string{nil, {"--once"}} {
		withRefreshContext(t)
		var out, stderr bytes.Buffer
		code := run(append(append([]string{}, args...), extra...), &out, &stderr)
		if code != 1 || stderr.String() != "policy_clock_uncertain\n" {
			t.Fatal(extra, code, out.String(), stderr.String())
		}
		if extra == nil && !bytes.Contains(out.Bytes(), []byte(`"event":"attempt","ok":false,"error":"policy_clock_uncertain"`)) {
			t.Fatal(out.String())
		}
		cancel := withRefreshContext(t)
		cancel()
		out.Reset()
		stderr.Reset()
		if code := run(append(append([]string{}, args...), extra...), &out, &stderr); code != 0 || out.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("canceled", extra, code, out.String(), stderr.String())
		}
	}
	if conns.Load() != 0 {
		t.Fatal("connected without a clock")
	}
}

// The shipped unit example must stay a valid, sandboxed, non-root unit.
func TestPolicyRefreshUnitExample(t *testing.T) {
	raw, err := os.ReadFile("../../docs/examples/policy-refresh.json")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := unit.Parse(raw, "policy-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Sandbox == nil || svc.Execution.UID == nil || *svc.Execution.UID == 0 || svc.Boot || len(svc.Sandbox.Caps) != 0 {
		t.Fatal("example must be sandboxed, non-root, off the boot path, without capabilities")
	}
	if !strings.Contains(string(raw), ".invalid/") {
		t.Fatal("example endpoint must stay a placeholder")
	}
}
