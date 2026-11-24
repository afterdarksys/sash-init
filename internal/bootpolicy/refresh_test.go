// SPDX-License-Identifier: GPL-3.0-or-later

package bootpolicy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "test-token-test-token-test-token-test-token-test-token-test-token-test-token-test-token-"

// refreshServer is a TLS 1.3 issuer stand-in. conns counts every accepted
// connection, so a test can prove that no request was even attempted.
type refreshServer struct {
	*httptest.Server
	conns atomic.Int32
}

func newRefreshServer(t *testing.T, handler http.HandlerFunc, configure func(*tls.Config)) *refreshServer {
	t.Helper()
	rs := &refreshServer{}
	rs.Server = httptest.NewUnstartedServer(handler)
	rs.Server.Config.ErrorLog = log.New(io.Discard, "", 0) // Refused handshakes are expected.
	rs.Server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			rs.conns.Add(1)
		}
	}
	rs.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	if configure != nil {
		configure(rs.Server.TLS)
	}
	rs.Server.StartTLS()
	t.Cleanup(rs.Server.Close)
	return rs
}

func credentialFile(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(file, []byte(testToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

// refresherFor trusts the test server's certificate in place of the system roots.
func refresherFor(t *testing.T, s *Store, rs *refreshServer) *Refresher {
	t.Helper()
	r, err := NewRefresher(s, rs.URL, credentialFile(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	pool := x509.NewCertPool()
	pool.AddCert(rs.Certificate())
	r.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return r
}

func testRefresher(t *testing.T, s *Store, handler http.HandlerFunc) (*Refresher, *refreshServer) {
	t.Helper()
	rs := newRefreshServer(t, handler, nil)
	return refresherFor(t, s, rs), rs
}

func renewTrust() (Trust, Policy, []byte, func(Policy) []byte) {
	trust, p, key := fixture()
	trust.MaxLifetime = LifetimeRenew
	return trust, p, signed(p, key), func(p Policy) []byte { return signed(p, key) }
}

func requireSequence(t *testing.T, s *Store, want uint64) {
	t.Helper()
	d, err := s.Load()
	if err != nil || d.Policy().Sequence != want {
		t.Fatalf("cache changed: %v %v", d, err)
	}
}

func TestRefreshSuccessAndUntrustedResponses(t *testing.T) {
	trust, p, key := fixture()
	s, _ := newStore(t, trust, fixed(p.IssuedAt))
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	next := p
	next.Sequence++
	var mu sync.Mutex
	response := signed(next, key)
	status := 200
	encoding := ""
	header := ""
	calls := 0
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if req.Method != "POST" || req.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("bad request")
		}
		var state RefreshRequest
		if err := json.NewDecoder(req.Body).Decode(&state); err != nil {
			t.Error(err)
		}
		if state.HostID != trust.HostID || state.EnrollmentID != trust.EnrollmentID || state.Sequence < 1 || state.PolicySHA256 == "" {
			t.Errorf("bad state %+v", state)
		}
		if encoding != "" {
			w.Header().Set("Content-Encoding", encoding)
		}
		if header != "" {
			w.Header().Set("X-Large", header)
		}
		w.WriteHeader(status)
		w.Write(response)
	})
	d, err := r.Once(context.Background())
	if err != nil || d.Policy().Sequence != 2 {
		t.Fatal(d, err)
	}
	for _, tc := range []struct {
		name                   string
		status                 int
		body                   []byte
		encoding, header, code string
	}{
		{"unauthorized", 401, []byte("secret response"), "", "", "policy_refresh_denied"},
		{"forbidden", 403, nil, "", "", "policy_refresh_denied"},
		{"server_error", 500, nil, "", "", "policy_refresh_http"},
		{"no_change", 304, nil, "", "", "policy_refresh_http"},
		{"no_content", 204, nil, "", "", "policy_refresh_http"},
		// Within the cap the oversized body would reach Verify as policy_bad_shape.
		{"oversized", 200, bytes.Repeat([]byte{' '}, MaxEnvelope+1), "", "", "policy_refresh_size"},
		// Within the default 1 MiB header cap this would install sequence 3.
		{"large_headers", 200, signed(func() Policy { n := next; n.Sequence = 3; return n }(), key), "", strings.Repeat("h", 20*1024), "policy_refresh_transport"},
		{"malformed", 200, []byte("bad"), "", "", "policy_bad_shape"},
		{"rollback", 200, signed(p, key), "", "", "policy_rollback"},
		{"stale_identical", 200, signed(next, key), "", "", "policy_refresh_stale"},
		{"compressed", 200, response, "gzip", "", "policy_refresh_encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			status, response, encoding, header = tc.status, tc.body, tc.encoding, tc.header
			mu.Unlock()
			_, err := r.Once(context.Background())
			requireCode(t, err, tc.code)
			if strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "secret") {
				t.Fatal("response or credential in error")
			}
			requireSequence(t, s, 2)
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 12 {
		t.Fatal(calls)
	}
}

func TestRefreshNoRedirectOrProxy(t *testing.T) {
	trust, p, _, _ := renewTrust()
	s, _ := newStore(t, trust, fixed(p.IssuedAt))
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer destination.Close()
	t.Setenv("HTTPS_PROXY", destination.URL)
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) { http.Redirect(w, req, destination.URL, 307) })
	_, err := r.Once(context.Background())
	requireCode(t, err, "policy_refresh_http")
	if leaked.Load() != 0 {
		t.Fatal("credential followed redirect/proxy")
	}
	// The proxy environment excludes loopback, so check the transport itself.
	transport := r.client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("unsafe transport")
	}
}

func TestRefreshTLSRefusal(t *testing.T) {
	trust, p, _, _ := renewTrust()
	s, _ := newStore(t, trust, fixed(p.IssuedAt))
	var calls atomic.Int32
	handler := func(w http.ResponseWriter, req *http.Request) { calls.Add(1) }
	// System roots do not include the test certificate.
	rs := newRefreshServer(t, handler, nil)
	r, err := NewRefresher(s, rs.URL, credentialFile(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.client.Transport.(*http.Transport).TLSClientConfig.RootCAs != nil {
		t.Fatal("custom roots")
	}
	_, err = r.Once(context.Background())
	requireCode(t, err, "policy_refresh_transport")
	// A trusted certificate on a server that stops at TLS 1.2.
	old := newRefreshServer(t, handler, func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12 })
	r12 := refresherFor(t, s, old)
	_, err = r12.Once(context.Background())
	requireCode(t, err, "policy_refresh_transport")
	if calls.Load() != 0 || rs.conns.Load() != 1 || old.conns.Load() != 1 {
		t.Fatal("request reached an untrusted server", calls.Load())
	}
	_, err = s.Load()
	requireCode(t, err, "policy_missing")
}

func TestRefreshCredentialAndCancellation(t *testing.T) {
	trust, p, _, _ := renewTrust()
	s, dir := newStore(t, trust, fixed(p.IssuedAt))
	var calls atomic.Int32
	var seen sync.Map
	// The handler reads the body first: an HTTP/1.1 server notices a
	// client that went away only once the body is consumed. release ends
	// it before the server closes (cleanups run last-registered first), so
	// it can never outlive the test.
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		seen.Store(req.Header.Get("Authorization"), true)
		entered <- struct{}{}
		_, _ = io.Copy(io.Discard, req.Body)
		select {
		case <-req.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	good := r.credentialFile
	for _, body := range []string{"short", strings.Repeat("x", 32) + "\n\n", strings.Repeat("x", 4097), strings.Repeat("x", 32) + " bad", "\n" + strings.Repeat("x", 32)} {
		if err := os.WriteFile(good, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := r.Once(context.Background())
		requireCode(t, err, "policy_refresh_credential")
	}
	rotated := strings.Repeat("y", 32)
	if err := os.WriteFile(good, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0644, 0640, 0602} {
		if err := os.Chmod(good, mode); err != nil {
			t.Fatal(err)
		}
		_, err := r.Once(context.Background())
		requireCode(t, err, "policy_refresh_credential")
	}
	if err := os.Chmod(good, 0600); err != nil {
		t.Fatal(err)
	}
	// A refusal must come before any request; a bounded context keeps a
	// regression from blocking on the handler.
	refused := func(path string) {
		t.Helper()
		r.credentialFile = path
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.Once(ctx)
		requireCode(t, err, "policy_refresh_credential")
	}
	// The symlink target is otherwise acceptable: only O_NOFOLLOW refuses it.
	link := good + "-link"
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	refused(link)
	hard := good + "-hard"
	if err := os.Link(good, hard); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "..", "fifo")
	makeFIFO(t, fifo)
	for _, path := range []string{hard, good, fifo, filepath.Dir(good), good + "-missing"} {
		refused(path)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid credential sent")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	// The credential is reread on every attempt, so rotation needs no restart.
	r.credentialFile = good
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := r.Once(ctx); finished <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh request never arrived")
	}
	cancel()
	err := <-finished
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := seen.Load("Bearer " + rotated); !ok || calls.Load() != 1 {
		t.Fatal("rotated credential not used")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := r.Once(canceled); !IsCanceled(err) || calls.Load() != 1 {
		t.Fatal(err)
	}
	_, err = s.Load()
	requireCode(t, err, "policy_missing")
}

func TestRefreshRunBackoffAndRecovery(t *testing.T) {
	trust, p, _, sign := renewTrust()
	var now atomic.Int64
	now.Store(p.IssuedAt)
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(now.Load(), 0), true }))
	var calls atomic.Int32
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {
		n := calls.Add(1)
		if n <= 5 {
			w.WriteHeader(503)
			return
		}
		next := p
		next.Sequence = uint64(n)
		next.IssuedAt = now.Load()
		next.NotBefore = next.IssuedAt
		next.ExpiresAt = next.IssuedAt + 600
		next.OfflineUntil = next.IssuedAt + 900
		next.RefreshAfterSeconds = 60
		w.Write(sign(next))
	})
	r.jitter = func(d time.Duration) time.Duration { return d }
	waits := []time.Duration{}
	r.wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		now.Add(int64(d / time.Second))
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := []RefreshResult{}
	err := r.Run(ctx, func(e RefreshResult) {
		events = append(events, e)
		if len(events) == 7 {
			cancel()
		}
	})
	if !IsCanceled(err) {
		t.Fatal(err)
	}
	want := []time.Duration{0, 30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 300 * time.Second, 60 * time.Second}
	if len(waits) < len(want) {
		t.Fatal(waits)
	}
	for i, d := range want {
		if waits[i] != d {
			t.Fatal(i, waits, want)
		}
	}
	if events[0].OK || events[0].Error != "policy_refresh_http" || events[0].Event != EventAttempt || events[0].NextAttemptSeconds != 30 {
		t.Fatal(events)
	}
	if !events[5].OK || events[5].Sequence != 6 || events[5].Enforcement != "metadata_only" || events[5].Lifetime != LifetimeRenew {
		t.Fatal(events)
	}
}

// A server that keeps returning the cached document is a failure: it backs
// off and never extends authority or postpones the due refresh.
func TestRefreshRunStaleResponse(t *testing.T) {
	trust, p, first, _ := renewTrust()
	var now atomic.Int64
	now.Store(p.IssuedAt + p.RefreshAfterSeconds)
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(now.Load(), 0), true }))
	if _, err := s.Install(first); err != nil {
		t.Fatal(err)
	}
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) { w.Write(first) })
	r.jitter = func(d time.Duration) time.Duration { return d }
	waits := []time.Duration{}
	r.wait = func(ctx context.Context, d time.Duration) error { waits = append(waits, d); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []RefreshResult
	err := r.Run(ctx, func(e RefreshResult) {
		events = append(events, e)
		if len(events) == 3 {
			cancel()
		}
	})
	if !IsCanceled(err) || len(waits) < 3 || waits[0] != 0 || waits[1] != 30*time.Second || waits[2] != 60*time.Second {
		t.Fatal(err, waits)
	}
	for _, e := range events {
		if e.OK || e.Error != "policy_refresh_stale" {
			t.Fatal(events)
		}
	}
	requireSequence(t, s, 1)
}

func TestRefreshScheduling(t *testing.T) {
	trust, p, key := fixture()
	now := p.IssuedAt
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(now, 0), true }))
	d, err := s.Install(signed(p, key))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRefresher(s, "https://issuer.example/renew", "/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.jitter = func(d time.Duration) time.Duration { return d * 12 / 10 }
	if got := r.initialDelay(); got != 6*time.Hour {
		t.Fatal(got)
	}
	// The initial wait is reported before it starts.
	r.wait = func(ctx context.Context, d time.Duration) error { return context.Canceled }
	var events []RefreshResult
	if err := r.Run(context.Background(), func(e RefreshResult) { events = append(events, e) }); !IsCanceled(err) {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Event != EventScheduled || events[0].NextAttemptSeconds != 6*3600 || events[0].Sequence != 1 {
		t.Fatal(events)
	}
	now += p.RefreshAfterSeconds + 1
	if got := r.initialDelay(); got != 0 {
		t.Fatal(got)
	}
	if got := r.nextDelay(d); got != 30*time.Second {
		t.Fatal("stale replay postponed renewal", got)
	}
	// In grace and after expiry the refresh is due at once.
	for _, at := range []int64{p.ExpiresAt, p.OfflineUntil} {
		now = at
		if got := r.initialDelay(); got != 0 {
			t.Fatal(at, got)
		}
	}
	for _, url := range []string{"http://issuer/renew", "https://u:p@issuer/renew", "https://issuer/renew?token=secret", "https://issuer/renew#fragment", "https://issuer/renew?", "https:///renew", "https:issuer"} {
		if _, err := NewRefresher(s, url, "/token"); err == nil {
			t.Fatal(url)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "issuer") {
			t.Fatal("configuration echoed in error")
		}
	}
	if _, err := NewRefresher(s, "https://issuer/renew", ""); err == nil {
		t.Fatal("empty credential path")
	}
	for i := 0; i < 100; i++ {
		j := jitterRefresh(time.Hour)
		if j < 48*time.Minute || j > 72*time.Minute {
			t.Fatal(j)
		}
	}
}

// A response in grace or past expiry, or a clock that loses trust, never
// installs; the cached document keeps its own deadlines.
func TestRefreshGraceExpiryAndClock(t *testing.T) {
	trust, p, first, sign := renewTrust()
	var now atomic.Int64
	trusted := atomic.Bool{}
	trusted.Store(true)
	now.Store(p.ExpiresAt) // The cached policy is in grace.
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(now.Load(), 0), trusted.Load() }))
	now.Store(p.IssuedAt)
	if _, err := s.Install(first); err != nil {
		t.Fatal(err)
	}
	now.Store(p.ExpiresAt)
	stale := p
	stale.Sequence = 2 // Higher, but signed with the old deadlines.
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) { w.Write(sign(stale)) })
	_, err := r.Once(context.Background())
	requireCode(t, err, "policy_expired")
	d, err := s.Load()
	if err != nil || d.Policy().Sequence != 1 || d.State(s.clock) != Grace {
		t.Fatal(d, err)
	}
	trusted.Store(false)
	r.wait = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	var events []RefreshResult
	err = r.Run(context.Background(), func(e RefreshResult) { events = append(events, e) })
	requireCode(t, err, "policy_clock_uncertain")
	if len(events) != 1 || events[0].Error != "policy_clock_uncertain" {
		t.Fatal(events)
	}
}

// never-mode: no clock, credential or connection is needed, and the worker
// stops after one not_renewing event.
func TestRefreshNeverMode(t *testing.T) {
	trust, p, key := fixture() // max_lifetime never
	for _, cached := range []bool{true, false} {
		s, _ := newStore(t, trust, nil)
		if cached {
			if _, err := s.Install(signed(never(p), key)); err != nil {
				t.Fatal(err)
			}
		}
		rs := newRefreshServer(t, func(w http.ResponseWriter, req *http.Request) {}, nil)
		r, err := NewRefresher(s, rs.URL, "/nonexistent")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		_, err = r.Once(context.Background())
		requireCode(t, err, "policy_not_renewing")
		r.wait = func(context.Context, time.Duration) error { t.Fatal("waited"); return nil }
		var events []RefreshResult
		if err := r.Run(context.Background(), func(e RefreshResult) { events = append(events, e) }); err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0] != NotRenewing() || rs.conns.Load() != 0 {
			t.Fatal(cached, events, rs.conns.Load())
		}
	}
	// A trust cap of renew makes an empty cache renew; it then needs a clock.
	trust.MaxLifetime = LifetimeRenew
	s, _ := newStore(t, trust, nil)
	r, err := NewRefresher(s, "https://issuer.example/renew", "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.Once(context.Background())
	requireCode(t, err, "policy_clock_uncertain")
}

// A refresh response that switches to never obeys the cap and the
// generation rule, and once installed the worker stops.
func TestRefreshNeverResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cap        string
		generation uint64
		code       string
	}{
		{"capped", LifetimeRenew, 2, "policy_lifetime_cap"},
		{"same_generation", LifetimeNever, 1, "policy_generation_conflict"},
		{"accepted", LifetimeNever, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust, p, key := fixture()
			trust.MaxLifetime = tc.cap
			s, _ := newStore(t, trust, fixed(p.IssuedAt+p.RefreshAfterSeconds)) // Due now.
			if _, err := s.Install(signed(p, key)); err != nil {
				t.Fatal(err)
			}
			n := never(p)
			n.Sequence, n.CatalogGeneration = 2, tc.generation
			response := signed(n, key)
			r, rs := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) { w.Write(response) })
			r.jitter = func(d time.Duration) time.Duration { return d }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.wait = func(ctx context.Context, d time.Duration) error {
				if d != 0 {
					cancel()
				}
				return ctx.Err()
			}
			var events []RefreshResult
			err := r.Run(ctx, func(e RefreshResult) { events = append(events, e) })
			if tc.code != "" {
				if !IsCanceled(err) || len(events) != 1 || events[0].Error != tc.code {
					t.Fatal(err, events)
				}
				requireSequence(t, s, 1)
				return
			}
			if err != nil || len(events) != 2 || !events[0].OK || events[0].Lifetime != LifetimeNever || events[1] != NotRenewing() {
				t.Fatal(err, events)
			}
			requireSequence(t, s, 2)
			conns := rs.conns.Load()
			_, err = r.Once(context.Background())
			requireCode(t, err, "policy_not_renewing")
			if rs.conns.Load() != conns {
				t.Fatal("not_renewing connected")
			}
		})
	}
}

// A revoked renew policy still renews; a corrupt cache or floor stops before
// any request.
func TestRefreshRevokedAndCorrupt(t *testing.T) {
	trust, p, key := fixture()
	s, dir := newStore(t, trust, fixed(p.IssuedAt))
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InstallFloor(signedFloor(floorFixture(2), key)); err != nil {
		t.Fatal(err)
	}
	next := p
	next.Sequence = 2
	var calls atomic.Int32
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		var state RefreshRequest
		if err := json.NewDecoder(req.Body).Decode(&state); err != nil || state.Sequence != 1 {
			t.Error(state, err)
		}
		w.Write(signed(next, key))
	})
	if d, err := r.Once(context.Background()); err != nil || d.Policy().Sequence != 2 {
		t.Fatal(d, err)
	}
	for _, name := range []string{"policy.json", "floor.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("corrupt"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err = r.Once(context.Background())
		requireCode(t, err, "policy_bad_shape")
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}

// An untrusted clock stops a renew host before the credential is read or any
// connection is made. Install would refuse the result anyway, so only the
// absence of a connection shows the guard.
func TestRefreshUntrustedClockBeforeRequest(t *testing.T) {
	trust, p, _, _ := renewTrust()
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(p.IssuedAt, 0), false }))
	r, rs := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {})
	_, err := r.Once(context.Background())
	requireCode(t, err, "policy_clock_uncertain")
	// A missing credential would be policy_refresh_credential if it were read first.
	r.credentialFile = filepath.Join(t.TempDir(), "missing")
	_, err = r.Once(context.Background())
	requireCode(t, err, "policy_clock_uncertain")
	if rs.conns.Load() != 0 {
		t.Fatal("connected with an untrusted clock")
	}
}

// The transport limits are part of the contract: the values are pinned, and
// shortened copies show each one ends a stalled attempt.
func TestRefreshTransportLimits(t *testing.T) {
	trust, p, _, _ := renewTrust()
	s, _ := newStore(t, trust, fixed(p.IssuedAt))
	release := make(chan struct{})
	mode := atomic.Int32{}
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		if mode.Load() == 1 { // Slow-drip body after prompt headers.
			w.WriteHeader(200)
			for {
				if _, err := w.Write([]byte(" ")); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-req.Context().Done():
					return
				case <-release:
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}
		select { // Headers never arrive.
		case <-req.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	transport := r.client.Transport.(*http.Transport)
	if r.client.Timeout != 30*time.Second || transport.ResponseHeaderTimeout != 20*time.Second || transport.TLSHandshakeTimeout != 10*time.Second || transport.MaxConnsPerHost != 1 || transport.MaxIdleConnsPerHost != 1 || transport.MaxResponseHeaderBytes != 16*1024 || !transport.DisableCompression {
		t.Fatal("transport limits changed")
	}
	transport.ResponseHeaderTimeout = 100 * time.Millisecond
	start := time.Now()
	_, err := r.Once(context.Background())
	requireCode(t, err, "policy_refresh_transport")
	transport.ResponseHeaderTimeout = 0
	mode.Store(1)
	r.client.Timeout = 200 * time.Millisecond
	_, err = r.Once(context.Background())
	requireCode(t, err, "policy_refresh_transport")
	if time.Since(start) > 10*time.Second {
		t.Fatal("stalled attempt not ended")
	}
	if _, err := s.Load(); fmt.Sprint(err) != "policy_missing" {
		t.Fatal("cache changed", err)
	}
}

// Retries cap at 5 minutes even when jitter would exceed it, and a success
// resets the backoff to 30 seconds.
func TestRefreshRetryCapAndReset(t *testing.T) {
	trust, p, _, sign := renewTrust()
	var now atomic.Int64
	now.Store(p.IssuedAt)
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(now.Load(), 0), true }))
	var calls atomic.Int32
	r, _ := testRefresher(t, s, func(w http.ResponseWriter, req *http.Request) {
		n := calls.Add(1)
		if n != 7 {
			w.WriteHeader(503)
			return
		}
		next := p
		next.IssuedAt = now.Load()
		next.NotBefore = next.IssuedAt
		next.ExpiresAt = next.IssuedAt + 600
		next.OfflineUntil = next.ExpiresAt
		next.RefreshAfterSeconds = 60
		w.Write(sign(next))
	})
	r.jitter = func(d time.Duration) time.Duration { return d * 12 / 10 }
	var waits []time.Duration
	r.wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		now.Add(int64(d / time.Second))
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := 0
	if err := r.Run(ctx, func(RefreshResult) {
		if events++; events == 8 {
			cancel()
		}
	}); !IsCanceled(err) {
		t.Fatal(err)
	}
	sec := time.Second
	want := []time.Duration{0, 36 * sec, 72 * sec, 144 * sec, 288 * sec, 300 * sec, 300 * sec, 72 * sec, 36 * sec}
	if len(waits) != len(want) {
		t.Fatal(waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatal(i, waits)
		}
	}
}

// When the jittered interval would reach normal expiry, the next attempt is
// halfway to expiry instead.
func TestRefreshNextDelayBeforeExpiry(t *testing.T) {
	trust, p, key := fixture()
	p.ExpiresAt = p.IssuedAt + 110
	p.OfflineUntil = p.ExpiresAt
	p.RefreshAfterSeconds = 100
	s, _ := newStore(t, trust, fixed(p.IssuedAt))
	d, err := s.Install(signed(p, key))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRefresher(s, "https://issuer.example/renew", "/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.jitter = func(d time.Duration) time.Duration { return d * 12 / 10 }
	if got := r.nextDelay(d); got != 55*time.Second {
		t.Fatal(got)
	}
}
