// SPDX-License-Identifier: GPL-3.0-or-later

package bootpolicy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// RefreshRequest is advisory local state. The issuer MUST select assignment by
// its independently authenticated host identity, never by requested scopes.
type RefreshRequest struct {
	TenantID          string `json:"tenant_id"`
	HostID            string `json:"host_id"`
	EnrollmentID      string `json:"enrollment_id"`
	Sequence          uint64 `json:"sequence"`
	CatalogGeneration uint64 `json:"catalog_generation"`
	PolicySHA256      string `json:"policy_sha256"`
}

// Refresh events. scheduled is emitted before an initial wait for a policy
// that is not yet due, attempt after every request, and not_renewing when the
// host's policy does not renew, after which the worker stops.
const (
	EventScheduled   = "scheduled"
	EventAttempt     = "attempt"
	EventNotRenewing = "not_renewing"
)

type RefreshResult struct {
	Event              string `json:"event"`
	OK                 bool   `json:"ok"`
	Error              string `json:"error"`
	Enforcement        string `json:"enforcement"`
	Lifetime           string `json:"lifetime,omitempty"`
	Sequence           uint64 `json:"sequence,omitempty"`
	NextAttemptSeconds int64  `json:"next_attempt_seconds,omitempty"`
}

// NotRenewing is the event for a host whose policy does not renew.
func NotRenewing() RefreshResult {
	return RefreshResult{Event: EventNotRenewing, OK: true, Enforcement: "metadata_only", Lifetime: LifetimeNever}
}

// Refresher pulls signed metadata from one provisioned HTTPS endpoint. No URL,
// credential, trust key, or transport setting is taken from a response.
//
// Threats: the request carries a bearer credential, so it goes only to the
// provisioned origin: TLS 1.3 against the system roots, no redirects, no
// environment proxy, no compression. Headers and body are capped. The
// credential is read from an owner-only regular file with one link, never a
// symlink, and is never written to an error, event or log. A response only
// takes effect through Store.Install, which checks signature, host binding,
// freshness, ordering, the revocation floor and the lifetime cap.
type Refresher struct {
	store          *Store
	endpoint       string
	credentialFile string
	client         *http.Client
	wait           func(context.Context, time.Duration) error
	jitter         func(time.Duration) time.Duration
}

func NewRefresher(s *Store, endpoint, credentialFile string) (*Refresher, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || credentialFile == "" || s == nil {
		return nil, fail.E("policy_refresh_config")
	}
	transport := &http.Transport{
		Proxy:                  nil, // Never use environment proxies for the credential-bearing request.
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1,
		DisableCompression: true,
	}
	return &Refresher{store: s, endpoint: u.String(), credentialFile: credentialFile, client: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, wait: waitRefresh, jitter: jitterRefresh}, nil
}
func (r *Refresher) Close() { r.client.CloseIdleConnections() }

func credential(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fail.E("policy_refresh_credential")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if !privateRegular(fd) {
		return "", fail.E("policy_refresh_credential")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return "", fail.E("policy_refresh_credential")
	}
	// Allow a single conventional trailing newline, never spaces or extra lines.
	b = bytes.TrimSuffix(b, []byte{'\n'})
	if len(b) < 32 {
		return "", fail.E("policy_refresh_credential")
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			return "", fail.E("policy_refresh_credential")
		}
	}
	return string(b), nil
}

// renewal reports the host's lifetime mode and the cached document that orders
// a replacement (nil when none). A trust cap of renew means renew whatever is
// cached; otherwise the cached policy decides, and no cache means never: a
// first renew policy is installed by other means, or the cap says renew. The
// cache is read as Install reads it for ordering, so a revoked or capped
// policy still renews. A corrupt floor or cache fails closed here, before any
// request.
func (s *Store) renewal() (string, *Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return "", nil, err
	}
	defer lock.Close()
	if _, err := s.loadFloor(); err != nil {
		return "", nil, err
	}
	d, err := s.loadForOrder()
	if err != nil && fail.Token(err) != "policy_missing" {
		return "", nil, err
	}
	switch {
	case s.trust.MaxLifetime == LifetimeRenew:
		return LifetimeRenew, d, nil
	case d != nil:
		return d.policy.Lifetime, d, nil
	default:
		return LifetimeNever, nil, nil
	}
}

// Once never changes the cache on transport/verification failures. Successful
// return means durable metadata acceptance, not active configuration or boot.
// A host that does not renew gets policy_not_renewing without a clock,
// credential or request. A response identical to the cache is
// policy_refresh_stale: it neither extends authority nor counts as renewal.
func (r *Refresher) Once(ctx context.Context) (*Document, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	lifetime, old, err := r.store.renewal()
	if err != nil {
		return nil, err
	}
	if lifetime != LifetimeRenew {
		return nil, fail.E("policy_not_renewing")
	}
	if r.store.clock == nil {
		return nil, fail.E("policy_clock_uncertain")
	}
	if _, ok := r.store.clock.Now(); !ok {
		return nil, fail.E("policy_clock_uncertain")
	}
	request := RefreshRequest{TenantID: r.store.trust.TenantID, HostID: r.store.trust.HostID, EnrollmentID: r.store.trust.EnrollmentID}
	if old != nil {
		p := old.policy
		request.Sequence = p.Sequence
		request.CatalogGeneration = p.CatalogGeneration
		request.PolicySHA256 = old.Digest()
	}
	token, err := credential(r.credentialFile)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fail.E("policy_refresh_config")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fail.E("policy_refresh_transport")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return nil, fail.E("policy_refresh_denied")
		}
		return nil, fail.E("policy_refresh_http")
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, fail.E("policy_refresh_encoding")
	}
	if resp.ContentLength > MaxEnvelope {
		return nil, fail.E("policy_refresh_size")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxEnvelope+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fail.E("policy_refresh_transport")
	}
	if len(raw) > MaxEnvelope {
		return nil, fail.E("policy_refresh_size")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d, err := r.store.Install(raw)
	if err != nil {
		return nil, err
	}
	if old != nil && d.policy.Sequence <= old.policy.Sequence {
		return nil, fail.E("policy_refresh_stale")
	}
	return d, nil
}

// Run retries failures until canceled. Emit receives only safe status tokens.
// Scheduled work lives in this supervised process, not in PID 1 or sash timers.
// It returns nil, after a not_renewing event, when the host's policy does not
// renew, including after a never-policy is installed by a refresh. It returns
// policy_clock_uncertain when the clock loses trust: an anchored clock cannot
// regain it in this process.
func (r *Refresher) Run(ctx context.Context, emit func(RefreshResult)) error {
	send := func(result RefreshResult) {
		if emit != nil {
			emit(result)
		}
	}
	lifetime, cached, err := r.store.renewal()
	if err == nil && lifetime != LifetimeRenew {
		send(NotRenewing())
		return nil
	}
	delay := r.initialDelay()
	if delay > 0 {
		result := RefreshResult{Event: EventScheduled, OK: true, Enforcement: "metadata_only", Lifetime: LifetimeRenew, NextAttemptSeconds: int64(delay / time.Second)}
		if cached != nil {
			result.Sequence = cached.policy.Sequence
		}
		send(result)
	}
	retry := 30 * time.Second
	for {
		if err := r.wait(ctx, delay); err != nil {
			return err
		}
		d, err := r.Once(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if fail.Token(err) == "policy_not_renewing" {
			send(NotRenewing())
			return nil
		}
		result := RefreshResult{Event: EventAttempt, OK: err == nil, Error: fail.Token(err), Enforcement: "metadata_only"}
		if fail.Token(err) == "policy_clock_uncertain" {
			send(result)
			return err
		}
		if err != nil {
			delay = r.jitter(retry)
			if delay > 5*time.Minute {
				delay = 5 * time.Minute
			}
			retry *= 2
			if retry > 5*time.Minute {
				retry = 5 * time.Minute
			}
		} else {
			retry = 30 * time.Second
			result.Sequence = d.policy.Sequence
			result.Lifetime = d.policy.Lifetime
			if d.policy.Lifetime != LifetimeRenew {
				send(result)
				send(NotRenewing())
				return nil
			}
			delay = r.nextDelay(d)
		}
		result.NextAttemptSeconds = int64(delay / time.Second)
		send(result)
	}
}
func (r *Refresher) initialDelay() time.Duration {
	d, err := r.store.Load()
	if err != nil || d.policy.Lifetime != LifetimeRenew || d.State(r.store.clock) != Valid {
		return 0
	}
	now, ok := r.store.clock.Now()
	if !ok {
		return 0
	}
	due := time.Unix(d.policy.IssuedAt+d.policy.RefreshAfterSeconds, 0)
	remaining := due.Sub(now)
	if remaining <= 0 {
		return 0
	}
	// Only subtract jitter on startup: never defer beyond the signed due time.
	delay := r.jitter(remaining)
	if delay > remaining {
		delay = remaining
	}
	return delay
}
func (r *Refresher) nextDelay(d *Document) time.Duration {
	// An unchanged/old response must not postpone refresh for another full interval.
	now, ok := r.store.clock.Now()
	if !ok {
		return 30 * time.Second
	}
	interval := time.Duration(d.policy.RefreshAfterSeconds) * time.Second
	remaining := time.Unix(d.policy.IssuedAt+d.policy.RefreshAfterSeconds, 0).Sub(now)
	if remaining > interval {
		remaining = interval
	}
	if remaining <= 0 {
		return 30 * time.Second
	}
	delay := r.jitter(remaining)
	beforeExpiry := time.Unix(d.policy.ExpiresAt, 0).Sub(now)
	if delay >= beforeExpiry {
		delay = beforeExpiry / 2
	}
	if delay < time.Second {
		delay = time.Second
	}
	return delay
}
func waitRefresh(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func jitterRefresh(d time.Duration) time.Duration {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return d
	}
	// Uniform enough for spreading refreshes, not for security decisions.
	factor := 800 + binary.LittleEndian.Uint64(b[:])%401
	return d * time.Duration(factor) / 1000
}

// IsCanceled distinguishes a normal worker stop from refresh refusals.
func IsCanceled(err error) bool { return errors.Is(err, context.Canceled) }
