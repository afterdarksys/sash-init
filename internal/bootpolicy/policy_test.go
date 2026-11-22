package bootpolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Public deterministic test key, never a production signing credential.
func fixture() (Trust, Policy, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	t := Trust{TenantID: "tenant-1", HostID: "host-1", EnrollmentID: "enrollment-1", RecoveryProfileID: "recovery-1", Keys: map[string]string{"test-key": base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}, MaxValiditySeconds: 7 * 86400, MaxGraceSeconds: 2 * 86400, MaxJobSeconds: 300, MinRefreshSeconds: 30, MaxRefreshSeconds: 86400}
	p := Policy{Version: Version, TenantID: t.TenantID, HostID: t.HostID, EnrollmentID: t.EnrollmentID, PolicyID: "standard", Sequence: 1, CatalogGeneration: 1, IssuedAt: 1800000000, NotBefore: 1800000000, ExpiresAt: 1800604800, OfflineUntil: 1800777600, RefreshAfterSeconds: 21600, CatalogSHA256: strings.Repeat("a", 64), Units: []Unit{{ID: "network", Needs: []string{}}, {ID: "agent", Needs: []string{"network"}}}, Jobs: []Job{{ID: "boot-agent", ScriptSHA256: strings.Repeat("b", 64), Scopes: []Scope{{Operation: "unit.start", Resource: "agent"}}, Phases: []string{"boot"}, TimeoutSeconds: 30, NeedsUnits: []string{"network", "agent"}, NeedsJobs: []string{}}}, OfflineUnits: []string{"network", "agent"}, OfflineJobs: []string{"boot-agent"}, RuntimeRestartUnits: []string{}, RecoveryProfileID: t.RecoveryProfileID}
	return t, p, key
}
func signPayload(payload []byte, key ed25519.PrivateKey, domain string) []byte {
	b, _ := json.Marshal(envelope{KeyID: "test-key", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), payload...)))})
	return b
}
func signed(p Policy, key ed25519.PrivateKey) []byte {
	raw, _ := json.Marshal(p)
	return signPayload(raw, key, Domain)
}
func fixed(n int64) Clock {
	return ClockFunc(func() (time.Time, bool) { return time.Unix(n, 0), true })
}
func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	if fail.Token(err) != want {
		t.Fatalf("error %v, want %s", err, want)
	}
}

func TestGolden(t *testing.T) {
	trust, p, key := fixture()
	want := signed(p, key)
	if os.Getenv("SAHINIT_UPDATE_POLICY_FIXTURES") == "1" {
		if err := os.WriteFile("testdata/policy.json", append(want, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(trust, "", "  ")
		if err := os.WriteFile("testdata/trust.json", append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		b, _ = json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile("testdata/payload.json", append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile("testdata/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), want) {
		t.Fatal("golden signature changed")
	}
	d, err := Verify(got, trust)
	if err != nil {
		t.Fatal(err)
	}
	if d.State(fixed(p.IssuedAt)) != Valid {
		t.Fatal("not valid")
	}
	// Accessors cannot mutate the verified object or future renewal checks.
	copy := d.Policy()
	copy.Units[0].ID = "evil"
	raw := d.Bytes()
	raw[0] = 'x'
	if d.Policy().Units[0].ID != "network" || d.Bytes()[0] != '{' {
		t.Fatal("mutable document")
	}
}

func TestVerificationRejects(t *testing.T) {
	trust, p, key := fixture()
	for _, tc := range []struct {
		name string
		edit func(*Policy)
		code string
	}{
		{"host", func(p *Policy) { p.HostID = "other" }, "policy_host_mismatch"},
		{"enrollment", func(p *Policy) { p.EnrollmentID = "other" }, "policy_host_mismatch"},
		{"version", func(p *Policy) { p.Version = "sash/1" }, "policy_bad_shape"},
		{"zero_sequence", func(p *Policy) { p.Sequence = 0 }, "policy_bad_shape"},
		{"unsafe_integer", func(p *Policy) { p.Sequence = 1 << 53 }, "policy_bad_shape"},
		{"too_long", func(p *Policy) { p.OfflineUntil++ }, "policy_ceiling"},
		{"bad_interval", func(p *Policy) { p.NotBefore = p.ExpiresAt }, "policy_bad_shape"},
		{"wildcard", func(p *Policy) { p.Jobs[0].Scopes[0].Resource = "*" }, "policy_bad_shape"},
		{"unknown_verb", func(p *Policy) { p.Jobs[0].Scopes[0].Operation = "shell.exec" }, "policy_bad_shape"},
		{"nil_array", func(p *Policy) { p.OfflineUnits = nil }, "policy_bad_shape"},
		{"offline_not_closed", func(p *Policy) { p.OfflineUnits = []string{"agent"} }, "policy_bad_shape"},
		{"offline_job_scope", func(p *Policy) { p.OfflineUnits = []string{} }, "policy_bad_shape"},
		{"cycle", func(p *Policy) { p.Units[0].Needs = []string{"agent"} }, "policy_bad_shape"},
		{"unknown_dependency", func(p *Policy) { p.Units[0].Needs = []string{"missing"} }, "policy_bad_shape"},
		{"duplicate_scope", func(p *Policy) { p.Jobs[0].Scopes = append(p.Jobs[0].Scopes, p.Jobs[0].Scopes[0]) }, "policy_bad_shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, p, _ := fixture()
			tc.edit(&p)
			_, err := Verify(signed(p, key), trust)
			requireCode(t, err, tc.code)
		})
	}
	payload, _ := json.Marshal(p)
	for _, raw := range [][]byte{
		bytes.Replace(payload, []byte(`"id":"boot-agent"`), []byte(`"id":"boot-agent","id":"evil"`), 1),
		bytes.Replace(payload, []byte(`"version":`), []byte(`"unknown":1,"version":`), 1),
		bytes.Replace(payload, []byte(`"sequence":1`), []byte(`"sequence":1.0`), 1),
		append(payload, []byte(`{}`)...),
		bytes.Replace(payload, []byte(`"runtime_restart_units":[],`), nil, 1),
	} {
		_, err := Verify(signPayload(raw, key, Domain), trust)
		requireCode(t, err, "policy_bad_shape")
	}
	_, err := Verify(signPayload(payload, key, "sash-grant-v1\n"), trust)
	requireCode(t, err, "policy_bad_signature")
	altered := append([]byte(nil), payload...)
	altered[0] = '['
	var env envelope
	json.Unmarshal(signed(p, key), &env)
	env.Payload = base64.StdEncoding.EncodeToString(altered)
	raw, _ := json.Marshal(env)
	_, err = Verify(raw, trust)
	requireCode(t, err, "policy_bad_signature")
	env.KeyID = "unknown"
	raw, _ = json.Marshal(env)
	_, err = Verify(raw, trust)
	requireCode(t, err, "policy_bad_signature")
	_, err = Verify(bytes.Repeat([]byte{' '}, MaxEnvelope+1), trust)
	requireCode(t, err, "policy_bad_shape")
}

func TestStateBoundaries(t *testing.T) {
	trust, p, key := fixture()
	d, err := Verify(signed(p, key), trust)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		now   int64
		state State
	}{{p.NotBefore - 1, NotYetValid}, {p.NotBefore, Valid}, {p.ExpiresAt - 1, Valid}, {p.ExpiresAt, Grace}, {p.OfflineUntil - 1, Grace}, {p.OfflineUntil, Expired}} {
		if got := d.State(fixed(tc.now)); got != tc.state {
			t.Fatalf("%d: %s want %s", tc.now, got, tc.state)
		}
	}
	if d.State(nil) != ClockUncertain {
		t.Fatal("implicit clock trust")
	}
	requireCode(t, d.CheckFresh(fixed(p.ExpiresAt)), "policy_expired")
	requireCode(t, d.CheckFresh(nil), "policy_clock_uncertain")
}

func TestClockSuspendAndRollback(t *testing.T) {
	elapsed := time.Second
	c := NewClockWithElapsed(time.Unix(1000, 0), func() (time.Duration, error) { return elapsed, nil })
	elapsed += 48 * time.Hour // Suspend-inclusive elapsed time.
	now, ok := c.Now()
	if !ok || now.Unix() != 1000+48*3600 {
		t.Fatal(now, ok)
	}
	requireCode(t, c.Advance(time.Unix(1000, 0)), "policy_clock_rollback")
	if err := c.Advance(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	later, _ := c.Now()
	if !later.Equal(now.Add(time.Hour)) {
		t.Fatal(later)
	}
	elapsed = 0
	if _, ok := c.Now(); ok {
		t.Fatal("elapsed rollback trusted")
	}
	elapsed = 100 * time.Hour
	if _, ok := c.Now(); ok {
		t.Fatal("confidence silently restored")
	}
}

func newStore(t *testing.T, trust Trust, clock Clock) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path, trust, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}
