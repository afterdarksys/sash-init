package bootpolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func never(p Policy) Policy {
	p.Version = Version2
	p.Lifetime = LifetimeNever
	p.ExpiresAt, p.OfflineUntil, p.RefreshAfterSeconds = 0, 0, 0
	return p
}
func floorFixture(min uint64) Floor {
	return Floor{Version: FloorVersion, TenantID: "tenant-1", HostID: "host-1", EnrollmentID: "enrollment-1", MinSequence: min, IssuedAt: 1800000000}
}
func signedFloor(f Floor, key ed25519.PrivateKey) []byte {
	raw, _ := json.Marshal(f)
	return signPayload(raw, key, FloorDomain)
}

// Golden vectors shared with scripts/check-boot-policy-vector.mjs.
func TestGoldenLifetimeAndFloor(t *testing.T) {
	trust, p, key := fixture()
	n := never(p)
	nPayload, _ := json.Marshal(n)
	f := floorFixture(2)
	fPayload, _ := json.Marshal(f)
	vectors := map[string][]byte{
		"policy-never.json":        signed(n, key),
		"floor.json":               signedFloor(f, key),
		"floor-wrong-domain.json":  signPayload(fPayload, key, Domain),
		"policy-wrong-domain.json": signPayload(nPayload, key, FloorDomain),
	}
	if os.Getenv("SAHINIT_UPDATE_POLICY_FIXTURES") == "1" {
		for name, b := range vectors {
			if err := os.WriteFile("testdata/"+name, append(b, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for name, v := range map[string]any{"payload-never.json": n, "floor-payload.json": f} {
			b, _ := json.MarshalIndent(v, "", "  ")
			if err := os.WriteFile("testdata/"+name, append(b, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, want := range vectors {
		got, err := os.ReadFile("testdata/" + name)
		if err != nil || !bytes.Equal(bytes.TrimSpace(got), want) {
			t.Fatal(name, "golden signature changed", err)
		}
	}
	d, err := Verify(vectors["policy-never.json"], trust)
	if err != nil || d.Policy().Lifetime != LifetimeNever || d.State(nil) != Valid {
		t.Fatal(d, err)
	}
	fd, err := VerifyFloor(vectors["floor.json"], trust)
	if err != nil || fd.Floor().MinSequence != 2 {
		t.Fatal(fd, err)
	}
	_, err = VerifyFloor(vectors["floor-wrong-domain.json"], trust)
	requireCode(t, err, "policy_bad_signature")
	_, err = Verify(vectors["policy-wrong-domain.json"], trust)
	requireCode(t, err, "policy_bad_signature")
	// Each document type refuses the other's correctly signed envelope.
	_, err = Verify(vectors["floor.json"], trust)
	requireCode(t, err, "policy_bad_signature")
	_, err = VerifyFloor(vectors["policy-never.json"], trust)
	requireCode(t, err, "policy_bad_signature")
	// The version-1 fixture is renew without a lifetime field.
	v1, err := os.ReadFile("testdata/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err = Verify(v1, trust)
	if err != nil || d.Policy().Lifetime != LifetimeRenew || d.State(nil) != ClockUncertain {
		t.Fatal(d, err)
	}
}

func TestNeverIgnoresClock(t *testing.T) {
	trust, p, key := fixture()
	d, err := Verify(signed(never(p), key), trust)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Second
	anchored := NewClockWithElapsed(time.Unix(p.IssuedAt, 0), func() (time.Duration, error) { return elapsed, nil })
	elapsed = 0 // Elapsed time ran backwards: the anchored clock is now untrusted.
	untrusted := ClockFunc(func() (time.Time, bool) { return time.Time{}, false })
	for _, c := range []Clock{nil, untrusted, anchored, fixed(1), fixed(p.IssuedAt - 86400*365), fixed(p.IssuedAt + 100*365*86400), fixed(maxInteger)} {
		if d.State(c) != Valid || d.CheckFresh(c) != nil {
			t.Fatalf("%v: %s", c, d.State(c))
		}
	}
	// The renew form of the same policy does depend on the clock.
	r := p
	r.Version = Version2
	r.Lifetime = LifetimeRenew
	d, err = Verify(signed(r, key), trust)
	if err != nil || d.State(fixed(p.OfflineUntil)) != Expired || d.State(fixed(p.NotBefore-1)) != NotYetValid || d.State(nil) != ClockUncertain {
		t.Fatal(err)
	}
}

func TestLifetimeRejects(t *testing.T) {
	trust, p, key := fixture()
	for _, tc := range []struct {
		name string
		edit func(*Policy)
		code string
	}{
		{"never_expires", func(p *Policy) { p.ExpiresAt = p.IssuedAt + 60 }, "policy_bad_shape"},
		{"never_offline", func(p *Policy) { p.OfflineUntil = p.IssuedAt + 60 }, "policy_bad_shape"},
		{"never_refresh", func(p *Policy) { p.RefreshAfterSeconds = 60 }, "policy_bad_shape"},
		{"never_delayed", func(p *Policy) { p.NotBefore++ }, "policy_bad_shape"},
		{"never_no_issue", func(p *Policy) { p.IssuedAt, p.NotBefore = 0, 0 }, "policy_bad_shape"},
		{"never_unsafe_issue", func(p *Policy) { p.IssuedAt, p.NotBefore = maxInteger+1, maxInteger+1 }, "policy_bad_shape"},
		{"unknown_lifetime", func(p *Policy) { p.Lifetime = "forever" }, "policy_bad_shape"},
		{"renew_times_checked", func(p *Policy) {
			p.Lifetime = LifetimeRenew
			p.ExpiresAt, p.OfflineUntil, p.RefreshAfterSeconds = p.IssuedAt+604801, p.IssuedAt+604801, 21600
		}, "policy_ceiling"},
		{"renew_zero_times", func(p *Policy) { p.Lifetime = LifetimeRenew }, "policy_bad_shape"},
		{"v1_with_lifetime", func(p *Policy) { p.Version = Version }, "policy_bad_shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := never(p)
			tc.edit(&n)
			_, err := Verify(signed(n, key), trust)
			requireCode(t, err, tc.code)
		})
	}
	// Version 2 requires the field, even empty; version 1 refuses it, even renew.
	payload, _ := json.Marshal(never(p))
	for _, raw := range [][]byte{
		bytes.Replace(payload, []byte(`,"lifetime":"never"`), nil, 1),
		bytes.Replace(payload, []byte(`"lifetime":"never"`), []byte(`"lifetime":""`), 1),
		bytes.Replace(payload, []byte(`"lifetime":"never"`), []byte(`"lifetime":"never","lifetime":"never"`), 1),
	} {
		_, err := Verify(signPayload(raw, key, Domain), trust)
		requireCode(t, err, "policy_bad_shape")
	}
	v1, _ := json.Marshal(p)
	withField := bytes.Replace(v1, []byte(`"version":`), []byte(`"lifetime":"renew","version":`), 1)
	_, err := Verify(signPayload(withField, key, Domain), trust)
	requireCode(t, err, "policy_bad_shape")
}

func TestTrustLifetimeCap(t *testing.T) {
	trust, p, key := fixture()
	trust.MaxLifetime = LifetimeRenew
	_, err := Verify(signed(never(p), key), trust)
	requireCode(t, err, "policy_lifetime_cap")
	if _, err := Verify(signed(p, key), trust); err != nil {
		t.Fatal("renew refused under renew cap", err)
	}
	for _, v := range []string{"", "always", "Never"} {
		trust.MaxLifetime = v
		requireCode(t, trust.Validate(), "policy_bad_trust")
	}
	raw, err := os.ReadFile("testdata/trust.json")
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	delete(obj, "max_lifetime")
	old, _ := json.Marshal(obj)
	if got, err := DecodeTrust(old); err != nil || got.MaxLifetime != LifetimeNever {
		t.Fatal("trust without max_lifetime", got.MaxLifetime, err)
	}
	for _, edit := range []func(map[string]any){
		func(m map[string]any) { m["max_lifetime"] = "" },
		func(m map[string]any) { m["max_lifetime"] = "sometimes" },
		func(m map[string]any) { m["max_lifetime"] = 1 },
		func(m map[string]any) { m["max_lifetime"] = "renew"; m["extra"] = "x" },
		func(m map[string]any) { delete(m, "keys") },
	} {
		m := map[string]any{}
		for k, v := range obj {
			m[k] = v
		}
		edit(m)
		b, _ := json.Marshal(m)
		if _, err := DecodeTrust(b); err == nil {
			t.Fatal("accepted", string(b))
		}
	}
	obj["max_lifetime"] = "renew"
	b, _ := json.Marshal(obj)
	if got, err := DecodeTrust(b); err != nil || got.MaxLifetime != LifetimeRenew {
		t.Fatal(got, err)
	}
	// A host whose cap is tightened refuses its cached never-policy.
	trust.MaxLifetime = LifetimeNever
	s, path := newStore(t, trust, nil)
	if _, err := s.Install(signed(never(p), key)); err != nil {
		t.Fatal("never install without clock", err)
	}
	trust.MaxLifetime = LifetimeRenew
	capped, err := OpenStore(path, trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer capped.Close()
	_, err = capped.Load()
	requireCode(t, err, "policy_lifetime_cap")
}

func TestLifetimeRenewalOrdering(t *testing.T) {
	trust, p, key := fixture()
	s, _ := newStore(t, trust, fixed(p.IssuedAt))
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	// Version 1 to version 2 renew at the same generation is a renewal.
	r := p
	r.Version, r.Lifetime, r.Sequence = Version2, LifetimeRenew, 2
	if _, err := s.Install(signed(r, key)); err != nil {
		t.Fatal(err)
	}
	// Switching mode is a permission change: it needs a new generation.
	n := never(p)
	n.Sequence = 3
	_, err := s.Install(signed(n, key))
	requireCode(t, err, "policy_generation_conflict")
	n.CatalogGeneration = 2
	if _, err := s.Install(signed(n, key)); err != nil {
		t.Fatal(err)
	}
	n.Sequence = 4
	n.IssuedAt, n.NotBefore = n.IssuedAt+50, n.NotBefore+50
	if _, err := s.Install(signed(n, key)); err != nil {
		t.Fatal("never renewal at the same generation", err)
	}
	_, err = s.Install(signed(r, key))
	requireCode(t, err, "policy_rollback")
}

func TestFloorRejects(t *testing.T) {
	trust, _, key := fixture()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	good := floorFixture(2)
	for _, tc := range []struct {
		name string
		edit func(*Floor)
		code string
	}{
		{"version", func(f *Floor) { f.Version = Version }, "policy_bad_shape"},
		{"tenant", func(f *Floor) { f.TenantID = "other" }, "policy_host_mismatch"},
		{"host", func(f *Floor) { f.HostID = "other" }, "policy_host_mismatch"},
		{"enrollment", func(f *Floor) { f.EnrollmentID = "other" }, "policy_host_mismatch"},
		{"zero", func(f *Floor) { f.MinSequence = 0 }, "policy_bad_shape"},
		{"unsafe", func(f *Floor) { f.MinSequence = maxInteger + 1 }, "policy_bad_shape"},
		{"no_issue", func(f *Floor) { f.IssuedAt = 0 }, "policy_bad_shape"},
		{"unsafe_issue", func(f *Floor) { f.IssuedAt = maxInteger + 1 }, "policy_bad_shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := good
			tc.edit(&f)
			_, err := VerifyFloor(signedFloor(f, key), trust)
			requireCode(t, err, tc.code)
		})
	}
	payload, _ := json.Marshal(good)
	for _, raw := range [][]byte{
		bytes.Replace(payload, []byte(`"version":`), []byte(`"extra":1,"version":`), 1),
		bytes.Replace(payload, []byte(`,"issued_at":1800000000`), nil, 1),
		bytes.Replace(payload, []byte(`"min_sequence":2`), []byte(`"min_sequence":2,"min_sequence":9`), 1),
		bytes.Replace(payload, []byte(`"min_sequence":2`), []byte(`"min_sequence":2.0`), 1),
	} {
		_, err := VerifyFloor(signPayload(raw, key, FloorDomain), trust)
		requireCode(t, err, "policy_bad_shape")
	}
	for _, raw := range [][]byte{
		signPayload(payload, key, Domain),
		signPayload(payload, key, "sash-grant-v1\n"),
		signPayload(payload, other, FloorDomain),
	} {
		_, err := VerifyFloor(raw, trust)
		requireCode(t, err, "policy_bad_signature")
	}
	// Tampered payload under the original signature.
	var env envelope
	json.Unmarshal(signedFloor(good, key), &env)
	lower := floorFixture(1)
	tampered, _ := json.Marshal(lower)
	env.Payload = base64.StdEncoding.EncodeToString(tampered)
	raw, _ := json.Marshal(env)
	_, err := VerifyFloor(raw, trust)
	requireCode(t, err, "policy_bad_signature")
	env.KeyID = "unknown"
	raw, _ = json.Marshal(env)
	_, err = VerifyFloor(raw, trust)
	requireCode(t, err, "policy_bad_signature")
}

func TestStoreFloor(t *testing.T) {
	trust, p, key := fixture()
	s, path := newStore(t, trust, nil)
	_, err := s.Floor()
	requireCode(t, err, "policy_floor_missing")
	n := never(p)
	if _, err := s.Install(signed(n, key)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InstallFloor(signedFloor(floorFixture(1), key)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err != nil {
		t.Fatal("sequence at the floor refused", err)
	}
	two := signedFloor(floorFixture(2), key)
	if _, err := s.InstallFloor(two); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InstallFloor(two); err != nil {
		t.Fatal("idempotent retry", err)
	}
	_, err = s.Load()
	requireCode(t, err, "policy_revoked")
	_, err = s.Install(signed(n, key))
	requireCode(t, err, "policy_revoked")
	_, err = s.InstallFloor(signedFloor(floorFixture(1), key))
	requireCode(t, err, "policy_floor_rollback")
	changed := floorFixture(2)
	changed.IssuedAt++
	_, err = s.InstallFloor(signedFloor(changed, key))
	requireCode(t, err, "policy_floor_conflict")
	n.Sequence = 2
	if _, err := s.Install(signed(n, key)); err != nil {
		t.Fatal("replacement at the floor", err)
	}
	// The floor survives reopen and still refuses a lower floor and policy.
	reopened, err := OpenStore(path, trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f, err := reopened.Floor()
	if err != nil || f.Floor().MinSequence != 2 {
		t.Fatal(f, err)
	}
	_, err = reopened.InstallFloor(signedFloor(floorFixture(1), key))
	requireCode(t, err, "policy_floor_rollback")
	if _, err := reopened.InstallFloor(signedFloor(floorFixture(5), key)); err != nil {
		t.Fatal(err)
	}
	_, err = reopened.Load()
	requireCode(t, err, "policy_revoked")
	// The floor also applies to renew policies.
	r := p
	r.Sequence = 4
	r.CatalogGeneration = 2
	clocked, err := OpenStore(path, trust, fixed(p.IssuedAt))
	if err != nil {
		t.Fatal(err)
	}
	defer clocked.Close()
	_, err = clocked.Install(signed(r, key))
	requireCode(t, err, "policy_revoked")
}

func TestStoreFloorCorruptAndUnsafe(t *testing.T) {
	trust, p, key := fixture()
	for _, kind := range []string{"corrupt", "wrong_domain", "other_host", "symlink", "public", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			s, path := newStore(t, trust, nil)
			if _, err := s.Install(signed(never(p), key)); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, "floor.json")
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(floorFixture(1))
			otherHost := floorFixture(1)
			otherHost.HostID = "host-2"
			var err error
			switch kind {
			case "corrupt":
				err = os.WriteFile(file, []byte("bad"), 0600)
			case "wrong_domain":
				err = os.WriteFile(file, signPayload(payload, key, Domain), 0600)
			case "other_host":
				err = os.WriteFile(file, signedFloor(otherHost, key), 0600)
			case "symlink":
				err = os.Symlink(target, file)
			case "public":
				err = os.WriteFile(file, signedFloor(floorFixture(1), key), 0644)
			case "fifo":
				makeFIFO(t, file)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Load(); err == nil {
				t.Fatal("loaded past a bad floor")
			}
			if _, err := s.Install(signed(never(p), key)); err == nil {
				t.Fatal("installed past a bad floor")
			}
			if _, err := s.InstallFloor(signedFloor(floorFixture(3), key)); err == nil {
				t.Fatal("bad floor silently replaced")
			}
			if _, err := s.Floor(); err == nil {
				t.Fatal("bad floor shown")
			}
			b, err := os.ReadFile(target)
			if err != nil || string(b) != "untouched" {
				t.Fatal("target modified")
			}
		})
	}
}

func TestStoreFloorFailuresPreserveState(t *testing.T) {
	trust, _, key := fixture()
	for _, stage := range []string{"created", "written", "file_synced", "renamed", "directory_synced"} {
		t.Run(stage, func(t *testing.T) {
			s, path := newStore(t, trust, nil)
			if _, err := s.InstallFloor(signedFloor(floorFixture(1), key)); err != nil {
				t.Fatal(err)
			}
			s.checkpoint = func(got string) error {
				if got == stage {
					return errors.New("injected")
				}
				return nil
			}
			next := signedFloor(floorFixture(2), key)
			_, err := s.InstallFloor(next)
			requireCode(t, err, "policy_store_failed")
			reopened, err := OpenStore(path, trust, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			f, err := reopened.Floor()
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(1)
			if stage == "renamed" || stage == "directory_synced" {
				want = 2
				_, err = s.Floor()
				requireCode(t, err, "policy_store_failed")
			}
			if f.Floor().MinSequence != want {
				t.Fatalf("floor %d, want %d", f.Floor().MinSequence, want)
			}
			if _, err := reopened.InstallFloor(next); err != nil {
				t.Fatal(err)
			}
		})
	}
}
