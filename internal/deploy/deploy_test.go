// SPDX-License-Identifier: GPL-3.0-or-later

package deploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/fail"
)

type fixture struct {
	m        *Manager
	p        bootpolicy.Policy
	key      ed25519.PrivateKey
	bundle   string
	manifest []byte
	now      *int64
}

func setup(t *testing.T) fixture {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := bootpolicy.Trust{TenantID: "t", HostID: "h", EnrollmentID: "e", RecoveryProfileID: "r", Keys: map[string]string{"test": base64.StdEncoding.EncodeToString(pub)}, MaxValiditySeconds: 1000, MaxGraceSeconds: 1000, MaxJobSeconds: 60, MinRefreshSeconds: 30, MaxRefreshSeconds: 60, MaxLifetime: bootpolicy.LifetimeNever}
	root := t.TempDir()
	os.Chmod(root, 0700)
	now := int64(1800000000)
	m, err := Open(root, trust, bootpolicy.ClockFunc(func() (time.Time, bool) { return time.Unix(now, 0), true }))
	if err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	os.Chmod(bundle, 0700)
	os.Mkdir(filepath.Join(bundle, "units"), 0700)
	os.Mkdir(filepath.Join(bundle, "artifacts"), 0700)
	binary := []byte("fixture executable bytes\n")
	u := []byte(`{"name":"app","type":"simple","ready":"exec","exec":["@/artifacts/app"],"boot":true,"essential":true}`)
	os.WriteFile(filepath.Join(bundle, "units/app.json"), u, 0600)
	os.WriteFile(filepath.Join(bundle, "artifacts/app"), binary, 0600)
	raw, _ := json.Marshal(Manifest{Resources: []json.RawMessage{}, Version: "sahinit-catalog/1", Units: []File{{"units/app.json", Hash(u)}}, Artifacts: []File{{"artifacts/app", Hash(binary)}}, Jobs: []File{}})
	p := bootpolicy.Policy{Version: bootpolicy.Version2, Lifetime: bootpolicy.LifetimeRenew, TenantID: "t", HostID: "h", EnrollmentID: "e", RecoveryProfileID: "r", PolicyID: "standard", Sequence: 1, CatalogGeneration: 1, IssuedAt: now, NotBefore: now, ExpiresAt: now + 100, OfflineUntil: now + 200, RefreshAfterSeconds: 30, CatalogSHA256: Hash(raw), Units: []bootpolicy.Unit{{ID: "app", Needs: []string{}}}, Jobs: []bootpolicy.Job{}, OfflineUnits: []string{}, OfflineJobs: []string{}, RuntimeRestartUnits: []string{"app"}}
	return fixture{m, p, key, bundle, raw, &now}
}
func (f fixture) sign() []byte {
	raw, _ := json.Marshal(f.p)
	sig := ed25519.Sign(f.key, append([]byte(bootpolicy.Domain), raw...))
	b, _ := json.Marshal(map[string]string{"key_id": "test", "payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(sig)})
	return b
}
func (f fixture) stage(t *testing.T) *Catalog {
	t.Helper()
	c, err := f.m.Stage(f.sign(), f.manifest, f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestPendingDoesNotRenewActive(t *testing.T) {
	f := setup(t)
	old := f.stage(t)
	st, _ := f.m.State()
	if st.Active != "" || st.Pending != old.ID {
		t.Fatal(st)
	}
	lock, err := f.m.Lock()
	if err != nil {
		t.Fatal(err)
	}
	err = f.m.CommitActive(old.ID)
	lock.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.p.Sequence++
	f.p.ExpiresAt += 100
	f.p.OfflineUntil += 100
	pending := f.stage(t)
	st, _ = f.m.State()
	if st.Active != old.ID || st.Pending != pending.ID {
		t.Fatal(st)
	}
	*f.now += 150
	if err := f.m.Admit(old, "app", false); fail.Token(err) != "policy_unit_denied" {
		t.Fatal(err)
	}
	if err := f.m.Admit(pending, "app", false); err != nil {
		t.Fatal(err)
	}
	*f.now += 100
	if err := f.m.Admit(old, "app", true); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Admit(old, "app", false); err == nil {
		t.Fatal("expired manual start allowed")
	}
	f.p.Sequence = 1
	if _, err := f.m.Stage(f.sign(), f.manifest, f.bundle); err == nil {
		t.Fatal("rollback allowed")
	}
}
func TestBundleVerification(t *testing.T) {
	for _, tc := range []string{"signature", "manifest", "artifact", "dependencies", "duplicate", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			f := setup(t)
			switch tc {
			case "signature":
				_, f.key, _ = ed25519.GenerateKey(rand.Reader)
			case "manifest":
				f.manifest = append(f.manifest, ' ')
			case "artifact":
				os.WriteFile(filepath.Join(f.bundle, "artifacts/app"), []byte("tampered"), 0600)
			case "dependencies":
				f.p.Units[0].ID = "other"
			case "duplicate":
				u := []byte(`{"name":"app","type":"simple","ready":"exec","exec":["@/artifacts/app"],"boot":true,"boot":false}`)
				os.WriteFile(filepath.Join(f.bundle, "units/app.json"), u, 0600)
				var m Manifest
				json.Unmarshal(f.manifest, &m)
				m.Units[0].SHA256 = Hash(u)
				f.manifest, _ = json.Marshal(m)
				f.p.CatalogSHA256 = Hash(f.manifest)
			case "symlink":
				os.Rename(filepath.Join(f.bundle, "artifacts/app"), filepath.Join(f.bundle, "artifacts/real"))
				os.Symlink("real", filepath.Join(f.bundle, "artifacts/app"))
			}
			if _, err := f.m.Stage(f.sign(), f.manifest, f.bundle); err == nil {
				t.Fatal("accepted invalid bundle")
			}
			st, _ := f.m.State()
			if st.Active != "" || st.Pending != "" {
				t.Fatal(st)
			}
		})
	}
}
func TestLoadRechecksBytesAndIdentity(t *testing.T) {
	f := setup(t)
	c := f.stage(t)
	if c.Units["app"].SHA256 == "" {
		t.Fatal("unbound executable")
	}
	path := filepath.Join(c.Dir, "artifacts/app")
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte("tampered"), 0500)
	if _, err := f.m.Load(c.ID); fail.Token(err) != "artifact_digest" {
		t.Fatal(err)
	}
}
func TestNeverAndLock(t *testing.T) {
	f := setup(t)
	f.p.Lifetime = bootpolicy.LifetimeNever
	f.p.ExpiresAt = 0
	f.p.OfflineUntil = 0
	f.p.RefreshAfterSeconds = 0
	f.m.Clock = bootpolicy.ClockFunc(func() (time.Time, bool) { return time.Time{}, false })
	c := f.stage(t)
	if err := f.m.Admit(c, "app", false); err != nil {
		t.Fatal(err)
	}
	lock, err := f.m.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := f.m.Stage(f.sign(), f.manifest, f.bundle); fail.Token(err) != "deployment_busy" {
		t.Fatal(err)
	}
}

func (f fixture) signFloor(min uint64) []byte {
	raw, _ := json.Marshal(bootpolicy.Floor{Version: bootpolicy.FloorVersion, TenantID: "t", HostID: "h", EnrollmentID: "e", MinSequence: min, IssuedAt: *f.now})
	sig := ed25519.Sign(f.key, append([]byte(bootpolicy.FloorDomain), raw...))
	b, _ := json.Marshal(map[string]string{"key_id": "test", "payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(sig)})
	return b
}

// A floor installed after a generation was staged refuses its admission,
// for a first start and for an automatic restart alike.
func TestAdmitRefusesBelowFloor(t *testing.T) {
	f := setup(t)
	c := f.stage(t)
	if err := f.m.Admit(c, "app", false); err != nil {
		t.Fatal(err)
	}
	store, err := bootpolicy.OpenStore(filepath.Join(f.m.Root, "policy"), f.m.Trust, f.m.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.InstallFloor(f.signFloor(2)); err != nil {
		t.Fatal(err)
	}
	store.Close()
	for _, restart := range []bool{false, true} {
		if err := f.m.Admit(c, "app", restart); fail.Token(err) != "policy_revoked" {
			t.Fatalf("restart=%v: %v", restart, err)
		}
	}
}

// Boot jobs, resources and sash units are refused: deployments carry exec
// units only.
func TestJobsAndSashRefused(t *testing.T) {
	for _, tc := range []string{"policy_jobs", "manifest_jobs", "resources", "sash"} {
		t.Run(tc, func(t *testing.T) {
			f := setup(t)
			var m Manifest
			json.Unmarshal(f.manifest, &m)
			want := "deployment_jobs"
			switch tc {
			case "policy_jobs":
				f.p.Jobs = []bootpolicy.Job{{ID: "storage", ScriptSHA256: Hash([]byte("x")), Scopes: []bootpolicy.Scope{{Operation: "unit.start", Resource: "app"}}, Phases: []string{"boot"}, TimeoutSeconds: 30, NeedsUnits: []string{"app"}, NeedsJobs: []string{}}}
			case "manifest_jobs":
				m.Jobs = []File{{"jobs/storage.sash", Hash([]byte("x"))}}
			case "resources":
				m.Resources = []json.RawMessage{json.RawMessage(`{"id":"data","operation":"mount.ensure","arguments":[]}`)}
				// The strict decoder refuses any element before the
				// emptiness check.
				want = "policy_bad_shape"
			case "sash":
				u := []byte(`{"name":"app","sash":{"file":"/etc/app.sash","grant":"/etc/app.grant"},"exec":["@/artifacts/app"]}`)
				os.WriteFile(filepath.Join(f.bundle, "units/app.json"), u, 0600)
				m.Units[0].SHA256 = Hash(u)
				want = "deployment_sash"
			}
			f.manifest, _ = json.Marshal(m)
			f.p.CatalogSHA256 = Hash(f.manifest)
			if _, err := f.m.Stage(f.sign(), f.manifest, f.bundle); fail.Token(err) != want {
				t.Fatalf("got %v want %s", err, want)
			}
		})
	}
}

// exec[0] must be the @/ form naming a manifest artifact; a bare bundle path
// to the same artifact is refused, as is an absolute host path.
func TestExecNeedsArtifactPrefix(t *testing.T) {
	for _, exec := range []string{"artifacts/app", "/bin/true"} {
		f := setup(t)
		u := []byte(`{"name":"app","type":"simple","ready":"exec","exec":["` + exec + `"],"boot":true}`)
		os.WriteFile(filepath.Join(f.bundle, "units/app.json"), u, 0600)
		var m Manifest
		json.Unmarshal(f.manifest, &m)
		m.Units[0].SHA256 = Hash(u)
		f.manifest, _ = json.Marshal(m)
		f.p.CatalogSHA256 = Hash(f.manifest)
		if _, err := f.m.Stage(f.sign(), f.manifest, f.bundle); fail.Token(err) != "manifest_exec" {
			t.Fatalf("%s: %v", exec, err)
		}
	}
}
