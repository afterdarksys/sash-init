// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/deploy"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/supervise"
)

type deployFixture struct {
	trust     bootpolicy.Trust
	trustPath string
	key       ed25519.PrivateKey
	dir       string
}

func newDeployFixture(t *testing.T) *deployFixture {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := bootpolicy.Trust{TenantID: "t", HostID: "h", EnrollmentID: "e", RecoveryProfileID: "r", Keys: map[string]string{"test": base64.StdEncoding.EncodeToString(pub)}, MaxValiditySeconds: 1000, MaxGraceSeconds: 1000, MaxJobSeconds: 60, MinRefreshSeconds: 30, MaxRefreshSeconds: 60, MaxLifetime: bootpolicy.LifetimeNever}
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	raw, _ := json.Marshal(trust)
	path := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return &deployFixture{trust, path, key, dir}
}

// bundle writes a one-unit bundle with the given unit JSON fields and a
// signed policy; it returns the bundle dir, manifest and document paths.
func (f *deployFixture) bundle(t *testing.T, name string, units map[string]string, p bootpolicy.Policy) (string, string, string) {
	t.Helper()
	b := filepath.Join(f.dir, name)
	for _, d := range []string{b, b + "/units", b + "/artifacts"} {
		os.Mkdir(d, 0o700)
	}
	art := []byte("#!/bin/sh\nexec /bin/sleep 30\n")
	os.WriteFile(b+"/artifacts/app", art, 0o600)
	var files []deploy.File
	p.Units = nil
	for _, n := range []string{"app", "other"} {
		u, ok := units[n]
		if !ok {
			continue
		}
		os.WriteFile(b+"/units/"+n+".json", []byte(u), 0o600)
		files = append(files, deploy.File{Path: "units/" + n + ".json", SHA256: deploy.Hash([]byte(u))})
		p.Units = append(p.Units, bootpolicy.Unit{ID: n, Needs: []string{}})
	}
	m, _ := json.Marshal(deploy.Manifest{Resources: []json.RawMessage{}, Version: "sahinit-catalog/1", Units: files, Artifacts: []deploy.File{{Path: "artifacts/app", SHA256: deploy.Hash(art)}}, Jobs: []deploy.File{}})
	os.WriteFile(b+"/manifest.json", m, 0o600)
	p.CatalogSHA256 = deploy.Hash(m)
	raw, _ := json.Marshal(p)
	sig := ed25519.Sign(f.key, append([]byte(bootpolicy.Domain), raw...))
	doc, _ := json.Marshal(map[string]string{"key_id": "test", "payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(sig)})
	os.WriteFile(b+"/policy.json", doc, 0o600)
	return b, b + "/manifest.json", b + "/policy.json"
}

func policyFor(seq uint64, now int64) bootpolicy.Policy {
	return bootpolicy.Policy{Version: bootpolicy.Version2, Lifetime: bootpolicy.LifetimeRenew, TenantID: "t", HostID: "h", EnrollmentID: "e", RecoveryProfileID: "r", PolicyID: "standard", Sequence: seq, CatalogGeneration: seq, IssuedAt: now, NotBefore: now, ExpiresAt: now + 100, OfflineUntil: now + 200, RefreshAfterSeconds: 30, Units: []bootpolicy.Unit{{ID: "app", Needs: []string{}}}, Jobs: []bootpolicy.Job{}, OfflineUnits: []string{"app"}, OfflineJobs: []string{}, RuntimeRestartUnits: []string{}}
}

// A deployment unit whose limit the cgroup root cannot apply refuses the
// whole start, as strict boot does.
func TestDeploymentRefusesUnappliedLimit(t *testing.T) {
	f := newDeployFixture(t)
	p := policyFor(1, time.Now().Unix())
	p.Lifetime, p.ExpiresAt, p.OfflineUntil, p.RefreshAfterSeconds = bootpolicy.LifetimeNever, 0, 0, 0
	b, m, d := f.bundle(t, "b1", map[string]string{
		"app":   `{"name":"app","type":"simple","ready":"exec","exec":["@/artifacts/app"],"boot":true,"memory_max":"64M"}`,
		"other": `{"name":"other","type":"simple","ready":"exec","exec":["@/artifacts/app"],"boot":true}`,
	}, p)
	root := filepath.Join(f.dir, "deploy")
	var out, errb strings.Builder
	if code := run([]string{"deploy", "stage", "--root", root, "--trust", f.trustPath, "--bundle", b, "--manifest", m, "--document", d}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	if code := run([]string{"deploy", "bootstrap", "--root", root, "--trust", f.trustPath}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
	sock := privTmp(t) + "/s"
	defer os.Remove(sock)
	// Run in a goroutine so a supervisor that wrongly starts fails the test
	// instead of hanging it.
	var serr strings.Builder
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"supervise", "--deployment-root", root, "--trust", f.trustPath, "--socket", sock, "--no-cgroups"}, io.Discard, &serr)
	}()
	select {
	case code := <-done:
		if code != 2 || !strings.HasSuffix(serr.String(), "boot_refused\n") {
			t.Fatalf("code %d stderr %q", code, serr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the deployment started despite a refused limit")
	}
}

// ctl activate waits for boot, and refuses a pending generation that is no
// longer fresh before anything is admitted or applied.
func TestActivatorBootAndFreshness(t *testing.T) {
	f := newDeployFixture(t)
	now := time.Now().Unix()
	clock := now
	m, err := deploy.Open(filepath.Join(f.dir, "deploy"), f.trust, bootpolicy.ClockFunc(func() (time.Time, bool) { return time.Unix(clock, 0), true }))
	if err != nil {
		t.Fatal(err)
	}
	unitJSON := `{"name":"app","type":"simple","ready":"exec","exec":["@/artifacts/app"],"boot":true}`
	stage := func(name string, seq uint64) *deploy.Catalog {
		b, mf, d := f.bundle(t, name, map[string]string{"app": unitJSON}, policyFor(seq, now))
		raw, _ := os.ReadFile(mf)
		doc, _ := os.ReadFile(d)
		c, err := m.Stage(doc, raw, b)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	active := stage("b1", 1)
	lock, _ := m.Lock()
	if err := m.CommitActive(active.ID); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	pending := stage("b2", 2)
	self, _ := os.Executable()
	sup, err := supervise.New(active.Units, self)
	if err != nil {
		t.Fatal(err)
	}
	activate := activator(m, sup)
	if _, err := activate(context.Background()); fail.Token(err) != "boot_in_progress" {
		t.Fatalf("before boot: %v", err)
	}
	sup.SetBooted(true)
	clock = now + 150 // grace: admission would still pass for app
	if _, err := activate(context.Background()); fail.Token(err) != "policy_expired" {
		t.Fatalf("stale pending: %v", err)
	}
	if st, _ := m.State(); st.Active != active.ID || st.Pending != pending.ID {
		t.Fatalf("pointers moved: %+v", st)
	}
}
