package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
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
