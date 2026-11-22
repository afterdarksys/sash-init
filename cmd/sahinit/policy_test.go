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
