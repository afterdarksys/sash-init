package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/migrate"
)

func TestMigrateCLI(t *testing.T) {
	source := "../../tests/migration/fixtures/systemd"
	var out, stderr bytes.Buffer
	if code := run([]string{"migrate", "--from", "systemd", "--source", source}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, &stderr)
	}
	var r migrate.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Written || r.Units[0].Boot {
		t.Fatalf("unexpected activation: %+v", r)
	}
	dir := filepath.Join(t.TempDir(), "units")
	out.Reset()
	if code := run([]string{"migrate", "--from", "systemd", "--source", source, "--out", dir, "--boot"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, &stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "demo.json")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"migrate", "--from", "systemd", "--source", source, "--out", dir}, &out, &stderr); code != 2 {
		t.Fatalf("existing output exit: %d", code)
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "demo.service"), []byte("[Service]\nExecStart=/bin/true\nUser=nobody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"migrate", "--from", "systemd", "--source", bad}, &out, &stderr); code != 1 {
		t.Fatalf("blocker exit: %d", code)
	}
}
