package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func fleetKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("cmd fleet"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func writeKey(t *testing.T, dir string, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "fleet.pub")
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadFleetPub(t *testing.T) {
	dir := t.TempDir()
	pub := fleetKey().Public().(ed25519.PublicKey)
	for name, body := range map[string][]byte{"raw": pub, "hex": []byte(hex.EncodeToString(pub)), "hex newline": []byte(hex.EncodeToString(pub) + "\n")} {
		k, err := readFleetPub(writeKey(t, dir, body, 0o644))
		if err != nil || !bytes.Equal(k, pub) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"short":          {pub[:31], 0o644},
		"long":           {append(append([]byte{}, pub...), 0), 0o644},
		"bad hex":        {[]byte(strings.Repeat("z", 64)), 0o644},
		"group-writable": {pub, 0o664},
		"other-writable": {pub, 0o646},
	} {
		if _, err := readFleetPub(writeKey(t, dir, c.body, c.mode)); fail.Token(err) != "sash_fleet_key" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := readFleetPub(filepath.Join(dir, "missing")); fail.Token(err) != "sash_fleet_key" {
		t.Fatal("missing key")
	}
}

func TestSashFloorCommands(t *testing.T) {
	dir := t.TempDir()
	priv := fleetKey()
	key := writeKey(t, dir, priv.Public().(ed25519.PublicKey), 0o644)
	floors := filepath.Join(dir, "floors")
	if err := os.Mkdir(floors, 0o700); err != nil {
		t.Fatal(err)
	}
	floor := func(min uint64) string {
		p := filepath.Join(dir, "floor.json")
		if err := os.WriteFile(p, sash.SignFloor(sash.Floor{Version: sash.FloorVersion, Service: "app", MinSerial: min, IssuedAt: 100}, priv), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var out, errb bytes.Buffer
	if code := run([]string{"sash", "floor-install", "--dir", floors, "--fleet-pub", key, floor(4)}, &out, &errb); code != 0 || !strings.Contains(out.String(), `"min_serial":4`) || !strings.Contains(out.String(), `"service":"app"`) {
		t.Fatalf("install %d %q %q", code, out.String(), errb.String())
	}
	wantRun(t, []string{"sash", "floor-install", "--dir", floors, "--fleet-pub", key, floor(3)}, 1, "", "sash_floor_rollback\n")
	out.Reset()
	if code := run([]string{"sash", "floor-show", "--dir", floors, "--fleet-pub", key}, &out, &errb); code != 0 || strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `"min_serial":4`) {
		t.Fatalf("show %d %q", code, out.String())
	}
	wantRun(t, []string{"sash", "floor-show", "--dir", floors, "--fleet-pub", key, "web"}, 1, "", "sash_floor_missing web\n")
	wantRun(t, []string{"sash", "floor-install", "--dir", floors, floor(5)}, 2, "", sashUsage)
	wantRun(t, []string{"sash", "floor-burn"}, 2, "", sashUsage)
}

// setupSash refuses every sash unit, by file, when sahinit cannot run them,
// and leaves the rest of the catalog.
func TestSetupSashRefusals(t *testing.T) {
	dir := t.TempDir()
	priv := fleetKey()
	key := writeKey(t, dir, priv.Public().(ed25519.PublicKey), 0o644)
	floors := filepath.Join(dir, "floors")
	if err := os.Mkdir(floors, 0o700); err != nil {
		t.Fatal(err)
	}
	catalog := func() map[string]*unit.Service {
		uid := uint32(990)
		return map[string]*unit.Service{
			"app": {Name: "app", Sash: &unit.Sash{}, Execution: unit.Execution{UID: &uid, GID: &uid}},
			"web": {Name: "web", Exec: []string{"/bin/sh"}},
		}
	}
	for name, c := range map[string]struct {
		f    sashFlags
		want string
	}{
		"binary":   {sashFlags{binary: filepath.Join(dir, "no-sash"), fleetPub: key, floorDir: floors}, "sash_binary"},
		"no key":   {sashFlags{binary: "/bin/sh", floorDir: floors}, "sash_fleet_key"},
		"bad key":  {sashFlags{binary: "/bin/sh", fleetPub: filepath.Join(dir, "nope"), floorDir: floors}, "sash_fleet_key"},
		"no floor": {sashFlags{binary: "/bin/sh", fleetPub: key}, "sash_floor_store"},
		"bad dir":  {sashFlags{binary: "/bin/sh", fleetPub: key, floorDir: dir}, "sash_floor_store"},
		"cgroups":  {sashFlags{binary: "/bin/sh", fleetPub: key, floorDir: floors}, "sash_cgroups"},
	} {
		svcs := catalog()
		var errb bytes.Buffer
		cfg, n := setupSash(c.f, svcs, nil, "/bin/sh", &errb)
		if cfg != nil || n != 1 || errb.String() != c.want+" app.json\n" || svcs["app"] != nil || svcs["web"] == nil {
			t.Errorf("%s: %v %d %q", name, cfg, n, errb.String())
		}
	}
	svcs := map[string]*unit.Service{"web": {Name: "web"}}
	if cfg, n := setupSash(sashFlags{}, svcs, nil, "/bin/sh", &bytes.Buffer{}); cfg != nil || n != 0 || len(svcs) != 1 {
		t.Fatal("no sash unit")
	}
}
