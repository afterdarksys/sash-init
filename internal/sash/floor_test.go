package sash

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func newFloorStore(t *testing.T) (*FloorStore, string, ed25519.PrivateKey) {
	t.Helper()
	priv := testFleet("fleet")
	dir := filepath.Join(t.TempDir(), "floors")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenFloorStore(dir, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir, priv
}

func floorOf(service string, min uint64, at int64) Floor {
	return Floor{Version: FloorVersion, Service: service, MinSerial: min, IssuedAt: at}
}

func TestFloorMonotonicAndAdmit(t *testing.T) {
	s, dir, priv := newFloorStore(t)
	if err := s.Admit("app", 1); err != nil {
		t.Fatalf("no floor: %v", err)
	}
	first := SignFloor(floorOf("app", 5, 100), priv)
	if _, err := s.Install(first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(first); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := s.Admit("app", 4); fail.Token(err) != "sash_grant_revoked" {
		t.Fatalf("below floor: %v", err)
	}
	if err := s.Admit("app", 5); err != nil {
		t.Fatalf("at floor: %v", err)
	}
	if err := s.Admit("other", 1); err != nil {
		t.Fatalf("another service: %v", err)
	}
	if _, err := s.Install(SignFloor(floorOf("app", 4, 200), priv)); fail.Token(err) != "sash_floor_rollback" {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := s.Install(SignFloor(floorOf("app", 5, 200), priv)); fail.Token(err) != "sash_floor_conflict" {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := s.Install(SignFloor(floorOf("app", 9, 300), priv)); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit("app", 8); fail.Token(err) != "sash_grant_revoked" {
		t.Fatalf("raised floor: %v", err)
	}
	names, err := s.Services()
	if err != nil || strings.Join(names, ",") != "app" {
		t.Fatalf("services %v %v", names, err)
	}
	// Reopened, the floor holds.
	s2, err := OpenFloorStore(dir, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Admit("app", 8); fail.Token(err) != "sash_grant_revoked" {
		t.Fatalf("reopened: %v", err)
	}
}

func TestFloorRefusals(t *testing.T) {
	s, dir, priv := newFloorStore(t)
	other := testFleet("other")
	if _, err := s.Install(SignFloor(floorOf("app", 2, 100), other)); fail.Token(err) != "sash_floor_bad_signature" {
		t.Fatalf("other key: %v", err)
	}
	for name, f := range map[string]Floor{
		"version": {Version: "sahinit-boot-floor/1", Service: "app", MinSerial: 2, IssuedAt: 1},
		"name":    floorOf("App", 2, 1),
		"zero":    floorOf("app", 0, 1),
		"issued":  floorOf("app", 2, 0),
	} {
		if _, err := s.Install(SignFloor(f, priv)); fail.Token(err) != "sash_floor_bad_shape" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The boot-policy floor's domain is not this one: the same payload
	// signed under it does not verify.
	good := SignFloor(floorOf("app", 2, 1), priv)
	if _, err := VerifyFloor([]byte(strings.Replace(string(good), `"payload"`, `"payload" `, 1)+" x"), priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("trailing data accepted")
	}
	// A corrupt floor fails closed: Admit refuses rather than admitting.
	if err := os.WriteFile(filepath.Join(dir, "app.floor"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit("app", 100); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := s.Install(good); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("corrupt replaced: %v", err)
	}
	// A floor file for another service under this name fails closed.
	if err := os.WriteFile(filepath.Join(dir, "app.floor"), SignFloor(floorOf("web", 2, 1), priv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit("app", 100); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("renamed floor: %v", err)
	}
	// A group-readable floor file fails closed.
	if err := os.WriteFile(filepath.Join(dir, "app.floor"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "app.floor"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit("app", 100); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("unsafe mode: %v", err)
	}
}

func TestFloorStoreDirAndCommitFailure(t *testing.T) {
	priv := testFleet("fleet")
	pub := priv.Public().(ed25519.PublicKey)
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFloorStore(dir, pub); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("group-readable dir: %v", err)
	}
	s, _, priv := newFloorStore(t)
	s.checkpoint = func(stage string) error {
		if stage == "renamed" {
			return errors.New("crash")
		}
		return nil
	}
	if _, err := s.Install(SignFloor(floorOf("app", 3, 1), priv)); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("ambiguous commit: %v", err)
	}
	if err := s.Admit("app", 1); fail.Token(err) != "sash_floor_store_failed" {
		t.Fatalf("store not failed closed: %v", err)
	}
}

// testdata/sash-floor-vectors.json is the floor's golden vector for a fleet
// signer (a systemapi.io job): the deterministic key below, the signed
// bytes, and what sahinit answers. Regenerate with -update-floor.
var updateFloor = flag.Bool("update-floor", false, "regenerate testdata/sash-floor-vectors.json")

func TestFloorGoldenVector(t *testing.T) {
	priv := testFleet("sahinit sash golden fleet key")
	pub := priv.Public().(ed25519.PublicKey)
	type vector struct {
		Name string `json:"name"`
		Doc  string `json:"doc"`
		Want string `json:"want"`
	}
	answer := func(doc []byte) string {
		if _, err := VerifyFloor(doc, pub); err != nil {
			return fail.Token(err)
		}
		return "ok"
	}
	good := SignFloor(floorOf("nginx", 7, 1_700_000_000), priv)
	other := SignFloor(floorOf("nginx", 7, 1_700_000_000), testFleet("sahinit sash golden other key"))
	var vecs []vector
	for _, v := range []struct {
		name string
		doc  []byte
	}{{"valid", good}, {"other_key", other}} {
		vecs = append(vecs, vector{v.name, string(v.doc), answer(v.doc)})
	}
	doc := map[string]any{
		"source":    "sahinit internal/sash TestFloorGoldenVector; the fleet key is sash's golden fleet key (sash-grant-vectors.json)",
		"domain":    FloorDomain,
		"fleet_pub": hex.EncodeToString(pub),
		"vectors":   vecs,
	}
	want, _ := json.MarshalIndent(doc, "", "  ")
	want = append(want, '\n')
	const p = "testdata/sash-floor-vectors.json"
	if *updateFloor {
		if err := os.WriteFile(p, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(want) {
		t.Fatalf("floor vector changed (%v); regenerate with -update-floor only for a deliberate format change", err)
	}
	if hex.EncodeToString(pub) != loadVectors(t).FleetPub {
		t.Fatal("floor vector key is not sash's golden fleet key")
	}
}
