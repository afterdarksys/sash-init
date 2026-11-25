// SPDX-License-Identifier: GPL-3.0-or-later

package sash

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// testdata/sash-grant-v3-vectors.json is a byte copy of sash's
// internal/grant/testdata/sash-grant-v3-vectors.json (sash-grant-v3-vectors/1)
// at 23a6672 on feat/boot-verbs. Fixed test keys: the fleet seed is 32*0x01,
// emergency 32*0x02, the wrong key 32*0x03.
type v3Vectors struct {
	V        string `json:"v"`
	FleetPub string `json:"fleet_pub"`
	EmergPub string `json:"emergency_pub"`
	Now      int64  `json:"now"`
	Cases    []struct {
		Name    string `json:"name"`
		Doc     string `json:"doc"`
		Want    string `json:"want"`
		Message string `json:"message"`
	} `json:"cases"`
}

func loadV3(t *testing.T) v3Vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/sash-grant-v3-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v v3Vectors
	if err := json.Unmarshal(raw, &v); err != nil || v.V != "sash-grant-v3-vectors/1" || len(v.Cases) == 0 {
		t.Fatalf("v3 vectors: %v", err)
	}
	return v
}

func seedKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

// Every sash case verifies here to sash's token, and both ways for a valid
// one: its exact signed bytes are Message's, and SignGrant with the test
// fleet seed writes sash's document byte for byte.
func TestGrantV3Vectors(t *testing.T) {
	v := loadV3(t)
	fleet := seedKey(1)
	if base64.StdEncoding.EncodeToString(fleet.Public().(ed25519.PublicKey)) != v.FleetPub {
		t.Fatal("the fleet seed is not the vectors' fleet key")
	}
	valid := 0
	for _, c := range v.Cases {
		g, err := VerifyGrant([]byte(c.Doc), fleet.Public().(ed25519.PublicKey), v.Now)
		got := ""
		if err != nil {
			got = fail.Token(err)
		}
		if got != c.Want {
			t.Errorf("%s: %q, sash says %q", c.Name, got, c.Want)
			continue
		}
		if c.Want != "" {
			continue
		}
		valid++
		if !g.BootOps() {
			t.Errorf("%s: not a boot grant", c.Name)
		}
		msg, err := Message(g)
		if err != nil || string(msg) != c.Message {
			t.Errorf("%s: message differs from sash's:\n%s\n%s", c.Name, msg, c.Message)
		}
		doc, err := SignGrant(g, fleet)
		if err != nil || string(doc) != c.Doc {
			t.Errorf("%s: signed document differs from sash's:\n%s\n%s", c.Name, doc, c.Doc)
		}
	}
	if valid < 2 {
		t.Fatalf("%d valid cases", valid)
	}
}

// The emergency key never verifies a boot grant here: sahinit holds the
// fleet key only.
func TestGrantV3EmergencyKeyRefused(t *testing.T) {
	v := loadV3(t)
	emerg, err := base64.StdEncoding.DecodeString(v.EmergPub)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		if c.Name != "valid" {
			continue
		}
		if _, err := VerifyGrant([]byte(c.Doc), emerg, v.Now); fail.Token(err) != "grant_bad_sig" {
			t.Fatalf("emergency key: %v", err)
		}
	}
}

func TestGrantV2RefusesEnsureSource(t *testing.T) {
	fleet := seedKey(1)
	g := SampleGrant("app", "app", "app")
	g.MountSources = []string{"ensure"}
	doc, err := SignGrant(g, fleet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGrant(doc, fleet.Public().(ed25519.PublicKey), 1); fail.Token(err) != "grant_bad_shape" {
		t.Fatalf("sash/2 ensure: %v", err)
	}
	g.MountSources = []string{"tmpfs"}
	doc, _ = SignGrant(g, fleet)
	if _, err := VerifyGrant(doc, fleet.Public().(ed25519.PublicKey), 1); err != nil {
		t.Fatalf("sash/2 tmpfs: %v", err)
	}
}

func TestSampleBootGrantVerifies(t *testing.T) {
	fleet := seedKey(1)
	doc, err := SignGrant(SampleBootGrant("hostprep", "hostprep", "hostprep"), fleet)
	if err != nil {
		t.Fatal(err)
	}
	g, err := VerifyGrant(doc, fleet.Public().(ed25519.PublicKey), 1)
	if err != nil || !g.BootOps() || !g.Has("boot.module") {
		t.Fatalf("%+v %v", g, err)
	}
	if SampleGrant("a", "a", "a").BootOps() {
		t.Fatal("sash/2 is not a boot grant")
	}
}
