// SPDX-License-Identifier: GPL-3.0-or-later

// A VM fixture generator, never included in the installed init binary. It
// makes a throwaway fleet key in memory and writes, into DIR, the public key,
// the signed sash/2 grants for the boot test's services and a signed floor
// that revokes one of them. The private key is never written: each image
// build gets a new one and it is gone when this exits.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/afterdarksys/sahinit/internal/sash"
)

func grant(service string) sash.Grant {
	g := sash.SampleGrant(service, "nobody", "nogroup")
	g.Exec, g.Serial = []string{"/probe"}, 5
	if service == "svc" {
		g.Entitlements = append(g.Entitlements, "file.write", "fs.mount")
		g.FileWrite = []string{"/srv/svc"}
		g.Mounts = []string{"/mnt/svc"}
		g.MountSources = []string{"tmpfs"}
	}
	return g
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sashfix DIR")
		os.Exit(2)
	}
	dir := os.Args[1]
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	write := func(name string, data []byte, mode os.FileMode) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			panic(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			panic(err)
		}
	}
	write("fleet.pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644)
	for _, service := range []string{"svc", "revoked"} {
		doc, err := sash.SignGrant(grant(service), priv)
		if err != nil {
			panic(err)
		}
		write(service+".grant", doc, 0o600)
	}
	// The grants carry serial 5; this floor puts revoked's at 6.
	write("revoked.floor", sash.SignFloor(sash.Floor{Version: sash.FloorVersion, Service: "revoked", MinSerial: 6, IssuedAt: time.Now().Unix()}, priv), 0o644)
}
