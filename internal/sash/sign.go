// SPDX-License-Identifier: GPL-3.0-or-later

package sash

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// SignGrant returns g as a signed sash/2 document. It is for tests and
// fixtures: sahinit never holds a fleet private key.
func SignGrant(g Grant, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fail.E("grant_bad_sig")
	}
	msg, err := Message(g)
	if err != nil {
		return nil, err
	}
	var body signedV2
	if err := json.Unmarshal(msg[len(grantDomain):], &body); err != nil {
		return nil, fail.E("grant_bad_shape")
	}
	doc, err := json.Marshal(wireV2{signedV2: body, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))})
	if err != nil {
		return nil, fail.E("grant_bad_shape")
	}
	return doc, nil
}

// SampleGrant is a valid sash/2 grant body for service, user and group, for
// tests: every service verb, no files, no exec.
func SampleGrant(service, user, group string) Grant {
	return Grant{
		V: "sash/2", Actor: "service:" + service, Host: "test", Purpose: PurposeService, LeaseID: "boot-" + service,
		Entitlements: []string{"svc.spawn", "svc.signal", "svc.wait", "svc.proc", "svc.status", "svc.probe", "svc.output"},
		FileRead:     []string{}, FileWrite: []string{}, Service: service, Exec: []string{}, Caps: []string{}, Mounts: []string{},
		MountSources: []string{}, User: user, Group: group, EnvNames: []string{}, Serial: 1,
	}
}
