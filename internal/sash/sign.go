// SPDX-License-Identifier: GPL-3.0-or-later

package sash

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// SignGrant returns g as a signed sash/2 (or, for V "sash/3", sash/3)
// document. It is for tests and fixtures: sahinit never holds a fleet
// private key.
func SignGrant(g Grant, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fail.E("grant_bad_sig")
	}
	msg, err := Message(g)
	if err != nil {
		return nil, err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	var wire any
	if g.V == "sash/3" {
		var body signedV3
		if err := json.Unmarshal(msg[len(grantDomainV3):], &body); err != nil {
			return nil, fail.E("grant_bad_shape")
		}
		wire = wireV3{signedV3: body, Sig: sig}
	} else {
		var body signedV2
		if err := json.Unmarshal(msg[len(grantDomain):], &body); err != nil {
			return nil, fail.E("grant_bad_shape")
		}
		wire = wireV2{signedV2: body, Sig: sig}
	}
	doc, err := json.Marshal(wire)
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

// SampleBootGrant is a valid sash/3 boot grant body for service, user and
// group, for tests: every boot key and the service verbs, no names.
func SampleBootGrant(service, user, group string) Grant {
	g := SampleGrant(service, user, group)
	g.V, g.Actor, g.Purpose = "sash/3", "boot:"+service, PurposeBoot
	g.Entitlements = append(g.Entitlements, "boot.module", "boot.device", "boot.mount", "boot.net", "boot.start", "boot.stop")
	g.Modules, g.Devices, g.HostMounts, g.NetProfiles, g.UnitsStart, g.UnitsStop = []string{}, []string{}, []string{}, []string{}, []string{}, []string{}
	return g
}
