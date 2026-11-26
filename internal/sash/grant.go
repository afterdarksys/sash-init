// SPDX-License-Identifier: GPL-3.0-or-later

// Package sash is sahinit's side of running sash services
// (docs/design/sash-services-1.md): the sash/2 boot grant, the signed
// per-service floor, the verb frames, the describe document and the verb
// checks. It does not import sash; every rule it shares with sash is pinned
// by a golden vector copied from the sash repository.
package sash

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Threats: a forged, swapped or edited grant; a sash/1 grant or a v1-domain
// signature presented as sash/2; a grant for another service, another
// identity, or below the service's floor; a "*"; an expired exp; a relative,
// unclean or "/" root; an oversized document. sahinit verifies the grant
// file itself before every start, with the fleet key only (a service has no
// emergency path), and never trusts that sash checked it. The signed
// message is sash's exactly (internal/grant/verify.go): the domain
// "sash-grant-v2\n", then the sash/1 fields and the sash/2 fields in the
// contract's order, as Go's encoding/json writes them; the golden vector in
// testdata pins it. Does NOT hold a private key and does NOT check host:
// sahinit has no host name in batch 1.

const (
	// MaxGrant is the largest grant sahinit reads, as sash's MaxDocument.
	MaxGrant       = 64 * 1024
	PurposeService = "service"
	grantDomain    = "sash-grant-v2\n"
	// GrantVersion is the one grant version ("v") sahinit accepts.
	GrantVersion = "sash/2"
)

// ServiceName is a service name, in the grant and the service block.
var ServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// UnixName is a user or group name.
var UnixName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var (
	mountName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	capName   = regexp.MustCompile(`^CAP_[A-Z0-9_]{1,32}$`)
)

// Grant is a verified sash/2 boot grant.
type Grant struct {
	V            string
	Actor        string
	Host         string
	Purpose      string
	Exp          int64
	LeaseID      string
	Entitlements []string
	FileRead     []string
	FileWrite    []string
	AllowPrivate bool
	Service      string
	Exec         []string
	Caps         []string
	Mounts       []string
	MountSources []string
	User         string
	Group        string
	EnvNames     []string
	Serial       uint64
}

type signedV1 struct {
	V            string   `json:"v"`
	Actor        string   `json:"actor"`
	Host         string   `json:"host"`
	Purpose      string   `json:"purpose"`
	Exp          int64    `json:"exp"`
	LeaseID      string   `json:"lease_id"`
	Entitlements []string `json:"entitlements"`
	FileRead     []string `json:"file_read"`
	FileWrite    []string `json:"file_write"`
	AllowPrivate bool     `json:"allow_private"`
}

type signedV2 struct {
	signedV1
	Service      string   `json:"service"`
	Exec         []string `json:"exec"`
	Caps         []string `json:"caps"`
	Mounts       []string `json:"mounts"`
	MountSources []string `json:"mount_sources"`
	User         string   `json:"user"`
	Group        string   `json:"group"`
	EnvNames     []string `json:"env_names"`
	Serial       uint64   `json:"serial"`
}

type wireV2 struct {
	signedV2
	Sig string `json:"sig"`
}

func norm(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Message is the exact byte string the fleet key signs for g.
func Message(g Grant) ([]byte, error) {
	body, err := json.Marshal(signedV2{
		signedV1: signedV1{V: g.V, Actor: g.Actor, Host: g.Host, Purpose: g.Purpose, Exp: g.Exp, LeaseID: g.LeaseID,
			Entitlements: norm(g.Entitlements), FileRead: norm(g.FileRead), FileWrite: norm(g.FileWrite), AllowPrivate: g.AllowPrivate},
		Service: g.Service, Exec: norm(g.Exec), Caps: norm(g.Caps), Mounts: norm(g.Mounts), MountSources: norm(g.MountSources),
		User: g.User, Group: g.Group, EnvNames: norm(g.EnvNames), Serial: g.Serial,
	})
	if err != nil {
		return nil, fail.E("grant_bad_shape")
	}
	return append([]byte(grantDomain), body...), nil
}

// VerifyGrant checks doc as a sash/2 service grant signed by fleet. now is
// the caller's clock in Unix seconds. Tokens are sash's: grant_missing,
// grant_bad_shape, grant_bad_sig, grant_star, grant_expired,
// grant_root_slash, grant_exp_zero.
func VerifyGrant(doc []byte, fleet ed25519.PublicKey, now int64) (Grant, error) {
	if len(doc) == 0 {
		return Grant{}, fail.E("grant_missing")
	}
	if len(doc) > MaxGrant {
		return Grant{}, fail.E("grant_bad_shape")
	}
	g, sig, err := parseGrant(doc)
	if err != nil {
		return Grant{}, err
	}
	if len(fleet) != ed25519.PublicKeySize {
		return Grant{}, fail.E("grant_bad_sig")
	}
	raw, decErr := base64.StdEncoding.DecodeString(sig)
	if decErr != nil || len(raw) != ed25519.SignatureSize {
		return Grant{}, fail.E("grant_bad_sig")
	}
	msg, err := Message(g)
	if err != nil || !ed25519.Verify(fleet, msg, raw) {
		return Grant{}, fail.E("grant_bad_sig")
	}
	for _, e := range g.Entitlements {
		if e == "*" {
			return Grant{}, fail.E("grant_star")
		}
	}
	if g.Exp != 0 && g.Exp < now {
		return Grant{}, fail.E("grant_expired")
	}
	return g, nil
}

func parseGrant(doc []byte) (Grant, string, error) {
	bad := func() (Grant, string, error) { return Grant{}, "", fail.E("grant_bad_shape") }
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var w wireV2
	if err := dec.Decode(&w); err != nil {
		return bad()
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return bad()
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doc, &raw); err != nil {
		return bad()
	}
	for _, key := range []string{"v", "actor", "host", "purpose", "exp", "lease_id", "entitlements", "service", "exec", "caps", "mounts", "mount_sources", "user", "group", "env_names", "serial", "sig"} {
		if _, ok := raw[key]; !ok {
			return bad()
		}
	}
	if w.V != GrantVersion || w.Purpose != PurposeService || w.Host == "" || w.LeaseID == "" || w.Sig == "" {
		return bad()
	}
	if !ServiceName.MatchString(w.Service) || w.Actor != "service:"+w.Service || w.Serial < 1 || w.Exp < 0 {
		return bad()
	}
	if w.Entitlements == nil || w.Exec == nil || w.Caps == nil || w.Mounts == nil || w.MountSources == nil || w.EnvNames == nil {
		return bad()
	}
	if !UnixName.MatchString(w.User) || !UnixName.MatchString(w.Group) {
		return bad()
	}
	for _, e := range w.Entitlements {
		if e == "" {
			return bad()
		}
	}
	for _, list := range [][]string{w.FileRead, w.FileWrite, w.Exec, w.Mounts} {
		if err := roots(list); err != nil {
			return Grant{}, "", err
		}
	}
	for _, src := range w.MountSources {
		if mountName.MatchString(src) {
			continue
		}
		if err := roots([]string{src}); err != nil {
			return Grant{}, "", err
		}
	}
	for _, e := range w.EnvNames {
		if !EnvName.MatchString(e) {
			return bad()
		}
	}
	for _, c := range w.Caps {
		if !capName.MatchString(c) {
			return bad()
		}
	}
	cp := func(s []string) []string { return append([]string(nil), s...) }
	return Grant{
		V: w.V, Actor: w.Actor, Host: w.Host, Purpose: w.Purpose, Exp: w.Exp, LeaseID: w.LeaseID,
		Entitlements: cp(w.Entitlements), FileRead: cp(w.FileRead), FileWrite: cp(w.FileWrite), AllowPrivate: w.AllowPrivate,
		Service: w.Service, Exec: cp(w.Exec), Caps: cp(w.Caps), Mounts: cp(w.Mounts), MountSources: cp(w.MountSources),
		User: w.User, Group: w.Group, EnvNames: cp(w.EnvNames), Serial: w.Serial,
	}, w.Sig, nil
}

func roots(list []string) error {
	for _, r := range list {
		if strings.HasPrefix(r, "/") && path.Clean(r) == "/" {
			return fail.E("grant_root_slash")
		}
		if path.Clean(r) != r || !strings.HasPrefix(r, "/") {
			return fail.E("grant_bad_shape")
		}
	}
	return nil
}

// Has reports whether key is listed. A "*" never verifies, so it is not
// considered here.
func (g Grant) Has(key string) bool { return key != "" && exact(g.Entitlements, key) }

// AllowsExec reports whether p is exactly one of the exec programs.
func (g Grant) AllowsExec(p string) bool { return exact(g.Exec, p) }

// AllowsCap reports whether c (CAP_NAME) is listed.
func (g Grant) AllowsCap(c string) bool { return exact(g.Caps, c) }

// AllowsRead reports whether p is at or under a file_read root.
func (g Grant) AllowsRead(p string) bool { return under(g.FileRead, p) }

// AllowsWrite reports whether p is at or under a file_write root.
func (g Grant) AllowsWrite(p string) bool { return under(g.FileWrite, p) }

// AllowsEnv reports whether spawn may set name: it has the form, the grant
// lists it, and it is not on the denylist.
func (g Grant) AllowsEnv(name string) bool {
	return EnvName.MatchString(name) && exact(g.EnvNames, name) && !EnvDenied(name)
}

// RootOf is the file_read or file_write root p lies at or under, or "".
func RootOf(roots []string, p string) string {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return ""
	}
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return r
		}
	}
	return ""
}

func exact(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func under(roots []string, p string) bool { return RootOf(roots, p) != "" }
