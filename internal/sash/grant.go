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
// testdata pins it. Does NOT hold a private key and does NOT check a sash/2
// grant's host: sahinit has no host name for it in batch 1.
//
// sash/3 (the boot grant, sash's docs/plans/2026-11-24-sash-boot-verbs-
// contract.md) adds: a sash/1 or sash/2 grant, or a v2-domain signature,
// presented as sash/3 and the reverse (its own domain, "sash-grant-v3\n",
// and purpose boot is sash/3 only); a name list padded past 64 entries, with
// a duplicate, or with an entry that is a path, a file name, an alias or a
// flag; a null list; "ensure" smuggled in as a mount source so mount ensure
// could hide a real mount (refused in sash/2 as well). Every field is
// required. Its host is checked by the supervisor against the trust file's
// host_id (sash_grant_host), not here; sash's v3 vectors in testdata pin the
// message and every refusal.

const (
	// MaxGrant is the largest grant sahinit reads, as sash's MaxDocument.
	MaxGrant       = 64 * 1024
	PurposeService = "service"
	// PurposeBoot is a sash/3 boot grant: the only kind that carries the
	// boot verbs.
	PurposeBoot   = "boot"
	grantDomain   = "sash-grant-v2\n"
	grantDomainV3 = "sash-grant-v3\n"
	// MaxBootList is the most entries one sash/3 name list may hold.
	MaxBootList = 64
	// mountSourceEnsure is never a mount source: a mount stage whose second
	// word is ensure is always mount ensure.
	mountSourceEnsure = "ensure"
)

// ServiceName is a service name, in the grant and the service block.
var ServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// UnixName is a user or group name.
var UnixName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// The sash/3 name grammars, as sash's. None holds "/", "." or a leading
// "-", so no name can be a path, a file name or a flag.
var (
	// ModuleName is the kernel's canonical spelling: "_", never "-".
	ModuleName = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,54}$`)
	// BootName is a device, host mount or network profile name.
	BootName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	// UnitName is a unit name, as the catalog's.
	UnitName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

var (
	mountName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	capName   = regexp.MustCompile(`^CAP_[A-Z0-9_]{1,32}$`)
)

// Grant is a verified sash/2 service grant or sash/3 boot grant.
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
	// The sash/3 lists: the names the boot verbs may use. Empty in sash/2.
	Modules     []string
	Devices     []string
	HostMounts  []string
	NetProfiles []string
	UnitsStart  []string
	UnitsStop   []string
	Serial      uint64
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

// signedV3 is every sash/2 field but serial, then the six boot lists, then
// serial last, in the order sash's contract fixes.
type signedV3 struct {
	signedV1
	Service      string   `json:"service"`
	Exec         []string `json:"exec"`
	Caps         []string `json:"caps"`
	Mounts       []string `json:"mounts"`
	MountSources []string `json:"mount_sources"`
	User         string   `json:"user"`
	Group        string   `json:"group"`
	EnvNames     []string `json:"env_names"`
	Modules      []string `json:"modules"`
	Devices      []string `json:"devices"`
	HostMounts   []string `json:"host_mounts"`
	NetProfiles  []string `json:"net_profiles"`
	UnitsStart   []string `json:"units_start"`
	UnitsStop    []string `json:"units_stop"`
	Serial       uint64   `json:"serial"`
}

type wireV3 struct {
	signedV3
	Sig string `json:"sig"`
}

func norm(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Message is the exact byte string the fleet key signs for g: the sash/2
// message, or for V "sash/3" the sash/3 one.
func Message(g Grant) ([]byte, error) {
	v1 := signedV1{V: g.V, Actor: g.Actor, Host: g.Host, Purpose: g.Purpose, Exp: g.Exp, LeaseID: g.LeaseID,
		Entitlements: norm(g.Entitlements), FileRead: norm(g.FileRead), FileWrite: norm(g.FileWrite), AllowPrivate: g.AllowPrivate}
	var body any
	domain := grantDomain
	if g.V == "sash/3" {
		domain = grantDomainV3
		body = signedV3{
			signedV1: v1, Service: g.Service, Exec: norm(g.Exec), Caps: norm(g.Caps), Mounts: norm(g.Mounts), MountSources: norm(g.MountSources),
			User: g.User, Group: g.Group, EnvNames: norm(g.EnvNames),
			Modules: norm(g.Modules), Devices: norm(g.Devices), HostMounts: norm(g.HostMounts),
			NetProfiles: norm(g.NetProfiles), UnitsStart: norm(g.UnitsStart), UnitsStop: norm(g.UnitsStop), Serial: g.Serial,
		}
	} else {
		body = signedV2{
			signedV1: v1, Service: g.Service, Exec: norm(g.Exec), Caps: norm(g.Caps), Mounts: norm(g.Mounts), MountSources: norm(g.MountSources),
			User: g.User, Group: g.Group, EnvNames: norm(g.EnvNames), Serial: g.Serial,
		}
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fail.E("grant_bad_shape")
	}
	return append([]byte(domain), out...), nil
}

// VerifyGrant checks doc as a sash/2 service grant or a sash/3 boot grant
// signed by fleet. now is
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
	var head struct {
		V json.RawMessage `json:"v"`
	}
	if err := json.Unmarshal(doc, &head); err != nil {
		return Grant{}, "", fail.E("grant_bad_shape")
	}
	if string(head.V) == `"sash/3"` {
		return parseV3(doc)
	}
	return parseV2(doc)
}

// strictDecode decodes doc into dst with no unknown field and nothing
// after it, and returns its top-level keys.
func strictDecode(doc []byte, dst any) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return nil, fail.E("grant_bad_shape")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fail.E("grant_bad_shape")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doc, &raw); err != nil {
		return nil, fail.E("grant_bad_shape")
	}
	return raw, nil
}

func hasKeys(raw map[string]json.RawMessage, keys []string) bool {
	for _, key := range keys {
		if _, ok := raw[key]; !ok {
			return false
		}
	}
	return true
}

var v2Keys = []string{"v", "actor", "host", "purpose", "exp", "lease_id", "entitlements", "service", "exec", "caps", "mounts", "mount_sources", "user", "group", "env_names", "serial", "sig"}

// v3Keys are every field a sash/3 document must carry.
var v3Keys = []string{"v", "actor", "host", "purpose", "exp", "lease_id", "entitlements", "file_read", "file_write", "allow_private",
	"service", "exec", "caps", "mounts", "mount_sources", "user", "group", "env_names",
	"modules", "devices", "host_mounts", "net_profiles", "units_start", "units_stop", "serial", "sig"}

func parseV2(doc []byte) (Grant, string, error) {
	bad := func() (Grant, string, error) { return Grant{}, "", fail.E("grant_bad_shape") }
	var w wireV2
	raw, err := strictDecode(doc, &w)
	if err != nil || !hasKeys(raw, v2Keys) {
		return bad()
	}
	if w.V != "sash/2" || w.Purpose != PurposeService || w.Actor != "service:"+w.Service || w.Sig == "" {
		return bad()
	}
	if err := shapeService(w.signedV1, w.Service, w.User, w.Group, w.Serial, w.Exec, w.Caps, w.Mounts, w.MountSources, w.EnvNames); err != nil {
		return Grant{}, "", err
	}
	cp := func(s []string) []string { return append([]string(nil), s...) }
	return Grant{
		V: w.V, Actor: w.Actor, Host: w.Host, Purpose: w.Purpose, Exp: w.Exp, LeaseID: w.LeaseID,
		Entitlements: cp(w.Entitlements), FileRead: cp(w.FileRead), FileWrite: cp(w.FileWrite), AllowPrivate: w.AllowPrivate,
		Service: w.Service, Exec: cp(w.Exec), Caps: cp(w.Caps), Mounts: cp(w.Mounts), MountSources: cp(w.MountSources),
		User: w.User, Group: w.Group, EnvNames: cp(w.EnvNames), Serial: w.Serial,
	}, w.Sig, nil
}

// parseV3 reads a sash/3 document: purpose boot only, actor boot:<service>,
// every sash/2 rule, no null list (file_read and file_write included), and
// the six name lists (each at most 64 entries, no duplicates, every entry in
// its grammar).
func parseV3(doc []byte) (Grant, string, error) {
	bad := func() (Grant, string, error) { return Grant{}, "", fail.E("grant_bad_shape") }
	var w wireV3
	raw, err := strictDecode(doc, &w)
	if err != nil || !hasKeys(raw, v3Keys) {
		return bad()
	}
	if w.V != "sash/3" || w.Purpose != PurposeBoot || w.Actor != "boot:"+w.Service || w.Sig == "" || w.FileRead == nil || w.FileWrite == nil {
		return bad()
	}
	if err := shapeService(w.signedV1, w.Service, w.User, w.Group, w.Serial, w.Exec, w.Caps, w.Mounts, w.MountSources, w.EnvNames); err != nil {
		return Grant{}, "", err
	}
	for _, l := range []struct {
		list []string
		re   *regexp.Regexp
	}{
		{w.Modules, ModuleName}, {w.Devices, BootName}, {w.HostMounts, BootName},
		{w.NetProfiles, BootName}, {w.UnitsStart, UnitName}, {w.UnitsStop, UnitName},
	} {
		if !bootList(l.list, l.re) {
			return bad()
		}
	}
	cp := func(s []string) []string { return append([]string(nil), s...) }
	return Grant{
		V: w.V, Actor: w.Actor, Host: w.Host, Purpose: w.Purpose, Exp: w.Exp, LeaseID: w.LeaseID,
		Entitlements: cp(w.Entitlements), FileRead: cp(w.FileRead), FileWrite: cp(w.FileWrite), AllowPrivate: w.AllowPrivate,
		Service: w.Service, Exec: cp(w.Exec), Caps: cp(w.Caps), Mounts: cp(w.Mounts), MountSources: cp(w.MountSources),
		User: w.User, Group: w.Group, EnvNames: cp(w.EnvNames),
		Modules: cp(w.Modules), Devices: cp(w.Devices), HostMounts: cp(w.HostMounts),
		NetProfiles: cp(w.NetProfiles), UnitsStart: cp(w.UnitsStart), UnitsStop: cp(w.UnitsStop),
		Serial: w.Serial,
	}, w.Sig, nil
}

// shapeService is the rules sash/2 and sash/3 share once v, purpose and
// actor are checked: host, lease and sig set, a service name, a serial of
// at least 1, unix names, every list present, entitlements non-empty
// strings, clean absolute roots, exec programs and mount points, a mount
// source a name or such a path (never ensure), env and capability names in
// their forms.
func shapeService(w signedV1, service, user, group string, serial uint64, exec, caps, mounts, sources, env []string) error {
	bad := fail.E("grant_bad_shape")
	if w.Host == "" || w.LeaseID == "" || !ServiceName.MatchString(service) || serial < 1 || w.Exp < 0 {
		return bad
	}
	if w.Entitlements == nil || exec == nil || caps == nil || mounts == nil || sources == nil || env == nil {
		return bad
	}
	if !UnixName.MatchString(user) || !UnixName.MatchString(group) {
		return bad
	}
	for _, e := range w.Entitlements {
		if e == "" {
			return bad
		}
	}
	for _, list := range [][]string{w.FileRead, w.FileWrite, exec, mounts} {
		if err := roots(list); err != nil {
			return err
		}
	}
	for _, src := range sources {
		if src == mountSourceEnsure {
			return bad
		}
		if mountName.MatchString(src) {
			continue
		}
		if err := roots([]string{src}); err != nil {
			return err
		}
	}
	for _, e := range env {
		if !EnvName.MatchString(e) {
			return bad
		}
	}
	for _, c := range caps {
		if !capName.MatchString(c) {
			return bad
		}
	}
	return nil
}

// bootList is a present list of at most MaxBootList entries, each in re,
// none twice.
func bootList(list []string, re *regexp.Regexp) bool {
	if list == nil || len(list) > MaxBootList {
		return false
	}
	seen := map[string]bool{}
	for _, s := range list {
		if !re.MatchString(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
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

// BootOps reports a sash/3 boot grant: the only kind that carries the boot
// verbs.
func (g Grant) BootOps() bool { return g.V == "sash/3" && g.Purpose == PurposeBoot }

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
