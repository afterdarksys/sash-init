// SPDX-License-Identifier: GPL-3.0-or-later

// Package bootpolicy verifies and caches signed boot-policy metadata. A verified
// document is not proof that its catalog or executable artifacts have been checked.
package bootpolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/afterdarksys/sahinit/internal/fail"
)

const (
	Version     = "sahinit-boot-policy/1" // No lifetime field; always renew.
	Version2    = "sahinit-boot-policy/2" // Carries a signed lifetime.
	Domain      = "sahinit-boot-policy-v1\n"
	MaxPayload  = 256 * 1024
	MaxEnvelope = 384 * 1024
	maxInteger  = 1<<53 - 1 // Integers shared with JavaScript must be exact.
)

// Trust is provisioned locally. It must never be taken from the policy response.
type Trust struct {
	TenantID           string            `json:"tenant_id"`
	HostID             string            `json:"host_id"`
	EnrollmentID       string            `json:"enrollment_id"`
	RecoveryProfileID  string            `json:"recovery_profile_id"`
	Keys               map[string]string `json:"keys"` // key ID -> standard base64 Ed25519 public key
	MaxValiditySeconds int64             `json:"max_validity_seconds"`
	MaxGraceSeconds    int64             `json:"max_grace_seconds"`
	MaxJobSeconds      int64             `json:"max_job_seconds"`
	MinRefreshSeconds  int64             `json:"min_refresh_seconds"`
	MaxRefreshSeconds  int64             `json:"max_refresh_seconds"`
	MaxLifetime        string            `json:"max_lifetime"` // never allows both modes; renew refuses never
}

// Lifetime modes. A version-1 payload is renew; new policies default to never.
const (
	LifetimeNever = "never"
	LifetimeRenew = "renew"
)

type Policy struct {
	Version             string   `json:"version"`
	TenantID            string   `json:"tenant_id"`
	HostID              string   `json:"host_id"`
	EnrollmentID        string   `json:"enrollment_id"`
	PolicyID            string   `json:"policy_id"`
	Sequence            uint64   `json:"sequence"`
	CatalogGeneration   uint64   `json:"catalog_generation"`
	IssuedAt            int64    `json:"issued_at"`
	NotBefore           int64    `json:"not_before"`
	ExpiresAt           int64    `json:"expires_at"`
	OfflineUntil        int64    `json:"offline_until"`
	RefreshAfterSeconds int64    `json:"refresh_after_seconds"`
	CatalogSHA256       string   `json:"catalog_sha256"`
	Units               []Unit   `json:"units"`
	Jobs                []Job    `json:"jobs"`
	OfflineUnits        []string `json:"offline_units"`
	OfflineJobs         []string `json:"offline_jobs"`
	RuntimeRestartUnits []string `json:"runtime_restart_units"`
	RecoveryProfileID   string   `json:"recovery_profile_id"`
	// Absent in Version, required in Version2. Decoded version-1 policies
	// report renew.
	Lifetime string `json:"lifetime,omitempty"`
}

type Unit struct {
	ID    string   `json:"id"`
	Needs []string `json:"needs"`
}

type Job struct {
	ID             string   `json:"id"`
	ScriptSHA256   string   `json:"script_sha256"`
	Scopes         []Scope  `json:"scopes"`
	Phases         []string `json:"phases"`
	TimeoutSeconds int64    `json:"timeout_seconds"`
	NeedsUnits     []string `json:"needs_units"`
	NeedsJobs      []string `json:"needs_jobs"`
}

type Scope struct {
	Operation string `json:"operation"`
	Resource  string `json:"resource"` // Named resource, never a free-form path/command.
}

type envelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Document retains private immutable verified bytes; accessors return copies.
type Document struct {
	policy  Policy
	payload []byte
	raw     []byte
	digest  string
}

func (d *Document) Policy() Policy {
	var p Policy
	_ = json.Unmarshal(d.payload, &p)
	p.Lifetime = d.policy.Lifetime
	return p
}
func (d *Document) Bytes() []byte  { return append([]byte(nil), d.raw...) }
func (d *Document) Digest() string { return d.digest }

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var digestRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var operations = map[string]bool{"mount.ensure": true, "device.wait": true, "module.load": true, "network.apply": true, "unit.start": true, "unit.stop": true, "unit.status": true}

func bad() error { return fail.E("policy_bad_shape") }

// DecodeStrict rejects missing/unknown/duplicate fields, nulls at any depth,
// trailing values and invalid UTF-8. All wire fields are mandatory, including [].
func DecodeStrict(raw []byte, dst any) error { return decodeStrict(raw, dst, "") }

// decodeStrict is DecodeStrict where the top-level field named absent must be
// missing instead of present; it is used for older wire versions.
func decodeStrict(raw []byte, dst any, absent string) error {
	if !utf8.Valid(raw) {
		return bad()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := readValue(dec, 0)
	if err != nil {
		return bad()
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad()
	}
	typ := reflect.TypeOf(dst)
	if typ == nil || typ.Kind() != reflect.Pointer || !shape(value, typ.Elem(), absent) {
		return bad()
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return bad()
	}
	return nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, bad()
	}
	tok, err := d.Token()
	if err != nil || tok == nil {
		return nil, bad()
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, bad()
			}
			key, ok := k.(string)
			if !ok {
				return nil, bad()
			}
			if _, ok := obj[key]; ok {
				return nil, bad()
			}
			v, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, bad()
		}
		return obj, nil
	case '[':
		arr := []any{}
		for d.More() {
			v, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, bad()
		}
		return arr, nil
	}
	return nil, bad()
}
func shape(v any, t reflect.Type, absent string) bool {
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		want := t.NumField()
		if absent != "" {
			want--
		}
		if !ok || len(obj) != want {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			x, ok := obj[name]
			if name == absent {
				if ok {
					return false
				}
				continue
			}
			if !ok || !shape(x, f.Type, "") {
				return false
			}
		}
	case reflect.Slice:
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range arr {
			if !shape(x, t.Elem(), "") {
				return false
			}
		}
	case reflect.Map:
		obj, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for _, x := range obj {
			if !shape(x, t.Elem(), "") {
				return false
			}
		}
	case reflect.String:
		_, ok := v.(string)
		return ok
	default:
		_, ok := v.(json.Number)
		return ok
	}
	return true
}

func (t Trust) Validate() error {
	for _, v := range []string{t.TenantID, t.HostID, t.EnrollmentID, t.RecoveryProfileID} {
		if !identifier.MatchString(v) {
			return fail.E("policy_bad_trust")
		}
	}
	if len(t.Keys) == 0 || len(t.Keys) > 16 {
		return fail.E("policy_bad_trust")
	}
	seen := map[string]bool{}
	for k, v := range t.Keys {
		b, err := decode64(v)
		if !identifier.MatchString(k) || err != nil || len(b) != ed25519.PublicKeySize || seen[v] {
			return fail.E("policy_bad_trust")
		}
		seen[v] = true
	}
	if t.MaxLifetime != LifetimeNever && t.MaxLifetime != LifetimeRenew {
		return fail.E("policy_bad_trust")
	}
	if t.MaxValiditySeconds <= 0 || t.MaxValiditySeconds > 366*86400 || t.MaxGraceSeconds < 0 || t.MaxGraceSeconds > 366*86400 || t.MaxJobSeconds <= 0 || t.MaxJobSeconds > 86400 || t.MinRefreshSeconds < 30 || t.MaxRefreshSeconds < t.MinRefreshSeconds || t.MaxRefreshSeconds > t.MaxValiditySeconds {
		return fail.E("policy_bad_trust")
	}
	return nil
}

// DecodeTrust strictly decodes a trust file. max_lifetime may be omitted, as in
// trust files written before lifetimes existed, and then means never.
func DecodeTrust(raw []byte) (Trust, error) {
	var t Trust
	if err := DecodeStrict(raw, &t); err != nil {
		t = Trust{}
		if err := decodeStrict(raw, &t, "max_lifetime"); err != nil {
			return Trust{}, err
		}
		t.MaxLifetime = LifetimeNever
	}
	return t, t.Validate()
}

func decode64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, bad()
	}
	return b, nil
}

// Verify checks cryptographic identity, shape, host binding, and local ceilings.
// It deliberately does not evaluate current time: expired cache still carries
// the anti-rollback sequence. Call State or CheckFresh separately.
func Verify(raw []byte, t Trust) (*Document, error) {
	payload, err := open(raw, t, Domain)
	if err != nil {
		return nil, err
	}
	// Threats: the version selects the shape, so a version-1 payload cannot
	// carry lifetime and a version-2 payload cannot omit it.
	var p Policy
	if err := DecodeStrict(payload, &p); err == nil {
		if p.Version != Version2 {
			return nil, bad()
		}
	} else {
		p = Policy{}
		if err := decodeStrict(payload, &p, "lifetime"); err != nil || p.Version != Version {
			return nil, bad()
		}
		p.Lifetime = LifetimeRenew
	}
	if err := p.validate(t); err != nil {
		return nil, err
	}
	h := sha256.Sum256(payload)
	return &Document{policy: p, payload: append([]byte(nil), payload...), raw: append([]byte(nil), raw...), digest: hex.EncodeToString(h[:])}, nil
}

// open checks local trust, the envelope, and the signature over domain and
// the decoded payload, and returns the payload. Each document type has its
// own domain so a signature over one can never verify as another.
func open(raw []byte, t Trust, domain string) ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > MaxEnvelope {
		return nil, bad()
	}
	var e envelope
	if err := DecodeStrict(raw, &e); err != nil {
		return nil, err
	}
	payload, err := decode64(e.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxPayload {
		return nil, bad()
	}
	sig, err := decode64(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fail.E("policy_bad_signature")
	}
	key, err := decode64(t.Keys[e.KeyID])
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(domain), payload...), sig) {
		return nil, fail.E("policy_bad_signature")
	}
	return payload, nil
}

func names(xs []string, limit int) (map[string]bool, bool) {
	if xs == nil || len(xs) > limit {
		return nil, false
	}
	out := map[string]bool{}
	for _, x := range xs {
		if !identifier.MatchString(x) || out[x] {
			return nil, false
		}
		out[x] = true
	}
	return out, true
}
func (p Policy) validate(t Trust) error {
	if (p.Version != Version || p.Lifetime != LifetimeRenew) && p.Version != Version2 {
		return bad()
	}
	if p.TenantID != t.TenantID || p.HostID != t.HostID || p.EnrollmentID != t.EnrollmentID {
		return fail.E("policy_host_mismatch")
	}
	if p.RecoveryProfileID != t.RecoveryProfileID {
		return fail.E("policy_recovery_mismatch")
	}
	if !identifier.MatchString(p.PolicyID) || p.Sequence == 0 || p.Sequence > maxInteger || p.CatalogGeneration == 0 || p.CatalogGeneration > maxInteger || !digestRE.MatchString(p.CatalogSHA256) {
		return bad()
	}
	switch p.Lifetime {
	case LifetimeRenew:
		if p.IssuedAt <= 0 || p.IssuedAt > p.NotBefore || p.NotBefore >= p.ExpiresAt || p.ExpiresAt > p.OfflineUntil || p.OfflineUntil > maxInteger {
			return bad()
		}
		if p.ExpiresAt-p.IssuedAt > t.MaxValiditySeconds || p.OfflineUntil-p.ExpiresAt > t.MaxGraceSeconds || p.RefreshAfterSeconds < t.MinRefreshSeconds || p.RefreshAfterSeconds > t.MaxRefreshSeconds || p.RefreshAfterSeconds >= p.ExpiresAt-p.NotBefore {
			return fail.E("policy_ceiling")
		}
	case LifetimeNever:
		// Threats: a never-policy carries no deadline a host could misread, and
		// no delayed start, so its validity never depends on the clock. Only a
		// higher sequence or the revocation floor ends it.
		if t.MaxLifetime != LifetimeNever {
			return fail.E("policy_lifetime_cap")
		}
		if p.IssuedAt <= 0 || p.IssuedAt > maxInteger || p.NotBefore != p.IssuedAt || p.ExpiresAt != 0 || p.OfflineUntil != 0 || p.RefreshAfterSeconds != 0 {
			return bad()
		}
	default:
		return bad()
	}
	if p.Units == nil || p.Jobs == nil || len(p.Units) > 256 || len(p.Jobs) > 256 {
		return bad()
	}
	units := map[string][]string{}
	jobs := map[string][]string{}
	for _, u := range p.Units {
		if !identifier.MatchString(u.ID) {
			return bad()
		}
		if _, ok := units[u.ID]; ok {
			return bad()
		}
		if _, ok := names(u.Needs, 64); !ok {
			return bad()
		}
		units[u.ID] = u.Needs
	}
	for _, j := range p.Jobs {
		if !identifier.MatchString(j.ID) || !digestRE.MatchString(j.ScriptSHA256) || j.TimeoutSeconds <= 0 || j.TimeoutSeconds > t.MaxJobSeconds || j.Scopes == nil || len(j.Scopes) > 64 {
			return bad()
		}
		if _, ok := jobs[j.ID]; ok {
			return bad()
		}
		if _, ok := names(j.NeedsJobs, 64); !ok {
			return bad()
		}
		jobs[j.ID] = j.NeedsJobs
		if _, ok := names(j.NeedsUnits, 64); !ok {
			return bad()
		}
		for _, n := range j.NeedsUnits {
			if _, ok := units[n]; !ok {
				return bad()
			}
		}
		phases, ok := names(j.Phases, 2)
		if !ok || len(phases) == 0 {
			return bad()
		}
		for ph := range phases {
			if ph != "boot" && ph != "cleanup" {
				return bad()
			}
		}
		scopes := map[Scope]bool{}
		for _, sc := range j.Scopes {
			if !operations[sc.Operation] || !identifier.MatchString(sc.Resource) || scopes[sc] {
				return bad()
			}
			scopes[sc] = true
			if strings.HasPrefix(sc.Operation, "unit.") {
				if _, ok := units[sc.Resource]; !ok {
					return bad()
				}
			}
		}
	}
	if !acyclic(units) || !acyclic(jobs) {
		return bad()
	}
	offline, ok := names(p.OfflineUnits, 256)
	if !ok || !closedSubset(offline, units) {
		return bad()
	}
	offJobs, ok := names(p.OfflineJobs, 256)
	if !ok || !closedSubset(offJobs, jobs) {
		return bad()
	}
	for _, j := range p.Jobs {
		if offJobs[j.ID] {
			for _, u := range j.NeedsUnits {
				if !offline[u] {
					return bad()
				}
			}
			for _, sc := range j.Scopes {
				if sc.Operation == "unit.start" && !offline[sc.Resource] {
					return bad()
				}
			}
		}
	}
	restarts, ok := names(p.RuntimeRestartUnits, 256)
	if !ok || !closedSubset(restarts, units) {
		return bad()
	}
	return nil
}
func acyclic(graph map[string][]string) bool {
	visited := map[string]int{}
	var visit func(string) bool
	visit = func(n string) bool {
		if visited[n] == 1 {
			return false
		}
		if visited[n] == 2 {
			return true
		}
		deps, ok := graph[n]
		if !ok {
			return false
		}
		visited[n] = 1
		for _, dep := range deps {
			if !visit(dep) {
				return false
			}
		}
		visited[n] = 2
		return true
	}
	for n := range graph {
		if !visit(n) {
			return false
		}
	}
	return true
}
func closedSubset(set map[string]bool, graph map[string][]string) bool {
	for n := range set {
		deps, ok := graph[n]
		if !ok {
			return false
		}
		for _, dep := range deps {
			if !set[dep] {
				return false
			}
		}
	}
	return true
}

// renewalBody excludes only authorization lifetime/refresh and sequence fields,
// and the wire version. The lifetime mode stays: changing it needs a new
// generation.
func (d *Document) renewalBody() []byte {
	p := d.policy
	p.Version = ""
	p.Sequence = 0
	p.IssuedAt = 0
	p.NotBefore = 0
	p.ExpiresAt = 0
	p.OfflineUntil = 0
	p.RefreshAfterSeconds = 0
	b, _ := json.Marshal(p)
	return b
}
func compare(old, next *Document) error {
	if next.policy.Sequence < old.policy.Sequence {
		return fail.E("policy_rollback")
	}
	if next.policy.Sequence == old.policy.Sequence {
		if !bytes.Equal(next.payload, old.payload) {
			return fail.E("policy_sequence_conflict")
		}
		return nil
	}
	if next.policy.CatalogGeneration < old.policy.CatalogGeneration {
		return fail.E("policy_rollback")
	}
	if next.policy.CatalogGeneration == old.policy.CatalogGeneration && !bytes.Equal(next.renewalBody(), old.renewalBody()) {
		return fail.E("policy_generation_conflict")
	}
	return nil
}
