package bootpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/afterdarksys/sahinit/internal/fail"
)

const (
	FloorVersion = "sahinit-boot-floor/1"
	FloorDomain  = "sahinit-boot-floor-v1\n"
)

// Floor revokes every policy whose sequence is below MinSequence.
//
// Threats: a floor is signed by a boot-policy key under its own domain, so
// neither a policy nor any other signed document can be replayed as one. It is
// bound to the host exactly as a policy is. It does not read the clock and has
// no expiry; it only ever rises. It does NOT protect against deleting the
// cache directory or restoring a disk snapshot (see boot-policy.md).
type Floor struct {
	Version      string `json:"version"`
	TenantID     string `json:"tenant_id"`
	HostID       string `json:"host_id"`
	EnrollmentID string `json:"enrollment_id"`
	MinSequence  uint64 `json:"min_sequence"`
	IssuedAt     int64  `json:"issued_at"`
}

// FloorDocument retains private immutable verified bytes like Document.
type FloorDocument struct {
	floor   Floor
	payload []byte
	raw     []byte
	digest  string
}

func (f *FloorDocument) Floor() Floor   { return f.floor }
func (f *FloorDocument) Bytes() []byte  { return append([]byte(nil), f.raw...) }
func (f *FloorDocument) Digest() string { return f.digest }

// VerifyFloor checks a revocation floor's signature, shape and host binding.
func VerifyFloor(raw []byte, t Trust) (*FloorDocument, error) {
	payload, err := open(raw, t, FloorDomain)
	if err != nil {
		return nil, err
	}
	var f Floor
	if err := DecodeStrict(payload, &f); err != nil {
		return nil, err
	}
	if f.Version != FloorVersion {
		return nil, bad()
	}
	if f.TenantID != t.TenantID || f.HostID != t.HostID || f.EnrollmentID != t.EnrollmentID {
		return nil, fail.E("policy_host_mismatch")
	}
	if f.MinSequence == 0 || f.MinSequence > maxInteger || f.IssuedAt <= 0 || f.IssuedAt > maxInteger {
		return nil, bad()
	}
	h := sha256.Sum256(payload)
	return &FloorDocument{floor: f, payload: append([]byte(nil), payload...), raw: append([]byte(nil), raw...), digest: hex.EncodeToString(h[:])}, nil
}

// admits refuses a policy below the floor. A nil floor admits everything.
func (f *FloorDocument) admits(d *Document) error {
	if f != nil && d.policy.Sequence < f.floor.MinSequence {
		return fail.E("policy_revoked")
	}
	return nil
}

func compareFloor(old, next *FloorDocument) error {
	if next.floor.MinSequence < old.floor.MinSequence {
		return fail.E("policy_floor_rollback")
	}
	if next.floor.MinSequence == old.floor.MinSequence && !bytes.Equal(next.payload, old.payload) {
		return fail.E("policy_floor_conflict")
	}
	return nil
}
