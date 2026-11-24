package sash

// The signed per-service floor, sahinit-sash-floor/1: a sash/2 grant whose
// serial is below its service's floor is refused (sash_grant_revoked).
//
// Threats: a floor is signed by the fleet key under its own domain,
// "sahinit-sash-floor-v1\n", so no grant, boot policy or boot-policy floor
// can be replayed as one, nor the reverse. The store mirrors
// internal/bootpolicy's floor store: a private directory owned by the
// supervisor, a lock, an exclusive temporary file, fsync, rename and a
// directory fsync; a floor only rises (sash_floor_rollback), a different
// floor at the same serial is sash_floor_conflict, and a present floor that
// is unreadable, unsafe or unverifiable fails closed. It does NOT protect
// against deleting the directory or restoring a disk snapshot, as the boot
// policy's floor does not.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/sahinit/internal/bootpolicy"
	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

const (
	FloorVersion = "sahinit-sash-floor/1"
	FloorDomain  = "sahinit-sash-floor-v1\n"
	maxFloor     = 4096
	maxInteger   = 1<<53 - 1
	floorSuffix  = ".floor"
)

// Floor is the signed payload.
type Floor struct {
	Version   string `json:"version"`
	Service   string `json:"service"`
	MinSerial uint64 `json:"min_serial"`
	IssuedAt  int64  `json:"issued_at"`
}

type floorEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// FloorDoc is a verified floor with its exact bytes.
type FloorDoc struct {
	floor   Floor
	payload []byte
	raw     []byte
	digest  string
}

func (f *FloorDoc) Floor() Floor   { return f.floor }
func (f *FloorDoc) Bytes() []byte  { return append([]byte(nil), f.raw...) }
func (f *FloorDoc) Digest() string { return f.digest }

// VerifyFloor checks a floor's envelope, signature and shape.
func VerifyFloor(raw []byte, fleet ed25519.PublicKey) (*FloorDoc, error) {
	bad := func() (*FloorDoc, error) { return nil, fail.E("sash_floor_bad_shape") }
	if len(raw) == 0 || len(raw) > maxFloor {
		return bad()
	}
	var e floorEnvelope
	if err := bootpolicy.DecodeStrict(raw, &e); err != nil {
		return bad()
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(payload) == 0 {
		return bad()
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || len(fleet) != ed25519.PublicKeySize ||
		!ed25519.Verify(fleet, append([]byte(FloorDomain), payload...), sig) {
		return nil, fail.E("sash_floor_bad_signature")
	}
	var f Floor
	if err := bootpolicy.DecodeStrict(payload, &f); err != nil {
		return bad()
	}
	if f.Version != FloorVersion || !ServiceName.MatchString(f.Service) || f.MinSerial == 0 || f.MinSerial > maxInteger || f.IssuedAt <= 0 || f.IssuedAt > maxInteger {
		return bad()
	}
	h := sha256.Sum256(payload)
	return &FloorDoc{floor: f, payload: append([]byte(nil), payload...), raw: append([]byte(nil), raw...), digest: hex.EncodeToString(h[:])}, nil
}

// SignFloor is for tests and fixtures: sahinit never holds the fleet key.
func SignFloor(f Floor, priv ed25519.PrivateKey) []byte {
	payload := []byte(`{"version":"` + f.Version + `","service":"` + f.Service + `","min_serial":` + itoa(f.MinSerial) + `,"issued_at":` + itoa(uint64(f.IssuedAt)) + `}`)
	sig := ed25519.Sign(priv, append([]byte(FloorDomain), payload...))
	return []byte(`{"payload":"` + base64.StdEncoding.EncodeToString(payload) + `","signature":"` + base64.StdEncoding.EncodeToString(sig) + `"}`)
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func compareFloor(old, next *FloorDoc) error {
	if next.floor.MinSerial < old.floor.MinSerial {
		return fail.E("sash_floor_rollback")
	}
	if next.floor.MinSerial == old.floor.MinSerial && !bytes.Equal(next.payload, old.payload) {
		return fail.E("sash_floor_conflict")
	}
	return nil
}

// FloorStore holds one floor per service in a private directory.
type FloorStore struct {
	mu         sync.Mutex
	dir        *os.File
	fleet      ed25519.PublicKey
	failed     bool
	checkpoint func(string) error // test-only fault injection
	// wait is how long a busy lock is retried; 0 is two seconds.
	wait time.Duration
}

// SetLockWait sets how long a busy lock is retried (tests).
func (s *FloorStore) SetLockWait(d time.Duration) {
	s.mu.Lock()
	s.wait = d
	s.mu.Unlock()
}

func (s *FloorStore) lockWait() time.Duration {
	if s.wait > 0 {
		return s.wait
	}
	return 2 * time.Second
}

// OpenFloorStore opens dir, which must be a directory (not a link) owned by
// the supervisor's uid with no group or other access.
func OpenFloorStore(path string, fleet ed25519.PublicKey) (*FloorStore, error) {
	if len(fleet) != ed25519.PublicKeySize {
		return nil, fail.E("sash_floor_store_failed")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail.E("sash_floor_store_failed")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&0o077 != 0 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, fail.E("sash_floor_store_failed")
	}
	return &FloorStore{dir: os.NewFile(uintptr(fd), path), fleet: append(ed25519.PublicKey(nil), fleet...)}, nil
}

// Close closes the store; later calls fail.
func (s *FloorStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = true
	return s.dir.Close()
}

func (s *FloorStore) lock() (*os.File, error) {
	if s.failed {
		return nil, fail.E("sash_floor_store_failed")
	}
	fd, err := unix.Openat(int(s.dir.Fd()), "lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fail.E("sash_floor_store_failed")
	}
	f := os.NewFile(uintptr(fd), "lock")
	if !privateRegular(fd) {
		f.Close()
		return nil, fail.E("sash_floor_store_failed")
	}
	// A busy store (a floor-install in progress) is waited for briefly;
	// still busy, it is sash_floor_busy, which a start treats as
	// transient.
	deadline := time.Now().Add(s.lockWait())
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK || time.Now().After(deadline) {
			f.Close()
			return nil, fail.E("sash_floor_busy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return f, nil
}

func privateRegular(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o077 == 0 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

// load returns nil when service has no floor. A present floor that does not
// read, is unsafe, does not verify, or names another service fails closed.
func (s *FloorStore) load(service string) (*FloorDoc, error) {
	if !ServiceName.MatchString(service) {
		return nil, fail.E("sash_floor_bad_shape")
	}
	fd, err := unix.Openat(int(s.dir.Fd()), service+floorSuffix, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fail.E("sash_floor_store_failed")
	}
	f := os.NewFile(uintptr(fd), service)
	defer f.Close()
	if !privateRegular(fd) {
		return nil, fail.E("sash_floor_store_failed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxFloor+1))
	if err != nil {
		return nil, fail.E("sash_floor_store_failed")
	}
	d, err := VerifyFloor(raw, s.fleet)
	if err != nil {
		return nil, fail.E("sash_floor_store_failed")
	}
	if d.floor.Service != service {
		return nil, fail.E("sash_floor_store_failed")
	}
	return d, nil
}

// Floor returns service's floor, or nil when none was installed.
func (s *FloorStore) Floor(service string) (*FloorDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return s.load(service)
}

// Admit refuses serial when it is below service's floor
// (sash_grant_revoked). No floor admits every serial.
func (s *FloorStore) Admit(service string, serial uint64) error {
	f, err := s.Floor(service)
	if err != nil {
		return err
	}
	if f != nil && serial < f.floor.MinSerial {
		return fail.E("sash_grant_revoked")
	}
	return nil
}

// Services lists the services that have a floor file, sorted.
func (s *FloorStore) Services() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, fail.E("sash_floor_store_failed")
	}
	entries, err := os.ReadDir(s.dir.Name())
	if err != nil {
		return nil, fail.E("sash_floor_store_failed")
	}
	var out []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), floorSuffix); ok && ServiceName.MatchString(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Install raises a service's floor. The same floor again is an idempotent
// retry.
func (s *FloorStore) Install(raw []byte) (*FloorDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	next, err := VerifyFloor(raw, s.fleet)
	if err != nil {
		return nil, err
	}
	old, err := s.load(next.floor.Service)
	if err != nil {
		return nil, err
	}
	if old != nil {
		if err := compareFloor(old, next); err != nil {
			return nil, err
		}
		if old.digest == next.digest {
			if err := s.dir.Sync(); err != nil {
				s.failed = true
				return nil, fail.E("sash_floor_store_failed")
			}
			return old, nil
		}
	}
	if err := s.commit(next.floor.Service+floorSuffix, next.raw); err != nil {
		return nil, err
	}
	return next, nil
}

// commit is bootpolicy's: exclusive temporary file, write, fsync, close,
// rename, directory fsync. A failure after the rename fails the store
// closed.
func (s *FloorStore) commit(target string, raw []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fail.E("sash_floor_store_failed")
	}
	name := "pending-" + hex.EncodeToString(nonce[:])
	dirfd := int(s.dir.Fd())
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fail.E("sash_floor_store_failed")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	defer unix.Unlinkat(dirfd, name, 0)
	stop := func(stage string) error {
		if s.checkpoint != nil {
			return s.checkpoint(stage)
		}
		return nil
	}
	failed := func() error { return fail.E("sash_floor_store_failed") }
	if _, err := f.Write(raw); err != nil || stop("written") != nil {
		return failed()
	}
	if err := f.Sync(); err != nil || stop("file_synced") != nil {
		return failed()
	}
	if err := f.Close(); err != nil {
		return failed()
	}
	if err := unix.Renameat(dirfd, name, dirfd, target); err != nil {
		return failed()
	}
	if err := stop("renamed"); err != nil {
		s.failed = true
		return failed()
	}
	if err := s.dir.Sync(); err != nil {
		s.failed = true
		return failed()
	}
	return nil
}
