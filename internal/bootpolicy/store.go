package bootpolicy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// Store caches the latest verified metadata, not an active boot catalog. The
// document itself holds the high-water sequence so there is no split commit.
// Provision a private directory first; parents must be administrator-controlled.
type Store struct {
	mu         sync.Mutex
	dir        *os.File
	trust      Trust
	clock      Clock
	failed     bool
	checkpoint func(string) error // Test-only fault injection; nil in production.
}

func OpenStore(path string, t Trust, c Clock) (*Store, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail.E("policy_store_failed")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, fail.E("policy_store_failed")
	}
	// Freeze trust inputs; caller mutation must not alter an open verifier/cache.
	keys := map[string]string{}
	for k, v := range t.Keys {
		keys[k] = v
	}
	t.Keys = keys
	return &Store{dir: os.NewFile(uintptr(fd), path), trust: t, clock: c}, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = true
	return s.dir.Close()
}

func (s *Store) lock() (*os.File, error) {
	if s.failed {
		return nil, fail.E("policy_store_failed")
	}
	fd, err := unix.Openat(int(s.dir.Fd()), "lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fail.E("policy_store_failed")
	}
	f := os.NewFile(uintptr(fd), "lock")
	if !privateRegular(fd) {
		f.Close()
		return nil, fail.E("policy_store_failed")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fail.E("policy_store_busy")
	}
	return f, nil
}
func privateRegular(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0077 == 0 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
func (s *Store) read(name string) ([]byte, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, fail.E("policy_missing")
	}
	if err != nil {
		return nil, fail.E("policy_store_failed")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if !privateRegular(fd) {
		return nil, fail.E("policy_store_failed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxEnvelope+1))
	if err != nil {
		return nil, fail.E("policy_store_failed")
	}
	return raw, nil
}
func (s *Store) load() (*Document, error) {
	raw, err := s.read("policy.json")
	if err != nil {
		return nil, err
	}
	return Verify(raw, s.trust)
}

// loadFloor returns nil when no floor was ever installed. A floor file that
// is present but unreadable, unsafe or unverifiable fails closed.
func (s *Store) loadFloor() (*FloorDocument, error) {
	raw, err := s.read("floor.json")
	if fail.Token(err) == "policy_missing" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return VerifyFloor(raw, s.trust)
}

// Load returns the cached policy, refusing it with policy_revoked when its
// sequence is below the installed revocation floor.
func (s *Store) Load() (*Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	floor, err := s.loadFloor()
	if err != nil {
		return nil, err
	}
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	if err := floor.admits(d); err != nil {
		return nil, err
	}
	return d, nil
}

// Floor returns the installed revocation floor, or policy_floor_missing.
func (s *Store) Floor() (*FloorDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	f, err := s.loadFloor()
	if err == nil && f == nil {
		return nil, fail.E("policy_floor_missing")
	}
	return f, err
}

// InstallFloor raises the revocation floor. A lower floor is refused, the same
// floor is an idempotent retry, and a different document at the same
// min_sequence is a conflict. A corrupt floor is never silently replaced.
func (s *Store) InstallFloor(raw []byte) (*FloorDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	next, err := VerifyFloor(raw, s.trust)
	if err != nil {
		return nil, err
	}
	old, err := s.loadFloor()
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
				return nil, fail.E("policy_store_failed")
			}
			return old, nil
		}
	}
	if err := s.commit("floor.json", next.raw, nil); err != nil {
		return nil, err
	}
	return next, nil
}

// Install requires fresh authorization. Grace/expired documents may be loaded,
// but cannot be installed as renewals. Corrupt cache is never silently replaced.
func (s *Store) Install(raw []byte) (*Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	next, err := Verify(raw, s.trust)
	if err != nil {
		return nil, err
	}
	if err := next.CheckFresh(s.clock); err != nil {
		return nil, err
	}
	floor, err := s.loadFloor()
	if err != nil {
		return nil, err
	}
	if err := floor.admits(next); err != nil {
		return nil, err
	}
	old, err := s.load()
	if err != nil && fail.Token(err) != "policy_missing" {
		return nil, err
	}
	if old != nil {
		if err := compare(old, next); err != nil {
			return nil, err
		}
		if old.digest == next.digest { // Retry after an ambiguous post-rename failure.
			if err := s.dir.Sync(); err != nil {
				s.failed = true
				return nil, fail.E("policy_store_failed")
			}
			return old, nil
		}
	}
	// Recheck at commit; slow disk IO cannot install a now-expired document.
	if err := s.commit("policy.json", next.raw, func() error { return next.CheckFresh(s.clock) }); err != nil {
		return nil, err
	}
	return next, nil
}

// commit atomically replaces target with raw: exclusive temporary file, write,
// fsync, close, recheck, rename, directory fsync. A failure after the rename
// is an ambiguous commit and fails the open store closed.
func (s *Store) commit(target string, raw []byte, recheck func() error) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fail.E("policy_store_failed")
	}
	name := "pending-" + hex.EncodeToString(nonce[:])
	dirfd := int(s.dir.Fd())
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fail.E("policy_store_failed")
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
	failed := func() error { return fail.E("policy_store_failed") }
	if err := stop("created"); err != nil {
		return failed()
	}
	if _, err := f.Write(raw); err != nil {
		return failed()
	}
	if err := stop("written"); err != nil {
		return failed()
	}
	if err := f.Sync(); err != nil {
		return failed()
	}
	if err := stop("file_synced"); err != nil {
		return failed()
	}
	if err := f.Close(); err != nil {
		return failed()
	}
	if recheck != nil {
		if err := recheck(); err != nil {
			return err
		}
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
	if err := stop("directory_synced"); err != nil {
		s.failed = true
		return failed()
	}
	return nil
}
