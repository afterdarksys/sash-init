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
func (s *Store) load() (*Document, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), "policy.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, fail.E("policy_missing")
	}
	if err != nil {
		return nil, fail.E("policy_store_failed")
	}
	f := os.NewFile(uintptr(fd), "policy.json")
	defer f.Close()
	if !privateRegular(fd) {
		return nil, fail.E("policy_store_failed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxEnvelope+1))
	if err != nil {
		return nil, fail.E("policy_store_failed")
	}
	return Verify(raw, s.trust)
}
func (s *Store) Load() (*Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return s.load()
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
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fail.E("policy_store_failed")
	}
	name := "pending-" + hex.EncodeToString(nonce[:])
	dirfd := int(s.dir.Fd())
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fail.E("policy_store_failed")
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
	failed := func() (*Document, error) { return nil, fail.E("policy_store_failed") }
	if err := stop("created"); err != nil {
		return failed()
	}
	if _, err := f.Write(next.raw); err != nil {
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
	// Recheck at commit; slow disk IO cannot install a now-expired document.
	if err := next.CheckFresh(s.clock); err != nil {
		return nil, err
	}
	if err := unix.Renameat(dirfd, name, dirfd, "policy.json"); err != nil {
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
	return next, nil
}
