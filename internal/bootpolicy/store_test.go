// SPDX-License-Identifier: GPL-3.0-or-later

package bootpolicy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestStoreRenewalAndReopen(t *testing.T) {
	trust, p, key := fixture()
	now := p.IssuedAt
	clock := ClockFunc(func() (time.Time, bool) { return time.Unix(now, 0), true })
	s, path := newStore(t, trust, clock)
	_, err := s.Load()
	requireCode(t, err, "policy_missing")
	first := signed(p, key)
	if _, err := s.Install(first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(first); err != nil {
		t.Fatal("retry", err)
	}
	changed := p
	changed.ExpiresAt--
	changed.OfflineUntil--
	_, err = s.Install(signed(changed, key))
	requireCode(t, err, "policy_sequence_conflict")
	changed = p
	changed.Sequence++
	changed.Jobs = append([]Job{}, p.Jobs...)
	changed.Jobs[0].TimeoutSeconds++
	_, err = s.Install(signed(changed, key))
	requireCode(t, err, "policy_generation_conflict")
	p.Sequence++
	p.IssuedAt += 100
	p.NotBefore += 100
	p.ExpiresAt += 100
	p.OfflineUntil += 100
	now += 100
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	_, err = s.Install(first)
	requireCode(t, err, "policy_rollback")
	p.Sequence++
	p.CatalogGeneration++
	p.CatalogSHA256 = string(bytes.Repeat([]byte{'c'}, 64))
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, trust, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	now = p.OfflineUntil
	d, err := reopened.Load()
	if err != nil || d.State(clock) != Expired || d.Policy().Sequence != 3 {
		t.Fatal(d, err)
	}
	p.Sequence++
	_, err = reopened.Install(signed(p, key))
	requireCode(t, err, "policy_expired")
	// An expired cache still protects its sequence against a currently valid replay.
	now = p.IssuedAt
	_, err = reopened.Install(first)
	requireCode(t, err, "policy_rollback")
}

func TestStoreFailuresPreserveState(t *testing.T) {
	trust, p, key := fixture()
	for _, stage := range []string{"created", "written", "file_synced", "renamed", "directory_synced"} {
		t.Run(stage, func(t *testing.T) {
			s, path := newStore(t, trust, fixed(p.IssuedAt))
			if _, err := s.Install(signed(p, key)); err != nil {
				t.Fatal(err)
			}
			next := p
			next.Sequence++
			s.checkpoint = func(got string) error {
				if got == stage {
					return errors.New("injected")
				}
				return nil
			}
			_, err := s.Install(signed(next, key))
			requireCode(t, err, "policy_store_failed")
			reopened, err := OpenStore(path, trust, fixed(p.IssuedAt))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			d, err := reopened.Load()
			if err != nil {
				t.Fatal(err)
			}
			expected := uint64(1)
			if stage == "renamed" || stage == "directory_synced" {
				expected = 2
				_, err = s.Load()
				requireCode(t, err, "policy_store_failed")
			}
			if d.Policy().Sequence != expected {
				t.Fatalf("sequence %d, want %d", d.Policy().Sequence, expected)
			}
			// A retry recovers the committed or uncommitted outcome without rollback.
			if _, err := reopened.Install(signed(next, key)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreRejectsUnsafeFilesAndCorruption(t *testing.T) {
	trust, p, key := fixture()
	for _, kind := range []string{"symlink", "hardlink", "public", "corrupt", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			s, path := newStore(t, trust, fixed(p.IssuedAt))
			file := filepath.Join(path, "policy.json")
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(target, file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, file); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(file, signed(p, key), 0644); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(file, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				makeFIFO(t, file)
			}
			if _, err := s.Install(signed(p, key)); err == nil {
				t.Fatal("unsafe state overwritten")
			}
			b, err := os.ReadFile(target)
			if err != nil || string(b) != "untouched" {
				t.Fatal("target modified")
			}
		})
	}
}

func TestStoreClockRecheckedAtCommit(t *testing.T) {
	trust, p, key := fixture()
	now := p.IssuedAt
	s, _ := newStore(t, trust, ClockFunc(func() (time.Time, bool) { return time.Unix(now, 0), true }))
	s.checkpoint = func(stage string) error {
		if stage == "file_synced" {
			now = p.ExpiresAt
		}
		return nil
	}
	_, err := s.Install(signed(p, key))
	requireCode(t, err, "policy_expired")
	_, err = s.Load()
	requireCode(t, err, "policy_missing")
}

func TestStoreConcurrentHighWater(t *testing.T) {
	trust, p, key := fixture()
	s, path := newStore(t, trust, fixed(p.IssuedAt))
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 2; i <= 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			other, err := OpenStore(path, trust, fixed(p.IssuedAt))
			if err != nil {
				t.Error(err)
				return
			}
			defer other.Close()
			next := p
			next.Sequence = uint64(n)
			_, err = other.Install(signed(next, key))
			if err != nil && fail.Token(err) != "policy_store_busy" && fail.Token(err) != "policy_rollback" {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	p.Sequence = 11
	if _, err := s.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	d, err := s.Load()
	if err != nil || d.Policy().Sequence != 11 {
		t.Fatal(d, err)
	}
}
