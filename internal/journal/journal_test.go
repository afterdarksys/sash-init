// SPDX-License-Identifier: GPL-3.0-or-later

package journal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestRotationRecoveryAndSequence(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	j, err := Open(dir, 64*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		j.Emit(Record{Unit: "service", Stream: "stdout", Data: make([]byte, 4096)})
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := Read(dir)
	if err != nil || len(records) == 0 {
		t.Fatalf("%d %v", len(records), err)
	}
	last := records[len(records)-1].Sequence
	if last != 100 || records[0].Sequence == 1 {
		t.Fatalf("rotation failed: first=%d last=%d", records[0].Sequence, last)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		st, _ := e.Info()
		if st.Size() > 64*1024 {
			t.Fatalf("unbounded %s", e.Name())
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, "current.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"torn":`)
	f.Close()
	j, err = Open(dir, 64*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	j.Emit(Record{Unit: "service", Stream: "stderr", Data: []byte("after restart")})
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	records, err = Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := records[len(records)-1]; r.Sequence != 101 || string(r.Data) != "after restart" || r.BootID == "" {
		t.Fatalf("%+v", r)
	}
}

func TestJournalRefusesLinksAndConcurrentWriter(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	j, err := Open(dir, 64*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, 64*1024, 1); err == nil {
		t.Fatal("second writer admitted")
	}
	j.Close()
	other := t.TempDir()
	os.Chmod(other, 0700)
	os.Symlink(filepath.Join(dir, "current.jsonl"), filepath.Join(other, "current.jsonl"))
	if _, err := Open(other, 64*1024, 1); err == nil {
		t.Fatal("symlink admitted")
	}
	j = &Journal{queue: make(chan Record, 1)}
	j.Emit(Record{})
	j.Emit(Record{})
	if j.Stats().Dropped != 1 {
		t.Fatal("overflow invisible")
	}
}

// A journal file with a second hard link is refused: the link could be a
// name somebody else reads or replaces.
func TestHardLinkedFileRefused(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	j, err := Open(dir, 64*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	if err := os.Link(filepath.Join(dir, "current.jsonl"), filepath.Join(dir, "other")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, 64*1024, 1); fail.Token(err) != "journal_perm" {
		t.Fatalf("open: %v", err)
	}
	if _, err := Read(dir); fail.Token(err) != "journal_perm" {
		t.Fatalf("read: %v", err)
	}
}
