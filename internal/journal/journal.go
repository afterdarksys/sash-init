// SPDX-License-Identifier: GPL-3.0-or-later

// Package journal stores bounded JSON records outside PID 1. Producers never
// wait for disk: a full queue drops records and exposes the count in Stats.
package journal

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

const MaxRecord = 32 * 1024

type Record struct {
	Sequence uint64          `json:"sequence"`
	BootID   string          `json:"boot_id"`
	Time     time.Time       `json:"time"`
	Unit     string          `json:"unit"`
	Stream   string          `json:"stream"`
	Data     []byte          `json:"data,omitempty"`
	Event    json.RawMessage `json:"event,omitempty"`
}
type Stats struct {
	Dropped uint64 `json:"dropped"`
	Error   string `json:"error,omitempty"`
}
type Journal struct {
	dir, boot string
	max       int64
	keep      int
	queue     chan Record
	done      chan struct{}
	lock      *os.File
	mu        sync.RWMutex
	closed    bool
	dropped   atomic.Uint64
	errMu     sync.Mutex
	err       error
}

func BootID() string {
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return strings.TrimSpace(string(b))
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func Open(dir string, maxBytes int64, keep int) (*Journal, error) {
	if maxBytes < 64*1024 || maxBytes > 64*1024*1024 || keep < 1 || keep > 16 {
		return nil, fail.E("journal_limits")
	}
	if !filepath.IsAbs(dir) {
		return nil, fail.E("journal_path")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	trusted, err := unit.TrustedDir(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(trusted)
	if err != nil || st.Mode().Perm()&0077 != 0 {
		return nil, fail.E("journal_perm")
	}
	lock, err := openFile(filepath.Join(trusted, "lock"), unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fail.E("journal_busy")
	}
	j := &Journal{dir: trusted, boot: BootID(), max: maxBytes, keep: keep, queue: make(chan Record, 256), done: make(chan struct{}), lock: lock}
	// Validate existing files before a writer is launched.
	records, err := Read(trusted)
	if err != nil {
		lock.Close()
		return nil, err
	}
	var seq uint64
	for _, r := range records {
		if r.Sequence > seq {
			seq = r.Sequence
		}
	}
	f, err := openFile(filepath.Join(trusted, "current.jsonl"), unix.O_RDWR|unix.O_APPEND|unix.O_CREAT)
	if err != nil {
		lock.Close()
		return nil, err
	}
	if err := repairTail(f); err != nil {
		f.Close()
		lock.Close()
		return nil, err
	}
	go j.write(f, seq)
	return j, nil
}

func repairTail(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return nil
	}
	n := st.Size()
	if n > MaxRecord+1 {
		n = MaxRecord + 1
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, st.Size()-n); err != nil {
		return err
	}
	if b[len(b)-1] == '\n' {
		return nil
	}
	last := bytes.LastIndexByte(b, '\n')
	if last < 0 && st.Size() > n {
		return fail.E("journal_torn_record")
	}
	return f.Truncate(st.Size() - n + int64(last+1))
}

func openFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0077 != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		f.Close()
		return nil, fail.E("journal_perm")
	}
	return f, nil
}

func (j *Journal) Emit(r Record) {
	if j == nil {
		return
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.closed {
		return
	}
	if len(r.Data) > 8192 {
		r.Data = r.Data[:8192]
		j.dropped.Add(1)
	}
	r.Data = append([]byte(nil), r.Data...)
	r.Event = append(json.RawMessage(nil), r.Event...)
	r.Time = time.Now().UTC()
	select {
	case j.queue <- r:
	default:
		j.dropped.Add(1)
	}
}
func (j *Journal) Stats() Stats {
	if j == nil {
		return Stats{}
	}
	j.errMu.Lock()
	defer j.errMu.Unlock()
	s := Stats{Dropped: j.dropped.Load()}
	if j.err != nil {
		s.Error = "journal_write"
	}
	return s
}
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	if !j.closed {
		j.closed = true
		close(j.queue)
	}
	j.mu.Unlock()
	<-j.done
	j.errMu.Lock()
	defer j.errMu.Unlock()
	return j.err
}
func (j *Journal) failed(err error) {
	if err == nil {
		return
	}
	j.errMu.Lock()
	if j.err == nil {
		j.err = err
	}
	j.errMu.Unlock()
}
func (j *Journal) write(f *os.File, seq uint64) {
	defer close(j.done)
	defer j.lock.Close()
	defer func() {
		if f != nil {
			j.failed(f.Sync())
			j.failed(f.Close())
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	st, _ := f.Stat()
	size := st.Size()
	for {
		select {
		case r, ok := <-j.queue:
			if !ok {
				return
			}
			seq++
			r.Sequence = seq
			r.BootID = j.boot
			b, err := json.Marshal(r)
			if err != nil || len(b) > MaxRecord {
				j.dropped.Add(1)
				continue
			}
			b = append(b, '\n')
			if size+int64(len(b)) > j.max {
				j.failed(f.Sync())
				j.failed(f.Close())
				f = nil
				if err := j.rotate(); err != nil {
					j.failed(err)
					return
				}
				f, err = openFile(filepath.Join(j.dir, "current.jsonl"), unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT)
				if err != nil {
					j.failed(err)
					return
				}
				size = 0
			}
			n, err := f.Write(b)
			size += int64(n)
			if err != nil {
				j.failed(err)
				return
			}
		case <-tick.C:
			j.failed(f.Sync())
		}
	}
}
func (j *Journal) rotate() error {
	view, err := viewLock(j.dir, unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer view.Close()
	for i := j.keep - 1; i >= 1; i-- {
		from := filepath.Join(j.dir, fmt.Sprintf("archive.%d.jsonl", i-1))
		to := filepath.Join(j.dir, fmt.Sprintf("archive.%d.jsonl", i))
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(filepath.Join(j.dir, "current.jsonl"), filepath.Join(j.dir, "archive.0.jsonl")); err != nil {
		return err
	}
	d, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Read ignores only a final torn record (power loss or a concurrent append).
// Complete malformed records are errors. Files and individual records are bounded.
func Read(dir string) ([]Record, error) {
	view, err := viewLock(dir, unix.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer view.Close()
	var out []Record
	for i := 15; i >= -1; i-- {
		name := fmt.Sprintf("archive.%d.jsonl", i)
		if i < 0 {
			name = "current.jsonl"
		}
		f, err := openFile(filepath.Join(dir, name), unix.O_RDONLY)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil || st.Size() > 64*1024*1024 {
			f.Close()
			return nil, fail.E("journal_size")
		}
		r := bufio.NewReaderSize(f, MaxRecord+1)
		for {
			line, err := r.ReadSlice('\n')
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				f.Close()
				return nil, err
			}
			var record Record
			if err := json.Unmarshal(line, &record); err != nil {
				f.Close()
				return nil, err
			}
			out = append(out, record)
		}
		f.Close()
	}
	return out, nil
}

func viewLock(dir string, how int) (*os.File, error) {
	f, err := openFile(filepath.Join(dir, "view.lock"), unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
