// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"encoding/json"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/journal"
	"strings"
	"sync"
	"time"
)

const logCapacity = 8192
const eventCapacity = 64

// tail is a bounded byte ring. Writes never wait for a reader or storage.
type tail struct {
	mu    sync.Mutex
	data  [logCapacity]byte
	total uint64
	emit  func([]byte)
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	start := 0
	if n > logCapacity {
		start = n - logCapacity
	}
	for i := start; i < n; i++ {
		t.data[(t.total+uint64(i))%logCapacity] = p[i]
	}
	t.total += uint64(n)
	if t.emit != nil {
		t.emit(p)
	}
	return n, nil
}

type LogTail struct {
	Data    []byte `json:"data"` // JSON base64 preserves arbitrary process output.
	Dropped uint64 `json:"dropped"`
}

func (t *tail) snapshot() LogTail {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.total
	if n > logCapacity {
		n = logCapacity
	}
	out := LogTail{Data: make([]byte, int(n)), Dropped: t.total - n}
	for i := range out.Data {
		out.Data[i] = t.data[(out.Dropped+uint64(i))%logCapacity]
	}
	return out
}

type Event struct {
	Sequence uint64    `json:"sequence"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	PID      int       `json:"pid"`
	Code     string    `json:"code,omitempty"`
	Exit     *Exit     `json:"exit,omitempty"`
}

type Exit struct {
	Code   int       `json:"code"`
	Signal int       `json:"signal"`
	Time   time.Time `json:"time"`
}

type Diagnostics struct {
	LastExit *Exit         `json:"last_exit,omitempty"`
	Name     string        `json:"name"`
	Cgroups  string        `json:"cgroups"`
	Stdout   LogTail       `json:"stdout"`
	Stderr   LogTail       `json:"stderr"`
	Events   []Event       `json:"events"`
	Journal  journal.Stats `json:"journal"`
}

// eventLocked requires runtime.mu; events never include argv or environment.
func (s *runtime) eventLocked(kind, code string, exit *Exit) {
	fail.Note(kind)
	// A sash entry event's code is the first word of the entry's stderr:
	// the service chose it, so it is not a catalog code.
	if !strings.HasPrefix(kind, "sash_") {
		fail.Note(code)
	}
	s.eventSeq++
	e := Event{Sequence: s.eventSeq, Time: time.Now().UTC(), Kind: kind, PID: s.pid, Code: code, Exit: exit}
	if len(s.events) == eventCapacity {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = e
	} else {
		s.events = append(s.events, e)
	}
	if s.records != nil {
		raw, _ := json.Marshal(e)
		s.records.Emit(journal.Record{Unit: s.svc.Name, Stream: "event", Event: raw})
	}
}

func (sup *Supervisor) Diagnostics(name string) (*Diagnostics, error) {
	s, err := sup.lookup(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	events := append([]Event{}, s.events...)
	lastExit := s.lastExit
	s.mu.Unlock()
	return &Diagnostics{Name: name, Cgroups: sup.cgroupMode(), Stdout: s.stdout.snapshot(), Stderr: s.stderr.snapshot(), Events: events, LastExit: lastExit, Journal: s.records.Stats()}, nil
}

// SetJournal is called before starting services. The journal is owned by the
// caller so it can outlive catalog transactions and be closed after shutdown.
func (sup *Supervisor) SetJournal(j *journal.Journal) {
	sup.journal = j
	for name, s := range sup.runtimes() {
		s.records = j
		for stream, tail := range map[string]*tail{"stdout": &s.stdout, "stderr": &s.stderr} {
			tail.emit = func(p []byte) {
				for len(p) > 0 {
					n := len(p)
					if n > 8192 {
						n = 8192
					}
					j.Emit(journal.Record{Unit: name, Stream: stream, Data: p[:n]})
					p = p[n:]
				}
			}
		}
	}
}
