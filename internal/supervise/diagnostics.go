package supervise

import (
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
	LastExit *Exit   `json:"last_exit,omitempty"`
	Name     string  `json:"name"`
	Cgroups  string  `json:"cgroups"`
	Stdout   LogTail `json:"stdout"`
	Stderr   LogTail `json:"stderr"`
	Events   []Event `json:"events"`
}

// eventLocked requires runtime.mu; events never include argv or environment.
func (s *runtime) eventLocked(kind, code string, exit *Exit) {
	s.eventSeq++
	e := Event{Sequence: s.eventSeq, Time: time.Now().UTC(), Kind: kind, PID: s.pid, Code: code, Exit: exit}
	if len(s.events) == eventCapacity {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = e
	} else {
		s.events = append(s.events, e)
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
	return &Diagnostics{Name: name, Cgroups: sup.cgroupMode(), Stdout: s.stdout.snapshot(), Stderr: s.stderr.snapshot(), Events: events, LastExit: lastExit}, nil
}
