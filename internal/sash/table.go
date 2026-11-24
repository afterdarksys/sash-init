package sash

import (
	"sync"
	"time"
)

// Table is one service's name-to-process table: the only handle a script
// has on a process it spawned. It lives as long as the service's start
// (across its sessions: start spawns, stop signals and waits) and is reset
// at the next start.
//
// Threats: a script names a process, never a pid, and only this service's
// table is consulted, so it cannot reach another service's process or an
// arbitrary pid. A name stays bound to its process after it exits, until
// the next start, so a later spawn cannot take a name an earlier one held
// while that one runs (name_in_use).
type Table struct {
	mu    sync.Mutex
	procs map[string]*Proc
	order []string
	// Changed, when set, is called (without the table lock) whenever a
	// process ends.
	Changed func()
}

// NewTable is an empty table.
func NewTable() *Table { return &Table{procs: map[string]*Proc{}} }

// Proc is one spawned process.
type Proc struct {
	Name    string
	Pid     int
	Started time.Time
	Stdout  *Tail
	Stderr  *Tail
	// Handle is the host's (a pidfd, a command).
	Handle any

	mu     sync.Mutex
	done   chan struct{}
	ended  bool
	exit   int
	signal string
	at     time.Time
	ready  bool
	table  *Table
}

// Reserve binds name to a new process record, or is false when a process
// of this service already holds it and is still running.
func (t *Table) Reserve(name string) (*Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.procs[name]; p != nil && !p.Ended() {
		return nil, false
	}
	p := &Proc{Name: name, done: make(chan struct{}), Stdout: NewTail(), Stderr: NewTail(), table: t}
	if _, ok := t.procs[name]; !ok {
		t.order = append(t.order, name)
	}
	t.procs[name] = p
	return p, true
}

// Release drops a reservation whose spawn failed.
func (t *Table) Release(p *Proc) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.procs[p.Name] == p {
		delete(t.procs, p.Name)
		for i, n := range t.order {
			if n == p.Name {
				t.order = append(t.order[:i], t.order[i+1:]...)
				break
			}
		}
	}
}

// Get is name's process, or nil.
func (t *Table) Get(name string) *Proc {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.procs[name]
}

// All is every process, in spawn order of their names.
func (t *Table) All() []*Proc {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Proc, 0, len(t.order))
	for _, n := range t.order {
		out = append(out, t.procs[n])
	}
	return out
}

// Running counts the processes that have not ended.
func (t *Table) Running() int {
	n := 0
	for _, p := range t.All() {
		if !p.Ended() {
			n++
		}
	}
	return n
}

// Ended reports whether the process has exited and been collected.
func (p *Proc) Ended() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ended
}

// Done is closed when the process ends.
func (p *Proc) Done() <-chan struct{} { return p.done }

// Exit records how the process ended: its exit status, or the name of the
// signal that ended it.
func (p *Proc) Exit(code int, signal string, at time.Time) {
	p.mu.Lock()
	if p.ended {
		p.mu.Unlock()
		return
	}
	p.ended, p.exit, p.signal, p.at = true, code, signal, at
	p.mu.Unlock()
	close(p.done)
	if p.table != nil && p.table.Changed != nil {
		p.table.Changed()
	}
}

// Result is the exit status, signal and end time once Ended.
func (p *Proc) Result() (int, string, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exit, p.signal, p.at
}

// SetReady marks the process ready (it wrote to its readiness fd).
func (p *Proc) SetReady() {
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
}

// Ready reports whether the process said it was ready.
func (p *Proc) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready
}

// Failed reports whether any process ended with a non-zero status or a
// signal.
func (t *Table) Failed() bool {
	for _, p := range t.All() {
		if p.Ended() {
			if code, sig, _ := p.Result(); code != 0 || sig != "" {
				return true
			}
		}
	}
	return false
}

const (
	tailBytes = 64 * 1024
	tailLines = 1000
)

// Tail keeps the last lines a process wrote, bounded in bytes and lines.
type Tail struct {
	mu      sync.Mutex
	lines   []string
	partial []byte
	size    int
	// Copy, when set, also receives each complete line.
	Copy func(line string)
}

// NewTail is an empty tail.
func NewTail() *Tail { return &Tail{} }

func (t *Tail) Write(b []byte) (int, error) {
	t.mu.Lock()
	var done []string
	for _, c := range b {
		if c == '\n' {
			done = append(done, string(t.partial))
			t.push(string(t.partial))
			t.partial = t.partial[:0]
			continue
		}
		if len(t.partial) < 4096 {
			t.partial = append(t.partial, c)
		}
	}
	cp := t.Copy
	t.mu.Unlock()
	if cp != nil {
		for _, l := range done {
			cp(l)
		}
	}
	return len(b), nil
}

func (t *Tail) push(l string) {
	t.lines = append(t.lines, l)
	t.size += len(l)
	for len(t.lines) > tailLines || t.size > tailBytes {
		t.size -= len(t.lines[0])
		t.lines = t.lines[1:]
	}
}

// Lines is the last n lines (all when n <= 0), the unfinished one included.
func (t *Tail) Lines(n int) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := append([]string(nil), t.lines...)
	if len(t.partial) > 0 {
		out = append(out, string(t.partial))
	}
	if n > 0 && n < len(out) {
		out = out[len(out)-n:]
	}
	return out
}
