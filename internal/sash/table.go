package sash

import (
	"sync"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
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
	mu     sync.Mutex
	procs  map[string]*Proc
	order  []string
	budget budget
	// mounts are the mount points this service mounted, oldest first.
	mounts []string
	// Changed, when set, is called (without the table lock) whenever a
	// process ends.
	Changed func()
}

// NewTable is an empty table.
func NewTable() *Table { return &Table{procs: map[string]*Proc{}, budget: budget{max: MaxOutput}} }

// Proc is one spawned process. Its pid, start time and host handle are
// set once, by the host's Spawn, while other goroutines may read the table.
type Proc struct {
	Name   string
	Stdout *Tail
	Stderr *Tail

	mu      sync.Mutex
	pid     int
	started time.Time
	handle  any
	done    chan struct{}
	ended   bool
	exit    int
	signal  string
	at      time.Time
	ready   bool
	table   *Table
}

// MaxNames is the most process names one service may bind.
const MaxNames = 64

// Reserve binds name to a new process record. It is name_in_use when a
// process of this service holds the name and still runs, and
// too_many_names past MaxNames.
func (t *Table) Reserve(name string) (*Proc, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.procs[name]; p != nil && !p.Ended() {
		return nil, fail.E("name_in_use")
	}
	if _, ok := t.procs[name]; !ok && len(t.procs) >= MaxNames {
		return nil, fail.E("too_many_names")
	}
	if old := t.procs[name]; old != nil {
		old.Stdout.Free()
		old.Stderr.Free()
	}
	p := &Proc{Name: name, done: make(chan struct{}), Stdout: &Tail{budget: &t.budget}, Stderr: &Tail{budget: &t.budget}, table: t}
	if _, ok := t.procs[name]; !ok {
		t.order = append(t.order, name)
	}
	t.procs[name] = p
	return p, nil
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

// Started records what the host started: pid, start time and its handle
// (a pidfd, a command).
func (p *Proc) Started(pid int, at time.Time, handle any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pid, p.started, p.handle = pid, at, handle
}

// Pid is the process id, 0 before Started.
func (p *Proc) Pid() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// StartedAt is the start time.
func (p *Proc) StartedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.started
}

// Handle is the host's handle.
func (p *Proc) Handle() any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.handle
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
	// MaxOutput bounds all captured output of one service.
	MaxOutput = 1 << 20
)

// budget is the bytes a service's tails may hold together.
type budget struct {
	mu   sync.Mutex
	used int
	max  int
}

// take reserves n bytes, or is false when that would pass max.
func (b *budget) take(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.max {
		return false
	}
	b.used += n
	return true
}

func (b *budget) give(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
}

// Used is the bytes the table's tails hold.
func (t *Table) Used() int {
	t.budget.mu.Lock()
	defer t.budget.mu.Unlock()
	return t.budget.used
}

// Tail keeps the last lines a process wrote, bounded in bytes and lines,
// and within its service's MaxOutput: past that its own oldest lines go
// first, and a line that still does not fit is dropped.
type Tail struct {
	mu      sync.Mutex
	lines   []string
	partial []byte
	size    int
	budget  *budget
	// Copy, when set, also receives each complete line.
	Copy func(line string)
}

// NewTail is an empty tail with no service budget.
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

func (t *Tail) dropOldest() {
	t.size -= len(t.lines[0])
	t.budget.give(len(t.lines[0]))
	t.lines[0] = ""
	t.lines = t.lines[1:]
}

func (t *Tail) push(l string) {
	for !t.budget.take(len(l)) {
		if len(t.lines) == 0 {
			return
		}
		t.dropOldest()
	}
	t.lines = append(t.lines, l)
	t.size += len(l)
	for len(t.lines) > tailLines || t.size > tailBytes {
		t.dropOldest()
	}
}

// Free drops every line, giving the bytes back to the service.
func (t *Tail) Free() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.budget.give(t.size)
	t.lines, t.partial, t.size = nil, nil, 0
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

// Mount records a mount this service made at dir.
func (t *Table) Mount(dir string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mounts = append(t.mounts, dir)
}

// Mounted reports whether this service mounted dir.
func (t *Table) Mounted(dir string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return exact(t.mounts, dir)
}

// Unmounted forgets the mount at dir.
func (t *Table) Unmounted(dir string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, d := range t.mounts {
		if d == dir {
			t.mounts = append(t.mounts[:i], t.mounts[i+1:]...)
			return
		}
	}
}

// Mounts is every mount this service made, newest first.
func (t *Table) Mounts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.mounts))
	for i := len(t.mounts) - 1; i >= 0; i-- {
		out = append(out, t.mounts[i])
	}
	return out
}
