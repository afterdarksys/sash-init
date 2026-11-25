// SPDX-License-Identifier: GPL-3.0-or-later

// Package supervise runs a static service catalog in the calling process.
//
// Threats: the control socket is local and uid-gated. A denied peer is
// refused before the body is acted on, and a peer-cred failure denies the
// caller. A peer inside a service's cgroup, or a process group a service
// has led, is refused (peer_supervised), so a service cannot drive the
// supervisor. The supervisor holds no keys, does not understand leases, and
// does not log oneshot arguments. A sandbox claim is stored only when Launch
// returns it. With cgroups, a service is its cgroup: when its main process
// exits, for any reason, everything left in the cgroup is killed and the
// service has ended only once the cgroup is empty (cgroup_stuck otherwise).
// Stop sends SIGTERM to the process group, under the service lock and only
// while the leader is unreaped or through a pidfd (see
// runtime.signalGroup), and SIGKILL through cgroup.kill. Without cgroups
// (--no-cgroups, or off Linux) process groups decide, as before. This
// package does not confine the network beyond the sandbox package and does
// not check leases.
package supervise

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/journal"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const (
	claimNone = "none"

	defaultBurst  = 5
	defaultWindow = 30 * time.Second
	maxArgv       = 32
)

var argRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Row is one status record. Fields are always encoded, including zeroes,
// except usage, which is present only while the service cgroup exists.
type Row struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Pid       int    `json:"pid"`
	Ready     bool   `json:"ready"`
	Restarts  int    `json:"restarts"`
	Sandbox   string `json:"sandbox"`
	LastError string `json:"last_error"`
	Desired   bool   `json:"desired"`
	Essential bool   `json:"essential"`
	// Cgroups is "enabled", "disabled" (--no-cgroups) or "unsupported".
	Cgroups string `json:"cgroups"`
	Cgroup  string `json:"cgroup"` // the service cgroup when enabled
	// CgroupTrusted marks a service with no sandbox running as root or as
	// the supervisor's uid: it can leave its cgroup, so kill-all, limits and
	// peer_supervised are not promised for it.
	CgroupTrusted bool          `json:"cgroup_trusted"`
	Limits        RowLimits     `json:"limits"`
	Usage         *cgroup.Usage `json:"usage,omitempty"`
	// Sash is present for a sash unit: its entry results, name table and
	// grant serial, never the grant body or env values.
	Sash *SashRow `json:"sash,omitempty"`
}

// RowLimits are a unit's cgroup limits; zero or empty is no limit.
type RowLimits struct {
	MemoryMax uint64 `json:"memory_max"`
	CPUMax    string `json:"cpu_max"`
	PidsMax   uint64 `json:"pids_max"`
}

// Cgroup modes reported in status and diagnostics.
const (
	CgroupsEnabled     = "enabled"
	CgroupsDisabled    = "disabled"
	CgroupsUnsupported = "unsupported"
)

// Supervisor is the userspace service supervisor. It is not PID 1.
type Supervisor struct {
	catalogMu       sync.RWMutex
	transaction     sync.RWMutex
	previous        map[string]*unit.Service
	previousDesired map[string]bool
	generation      uint64
	journal         *journal.Journal
	admit           func(string, bool) error
	retired         []*runtime
	Signed          bool
	OnActivate      func(context.Context) (CatalogDiff, error)
	self            string
	rt              map[string]*runtime
	mu              sync.Mutex
	ln              *net.UnixListener
	bound           string
	lock            *os.File // flock on bound + ".lock", held while bound
	serving         atomic.Bool
	shuttingDown    atomic.Bool
	// booted is set by the caller once the boot waves ended without a
	// strict failure; catalog changes wait for it (boot_in_progress).
	booted atomic.Bool
	// bootRec is this boot's record for the boot verbs, made on first use.
	bootOnce      sync.Once
	bootRec       *sash.BootState
	RestartBurst  int
	RestartWindow time.Duration
	// stableMin replaces the 10 s minimum a run must stay ready to reset
	// the crash count (tests only).
	stableMin time.Duration
	Allow     map[uint32]struct{}
	// SocketGID is the socket's group when Allow names a uid other than
	// the supervisor's own; the socket is then mode 0660.
	SocketGID    *uint32
	MaxHandlers  int
	ReadDeadline time.Duration
	// Cgroups is the delegated cgroup root. When nil, process groups decide
	// as before, and CgroupMode (CgroupsDisabled by default, or
	// CgroupsUnsupported) says why. Set both before Boot.
	Cgroups    *cgroup.Root
	CgroupMode string
	// Log, when set, receives one line per stray process killed
	// ("cgroup_stray PID").
	Log io.Writer
	// Sash, when set, runs sash units (sash.go). Set before Boot.
	Sash *SashConfig
	// mountReg holds every sash service's mounts (sash_mounts_linux.go).
	mountsOnce sync.Once
	mountReg   *mountRegistry
	// lookupUser and lookupGroup replace the system's name lookup in
	// tests.
	lookupUser, lookupGroup func(string) (uint32, error)
	// launching is held (read) while a child may sit in the supervisor's
	// leaf before joining its cgroup, so the stray sweep skips that time.
	launching sync.RWMutex
}

type runtime struct {
	// records is the persistent journal (--log-dir), nil without one.
	records    *journal.Journal
	stdout     tail
	stderr     tail
	events     []Event
	eventSeq   uint64
	lastExit   *Exit
	svc        *unit.Service
	op         sync.Mutex
	mu         sync.Mutex
	state      string
	desired    bool
	pid        int
	ready      bool
	restarts   int
	sandbox    string
	lastError  string
	gen        uint64
	stopReq    bool
	timedOut   bool
	restartsAt []time.Time
	// readyAt is when the current run became ready; crashes counts the
	// automatic restarts since a run stayed ready for stableFor; backoff
	// is set while a restart waits out its delay.
	readyAt  time.Time
	crashes  int
	backoff  bool
	procDone chan struct{}
	readyCh  chan struct{}
	cmd      *exec.Cmd
	// group is the pid of the last started process, which leads its own
	// process group; pidfd is a pidfd for it (-1 when unavailable). Both are
	// kept after it exits, for signalling what remains of its group, and
	// replaced at the next start. exiting is set, under mu, before the
	// leader is reaped.
	group   int
	pidfd   int
	exiting bool
	// led holds the groups this service led before the current one, kept
	// until each is empty, so their leftover members stay recognisable.
	led []ledGroup
	// cg is the cgroup root the last start used (nil without cgroups), and
	// cgErr a failure to empty the service cgroup (cgroup_stuck), which
	// makes the service failed whatever else happened.
	cg    *cgroup.Root
	cgErr string
	// sash is a sash unit's name table and entry results (sash.go).
	sash *sashState
	// journal limits the journal lines this service copies to the log.
	journal *lineBucket
}

type ledGroup struct {
	pid, pidfd int
}

// retireGroupLocked moves the current group to led before a new start, and
// drops led groups that are empty. Caller holds mu.
func (s *runtime) retireGroupLocked() {
	if s.group > 0 {
		s.led = append(s.led, ledGroup{pid: s.group, pidfd: s.pidfd})
	}
	s.group, s.pidfd = 0, -1
	kept := s.led[:0]
	for _, g := range s.led {
		if groupEmpty(g.pid, g.pidfd) {
			closePidfd(g.pidfd)
			continue
		}
		kept = append(kept, g)
	}
	s.led = kept
}

// ledGroupLocked reports whether pgid is a non-empty group this service has
// led, now or before. Caller holds mu.
func (s *runtime) ledGroupLocked(pgid int) bool {
	if pgid <= 0 {
		return false
	}
	if s.group == pgid && !groupEmpty(s.group, s.pidfd) {
		return true
	}
	for _, g := range s.led {
		if g.pid == pgid && !groupEmpty(g.pid, g.pidfd) {
			return true
		}
	}
	return false
}

// groupEmpty reports whether the group led by pid has no members. With a
// pidfd on Linux 6.9+ it asks about that exact pid, so a reused number reads
// as empty; otherwise it asks kill(-pid, 0).
func groupEmpty(pid, pidfd int) bool {
	if pidfd >= 0 {
		err := pidfdSignalGroup(pidfd, 0)
		if err != syscall.EINVAL && err != syscall.ENOSYS {
			return err == syscall.ESRCH
		}
	}
	return syscall.Kill(-pid, 0) == syscall.ESRCH
}

// New checks the catalog and the re-exec binary. self is not required to be absolute.
func New(svcs map[string]*unit.Service, self string) (*Supervisor, error) {
	if self == "" || len(svcs) == 0 {
		return nil, fail.E("failed")
	}
	if err := unit.ExecFile(self); err != nil {
		return nil, err
	}
	rt := make(map[string]*runtime, len(svcs))
	for name, svc := range svcs {
		if svc == nil || name != svc.Name {
			return nil, fail.E("failed")
		}
		done := make(chan struct{})
		close(done)
		rt[name] = &runtime{
			svc:      svc,
			state:    "stopped",
			procDone: done,
			pidfd:    -1,
		}
	}
	return &Supervisor{
		self:          self,
		rt:            rt,
		RestartBurst:  defaultBurst,
		RestartWindow: defaultWindow,
		ReadDeadline:  5 * time.Second,
		MaxHandlers:   32,
	}, nil
}

// Boot starts each wave in parallel and continues after a wave error.
// allowEmpty is the boot oneshot path: a socket oneshot still needs an arg.
func (sup *Supervisor) Boot(ctx context.Context, waves [][]string) error {
	if !sup.transaction.TryRLock() {
		return fail.E("busy")
	}
	defer sup.transaction.RUnlock()
	var first error
	for _, wave := range waves {
		errs := make([]error, len(wave))
		var wg sync.WaitGroup
		for i, name := range wave {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				allowEmpty := false
				if s, _ := sup.runtime(name); s != nil && s.svc.Type == "oneshot" {
					allowEmpty = true
				}
				errs[i] = sup.start(ctx, name, "", allowEmpty, true)
			}(i, name)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// Start starts a stopped, failed, or exited service. A running service is busy.
func (sup *Supervisor) Start(ctx context.Context, name string) error {
	if !sup.transaction.TryRLock() {
		return fail.E("busy")
	}
	defer sup.transaction.RUnlock()
	return sup.start(ctx, name, "", false, true)
}

// Oneshot runs a catalog oneshot with one checked arg. The arg is not logged.
func (sup *Supervisor) Oneshot(ctx context.Context, name, arg string) error {
	if !sup.transaction.TryRLock() {
		return fail.E("busy")
	}
	defer sup.transaction.RUnlock()
	s, err := sup.lookup(name)
	if err != nil {
		return err
	}
	if s.svc.Type != "oneshot" {
		return fail.E("not_oneshot")
	}
	if err := argOK(arg); err != nil {
		return err
	}
	return sup.start(ctx, name, arg, false, true)
}

// Stop signals the process group. A stopped or exited service stays as it is.
func (sup *Supervisor) Stop(ctx context.Context, name string) error {
	if !sup.transaction.TryRLock() {
		return fail.E("busy")
	}
	defer sup.transaction.RUnlock()
	return sup.stop(ctx, name, true)
}

func (sup *Supervisor) stop(ctx context.Context, name string, user bool) error {
	if ctx == nil || ctx.Err() != nil {
		return fail.E("failed")
	}
	s, err := sup.lookup(name)
	if err != nil {
		return err
	}
	if s.svc.Sash != nil {
		s.mu.Lock()
		if user {
			s.desired = false
		}
		if s.state == "blocked" {
			s.state, s.lastError = "stopped", ""
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		return sup.stopSash(ctx, s)
	}
	if !s.op.TryLock() {
		return fail.E("busy")
	}
	defer s.op.Unlock()

	s.mu.Lock()
	if user {
		s.desired = false
	}
	state := s.state
	pid := s.pid
	if state == "stopped" || state == "exited" || state == "blocked" {
		if state == "blocked" {
			s.state = "stopped"
			s.lastError = ""
		}
		s.mu.Unlock()
		return nil
	}
	if state == "failed" && pid == 0 {
		s.state = "stopped"
		s.ready = false
		s.lastError = ""
		s.mu.Unlock()
		return nil
	}
	if state == "stopping" {
		s.mu.Unlock()
		return fail.E("busy")
	}
	if (state == "starting" || state == "running") && pid <= 0 {
		s.gen++
		s.stopReq = true
		s.state = "stopped"
		s.ready = false
		s.pid = 0
		s.mu.Unlock()
		return nil
	}
	s.gen++
	gen := s.gen
	s.stopReq = true
	s.eventLocked("stopping", "", nil)
	s.state = "stopping"
	procDone := s.procDone
	s.mu.Unlock()

	if err := s.signalGroup(pid, syscall.SIGTERM); err != nil {
		return fail.E("failed")
	}
	if err := s.waitGroup(ctx, pid, procDone, timeoutOf(s.svc)); err != nil {
		if killErr := s.signalGroup(pid, syscall.SIGKILL); killErr != nil {
			return fail.E("failed")
		}
		<-procDone
		if ctx.Err() != nil {
			s.finishStop(gen)
			return fail.E("timeout")
		}
	}
	return s.finishStop(gen)
}

// finishStop marks the service stopped, or failed with the cgroup error
// when its cgroup could not be emptied, which it returns.
func (s *runtime) finishStop(gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "stopping" && s.gen == gen {
		s.ready = false
		s.pid = 0
		s.stopReq = false
		if s.cgErr != "" {
			s.state = "failed"
			s.lastError = s.cgErr
			return fail.E(s.cgErr)
		}
		s.state = "stopped"
	}
	return nil
}

// Restart stops and then starts. A user start clears the restart burst.
func (sup *Supervisor) Restart(ctx context.Context, name string) error {
	if !sup.transaction.TryRLock() {
		return fail.E("busy")
	}
	defer sup.transaction.RUnlock()
	if err := sup.stop(ctx, name, true); err != nil {
		return err
	}
	return sup.start(ctx, name, "", false, true)
}

// Shutdown stops dependents before their providers, concurrently within waves.
// It does not take the per-service operation lock.
func (sup *Supervisor) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sup.shuttingDown.Store(true)
	sup.transaction.RLock()
	defer sup.transaction.RUnlock()
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var first error
	note := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if first == nil {
			first = err
		}
		errMu.Unlock()
	}
	catalog := make(map[string]*unit.Service, len(sup.runtimes()))
	for name, s := range sup.runtimes() {
		catalog[name] = s.svc
	}
	waves, err := graph.ShutdownPlan(catalog)
	if err != nil {
		// Even a malformed programmatically constructed catalog must stop.
		note(err)
		var names []string
		for name := range sup.runtimes() {
			names = append(names, name)
		}
		waves = [][]string{names}
	}
	for _, wave := range waves {
		for _, name := range wave {
			s, _ := sup.runtime(name)
			if s.svc.Sash != nil {
				s.mu.Lock()
				s.gen++
				active := s.state == "running" || s.state == "starting" || s.state == "stopping"
				if active {
					s.stopReq = true
					s.state = "stopping"
					s.eventLocked("stopping", "", nil)
				}
				s.mu.Unlock()
				if active {
					wg.Add(1)
					go func(s *runtime) {
						defer wg.Done()
						note(sup.stopSashBody(context.Background(), s))
					}(s)
				}
				continue
			}
			s.mu.Lock()
			s.gen++
			s.stopReq = true
			state := s.state
			pid := s.pid
			procDone := s.procDone
			if state == "starting" && pid <= 0 {
				s.state = "stopped"
				s.ready = false
				s.pid = 0
				s.mu.Unlock()
				continue
			}
			if state != "running" && state != "starting" && state != "stopping" {
				s.mu.Unlock()
				continue
			}
			if pid <= 0 {
				s.state = "stopped"
				s.ready = false
				s.mu.Unlock()
				continue
			}
			s.eventLocked("stopping", "", nil)
			s.state = "stopping"
			s.mu.Unlock()
			wg.Add(1)
			go func(s *runtime, pid int, procDone chan struct{}) {
				defer wg.Done()
				if err := s.signalGroup(pid, syscall.SIGTERM); err != nil {
					note(err)
				}
				waitCtx := ctx
				if waitCtx.Err() != nil {
					waitCtx = context.Background()
				}
				if err := s.waitGroup(waitCtx, pid, procDone, timeoutOf(s.svc)); err != nil {
					if killErr := s.signalGroup(pid, syscall.SIGKILL); killErr != nil {
						note(killErr)
					}
					<-procDone
				}
				s.mu.Lock()
				if s.state == "stopping" {
					s.state = "stopped"
					s.ready = false
					s.pid = 0
					s.stopReq = false
					if s.cgErr != "" {
						s.state = "failed"
						s.lastError = s.cgErr
						note(fail.E(s.cgErr))
					}
				}
				s.mu.Unlock()
			}(s, pid, procDone)
		}
		wg.Wait()
	}
	// Whatever a service left behind is killed with its cgroup.
	sup.sweepStrays()
	if sup.Cgroups != nil {
		for name, s := range sup.runtimes() {
			if err := sup.Cgroups.KillAll(name, timeoutOf(s.svc)); err != nil {
				note(err)
			}
		}
	}
	if first != nil {
		return fail.E("failed")
	}
	return nil
}

// Status returns one row, or every row sorted by name when name is empty.
func (sup *Supervisor) Status(name string) ([]Row, error) {
	if name == "" {
		rows := make([]Row, 0, len(sup.runtimes()))
		for _, s := range sup.runtimes() {
			rows = append(rows, sup.row(s))
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		return rows, nil
	}
	s, err := sup.lookup(name)
	if err != nil {
		return nil, err
	}
	return []Row{sup.row(s)}, nil
}

// row reports the sandbox claim only while a process holds it: a stopped,
// exited, or failed service has no sandbox, whatever it had before. Usage
// is read while the service cgroup exists.
func (sup *Supervisor) row(s *runtime) Row {
	s.mu.Lock()
	sandbox := s.sandbox
	if s.pid <= 0 {
		sandbox = ""
	}
	l := s.svc.Limits
	r := Row{
		Name:      s.svc.Name,
		State:     s.state,
		Pid:       s.pid,
		Ready:     s.ready,
		Restarts:  s.restarts,
		Sandbox:   sandbox,
		LastError: s.lastError,
		Desired:   s.desired, Essential: s.svc.Essential,
		Cgroups: sup.cgroupMode(),
		Limits:  RowLimits{MemoryMax: l.MemoryMax, CPUMax: l.CPUMax(), PidsMax: l.PidsMax},

		CgroupTrusted: unit.CgroupTrusted(s.svc),
		Sash:          s.sashRowLocked(),
	}
	s.mu.Unlock()
	if sup.Cgroups != nil {
		r.Cgroup = sup.Cgroups.Path(s.svc.Name)
		if u, ok := sup.Cgroups.Usage(s.svc.Name); ok {
			r.Usage = &u
		}
	}
	return r
}

func (sup *Supervisor) cgroupMode() string {
	if sup.Cgroups != nil {
		return CgroupsEnabled
	}
	if sup.CgroupMode == "" {
		return CgroupsDisabled
	}
	return sup.CgroupMode
}

func (sup *Supervisor) lookup(name string) (*runtime, error) {
	if !unit.NameOK(name) {
		return nil, fail.E("not_found")
	}
	s, ok := sup.runtime(name)
	if !ok || s == nil || s.svc == nil {
		return nil, fail.E("not_found")
	}
	return s, nil
}

func (sup *Supervisor) start(ctx context.Context, name, arg string, allowEmpty, user bool) error {
	if ctx == nil || ctx.Err() != nil {
		return fail.E("failed")
	}
	s, err := sup.lookup(name)
	if err != nil {
		return err
	}
	if !s.op.TryLock() {
		return fail.E("busy")
	}
	defer s.op.Unlock()
	return sup.startLocked(ctx, s, arg, allowEmpty, user)
}

func (sup *Supervisor) startLocked(ctx context.Context, s *runtime, arg string, allowEmpty, user bool) error {
	if ctx.Err() != nil {
		return fail.E("failed")
	}
	s.mu.Lock()
	if user {
		s.desired = true
	}
	state := s.state
	s.mu.Unlock()
	if state == "running" || state == "starting" || state == "stopping" {
		return fail.E("busy")
	}
	if sup.admit != nil {
		if err := sup.admit(s.svc.Name, false); err != nil {
			s.mu.Lock()
			s.state, s.lastError, s.ready = "failed", fail.Token(err), false
			s.eventLocked("admission_denied", s.lastError, nil)
			s.mu.Unlock()
			return err
		}
	}
	if err := sup.needsGate(s); err != nil {
		if fail.Token(err) == "needs_failed" || fail.Token(err) == "needs_not_ready" {
			s.mu.Lock()
			s.state = "blocked"
			s.ready = false
			s.pid = 0
			s.lastError = fail.Token(err)
			s.sandbox = ""
			s.mu.Unlock()
		}
		return err
	}
	if s.svc.Sash != nil {
		s.mu.Lock()
		if sup.shuttingDown.Load() || s.state == "running" || s.state == "starting" || s.state == "stopping" {
			s.mu.Unlock()
			return fail.E("busy")
		}
		if user {
			s.gen++
			s.restarts = 0
			s.restartsAt = nil
			s.crashes = 0
			s.backoff = false
		}
		gen := s.gen
		s.eventLocked("starting", "", nil)
		s.state, s.ready, s.pid, s.stopReq, s.timedOut, s.lastError, s.sandbox, s.cgErr = "starting", false, 0, false, false, "", "", ""
		s.mu.Unlock()
		return sup.startSashLocked(ctx, s, gen)
	}
	argv := append([]string{}, s.svc.Exec...)
	if s.svc.Type == "oneshot" {
		if arg == "" {
			if !allowEmpty {
				return fail.E("arg_required")
			}
		} else {
			if err := argOK(arg); err != nil {
				return err
			}
			if len(argv) >= maxArgv {
				return fail.E("failed")
			}
			argv = append(argv, arg)
		}
	}
	s.mu.Lock()
	if sup.shuttingDown.Load() {
		s.mu.Unlock()
		return fail.E("failed")
	}
	if s.state == "running" || s.state == "starting" || s.state == "stopping" {
		s.mu.Unlock()
		return fail.E("busy")
	}
	if user {
		s.gen++
		s.restarts = 0
		s.restartsAt = nil
		s.crashes = 0
		s.backoff = false
	}
	gen := s.gen
	s.eventLocked("starting", "", nil)
	s.state = "starting"
	s.ready = false
	s.pid = 0
	s.stopReq = false
	s.timedOut = false
	s.lastError = ""
	s.sandbox = ""
	s.cgErr = ""
	s.mu.Unlock()
	return sup.launch(ctx, s, argv, gen)
}

func (sup *Supervisor) needsGate(s *runtime) error {
	failedNeed := false
	notReady := false
	for _, dep := range s.svc.Needs {
		other, ok := sup.runtime(dep)
		if !ok {
			notReady = true
			continue
		}
		other.mu.Lock()
		st := other.state
		ready := other.ready
		other.mu.Unlock()
		if st == "failed" {
			failedNeed = true
			continue
		}
		satisfied := (st == "running" && ready) || (st == "exited" && ready)
		if !satisfied {
			notReady = true
		}
	}
	if failedNeed {
		return fail.E("needs_failed")
	}
	if notReady {
		return fail.E("needs_not_ready")
	}
	return nil
}

func (sup *Supervisor) launch(ctx context.Context, s *runtime, argv []string, gen uint64) error {
	s.mu.Lock()
	if s.gen != gen || s.stopReq || sup.shuttingDown.Load() || s.state != "starting" {
		if s.state == "starting" && (s.gen != gen || sup.shuttingDown.Load() || s.stopReq) {
			s.state = "stopped"
			s.pid = 0
			s.ready = false
		}
		s.mu.Unlock()
		return fail.E("failed")
	}
	s.cg = sup.Cgroups
	s.mu.Unlock()

	// The service cgroup is made fresh, with its limits, before the child
	// starts; whatever an earlier start left in it is killed first. Limits
	// without cgroups are never ignored.
	sup.launching.RLock()
	defer sup.launching.RUnlock()
	var grp *cgroup.Group
	if sup.Cgroups != nil {
		g, err := sup.Cgroups.Prepare(s.svc.Name, s.svc.Limits, timeoutOf(s.svc))
		if err != nil {
			sup.failLaunch(s, gen, err)
			return err
		}
		grp = g
		defer grp.Close()
	} else if s.svc.Limits.Any() {
		err := fail.E("cgroup_controller")
		sup.failLaunch(s, gen, err)
		return err
	}
	notify := s.svc.Ready == "notify"
	cmd, claim, notifyR, err := sandbox.Launch(ctx, sup.self, argv, s.svc.Sandbox, notify, timeoutOf(s.svc), sandbox.Options{Path: s.svc.Path, SHA256: s.svc.SHA256, Execution: s.svc.Execution, Stdout: &s.stdout, Stderr: &s.stderr, Cgroup: grp})
	if err != nil {
		sup.dropCgroup(s)
		if notifyR != nil {
			if cerr := notifyR.Close(); cerr != nil {
				sup.failLaunch(s, gen, fail.E("failed"))
				return fail.E("failed")
			}
		}
		sup.failLaunch(s, gen, err)
		return err
	}
	claimOK := claim == claimNone
	if s.svc.Sandbox != nil {
		claimOK = sandbox.IsSandboxClaim(claim)
	}
	if !claimOK || cmd == nil || cmd.Process == nil {
		cerr := killCollected(cmd, notifyR)
		sup.dropCgroup(s)
		if cerr != nil {
			sup.failLaunch(s, gen, fail.E("failed"))
			return fail.E("failed")
		}
		sup.failLaunch(s, gen, fail.E("failed"))
		return fail.E("failed")
	}

	procDone := make(chan struct{})
	var readyCh chan struct{}
	if notify {
		readyCh = make(chan struct{})
	}
	// The child is not reaped until lifetime runs, so its pid is still its.
	pidfd := openPidfd(cmd.Process.Pid)
	s.mu.Lock()
	lost := s.gen != gen || s.stopReq || sup.shuttingDown.Load()
	if lost {
		if s.state == "starting" {
			s.state = "stopped"
			s.pid = 0
			s.ready = false
		}
		s.mu.Unlock()
		closePidfd(pidfd)
		cerr := killCollected(cmd, notifyR)
		sup.dropCgroup(s)
		if cerr != nil {
			return fail.E("failed")
		}
		return fail.E("failed")
	}
	s.retireGroupLocked()
	s.group, s.pidfd, s.exiting = cmd.Process.Pid, pidfd, false
	s.pid = cmd.Process.Pid
	s.eventLocked("started", "", nil)
	s.cmd = cmd
	s.procDone = procDone
	s.readyCh = readyCh
	s.sandbox = claim
	if s.svc.Ready == "exec" {
		s.state = "running"
		s.ready = true
		s.readyAt = clock()
		s.eventLocked("ready", "", nil)
	}
	s.mu.Unlock()

	go sup.lifetime(s, cmd, notifyR, procDone, readyCh, gen)
	if s.svc.Ready == "exec" {
		return nil
	}
	return sup.waitReady(ctx, s, procDone, readyCh, gen)
}

func (sup *Supervisor) lifetime(s *runtime, cmd *exec.Cmd, notifyR *os.File, procDone chan struct{}, readyCh chan struct{}, gen uint64) {
	if s.svc.Ready == "notify" && notifyR != nil {
		var buf [1]byte
		n, rerr := notifyR.Read(buf[:])
		var cerr error
		if s.svc.Watchdog == 0 || rerr != nil || n == 0 {
			cerr = notifyR.Close()
		}
		published := false
		if rerr == nil && n >= 1 && cerr == nil {
			s.mu.Lock()
			if s.gen == gen && !s.timedOut && !s.stopReq && !sup.shuttingDown.Load() {
				s.state = "running"
				s.ready = true
				s.readyAt = clock()
				s.lastError = ""
				s.eventLocked("ready", "", nil)
				published = true
			}
			s.mu.Unlock()
			if published {
				close(readyCh)
				if s.svc.Watchdog > 0 {
					go sup.watchdog(s, notifyR, procDone, gen)
				}
			} else if s.svc.Watchdog > 0 {
				notifyR.Close()
			}
		} else if rerr == nil && n >= 1 && cerr != nil {
			if err := s.signalGroup(cmd.Process.Pid, syscall.SIGKILL); err != nil {
				waitErr := cmd.Wait()
				if waitErr != nil && cmd.ProcessState == nil {
					sup.onExit(s, procDone, gen, false)
					return
				}
				sup.onExit(s, procDone, gen, false)
				return
			}
		}
	}
	s.markExiting(cmd.Process.Pid)
	sup.drainCgroup(s)
	waitErr := cmd.Wait()
	s.mu.Lock()
	exit := &Exit{Code: -1, Time: time.Now().UTC()}
	if cmd.ProcessState != nil {
		exit.Code = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			exit.Signal = int(ws.Signal())
		}
	}
	s.lastExit = exit
	s.eventLocked("exited", "", exit)
	s.mu.Unlock()
	ok := false
	if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
		ok = true
		if ws, is := cmd.ProcessState.Sys().(syscall.WaitStatus); is && ws.Signaled() {
			ok = false
		}
	}
	if waitErr != nil && cmd.ProcessState == nil {
		ok = false
	}
	sup.onExit(s, procDone, gen, ok)
}

func (sup *Supervisor) watchdog(s *runtime, pipe *os.File, done chan struct{}, gen uint64) {
	defer pipe.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-done:
			pipe.Close()
		case <-finished:
		}
	}()
	for {
		pipe.SetReadDeadline(time.Now().Add(s.svc.Watchdog))
		var b [1]byte
		if _, err := pipe.Read(b[:]); err == nil {
			continue
		}
		select {
		case <-done:
			return
		default:
		}
		s.mu.Lock()
		live := s.gen == gen && !s.stopReq && !s.exiting && !sup.shuttingDown.Load()
		pid := s.pid
		if live {
			s.lastError = "watchdog"
			s.eventLocked("watchdog", "watchdog", nil)
		}
		s.mu.Unlock()
		if live {
			_ = s.signalGroup(pid, syscall.SIGKILL)
		}
		return
	}
}

func (sup *Supervisor) onExit(s *runtime, procDone chan struct{}, gen uint64, exitedOK bool) {
	s.mu.Lock()
	if s.gen != gen {
		s.mu.Unlock()
		close(procDone)
		return
	}
	if s.cgErr != "" && !s.stopReq && !sup.shuttingDown.Load() {
		s.state = "failed"
		s.ready = false
		s.pid = 0
		s.lastError = s.cgErr
		s.mu.Unlock()
		close(procDone)
		return
	}
	if s.timedOut {
		s.state = "failed"
		s.ready = false
		s.pid = 0
		s.stopReq = false
		s.mu.Unlock()
		close(procDone)
		return
	}
	if s.stopReq || sup.shuttingDown.Load() {
		s.state = "stopped"
		s.ready = false
		s.pid = 0
		s.stopReq = false
		s.mu.Unlock()
		close(procDone)
		return
	}
	wasReady := s.ready
	if s.svc.Type == "oneshot" {
		s.pid = 0
		s.ready = false
		if exitedOK {
			s.state = "exited"
			s.ready = true
			s.lastError = ""
		} else {
			s.state = "failed"
			s.lastError = "failed"
			s.restarts = 0
		}
		s.mu.Unlock()
		close(procDone)
		return
	}
	restart := false
	if wasReady || s.svc.Ready == "exec" {
		switch s.svc.Restart {
		case "always":
			restart = true
		case "on-failure":
			restart = !exitedOK
		}
	}
	if !restart {
		s.pid = 0
		s.ready = false
		s.stopReq = false
		if exitedOK {
			s.state = "stopped"
			s.lastError = ""
		} else {
			s.state = "failed"
			if s.lastError == "" {
				s.lastError = "failed"
			}
		}
		s.mu.Unlock()
		close(procDone)
		return
	}
	if !sup.allowRestart(s) {
		s.state = "failed"
		s.ready = false
		s.pid = 0
		s.lastError = "restart_limit"
		s.eventLocked("restart_limit", "restart_limit", nil)
		s.sandbox = ""
		s.mu.Unlock()
		close(procDone)
		return
	}
	s.state = "starting"
	s.pid = 0
	s.ready = false
	s.stopReq = false
	s.timedOut = false
	s.sandbox = ""
	s.lastError = ""
	fresh := make(chan struct{})
	close(fresh)
	s.procDone = fresh
	s.backoff = true
	s.mu.Unlock()
	close(procDone)
	go sup.relaunch(s, gen)
}

// clock is the restart accounting's time source; tests replace it.
var clock = time.Now

// stableFor is how long a run must stay ready before its crash count is
// forgotten: at least 10 s (sup.stableMin, for tests), or the unit's
// timeout when longer.
func (sup *Supervisor) stableFor(svc *unit.Service) time.Duration {
	min := 10 * time.Second
	if sup.stableMin > 0 {
		min = sup.stableMin
	}
	if t := timeoutOf(svc); t > min {
		return t
	}
	return min
}

// allowRestart also counts consecutive crashes: a unit whose runs never stay
// ready for stableFor hits restart_limit after the burst, however long its
// restart delays make the gaps (the sliding window alone misses a loop
// whose backoff spreads five restarts over more than 30 s). Caller holds
// s.mu.
func (sup *Supervisor) allowRestart(s *runtime) bool {
	return sup.allowCrashRestart(s, sup.RestartBurst, sup.RestartWindow)
}

// allowCrashRestart is the restart decision for exec and sash units alike:
// the sliding window (burst in window) and the consecutive-crash count
// (burst crashes without a run that stayed ready for stableFor). Caller
// holds s.mu.
func (sup *Supervisor) allowCrashRestart(s *runtime, burst int, window time.Duration) bool {
	if burst <= 0 {
		burst = defaultBurst
	}
	if !s.readyAt.IsZero() && clock().Sub(s.readyAt) >= sup.stableFor(s.svc) {
		s.crashes = 0
	}
	if s.crashes >= burst {
		return false
	}
	if !allowRestartWith(s, burst, window) {
		return false
	}
	s.crashes++
	return true
}

// allowRestartWith is allowRestart with a burst and window; caller holds
// s.mu.
func allowRestartWith(s *runtime, burst int, window time.Duration) bool {
	if burst <= 0 {
		burst = defaultBurst
	}
	if window <= 0 {
		window = defaultWindow
	}
	now := clock()
	prev := s.restartsAt
	kept := make([]time.Time, 0, len(prev))
	for _, t := range prev {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= burst {
		s.restartsAt = kept
		return false
	}
	s.restartsAt = append(kept, now)
	s.restarts++
	return true
}

func (sup *Supervisor) relaunch(s *runtime, gen uint64) {
	s.mu.Lock()
	delay := restartDelay(s.svc, s.crashes)
	s.mu.Unlock()
	time.Sleep(delay)
	s.mu.Lock()
	s.backoff = false
	s.mu.Unlock()
	sup.transaction.RLock()
	defer sup.transaction.RUnlock()
	if current, ok := sup.runtime(s.svc.Name); !ok || current != s {
		return
	}
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	if s.gen != gen || s.state != "starting" || s.stopReq || sup.shuttingDown.Load() {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if sup.admit != nil {
		if err := sup.admit(s.svc.Name, true); err != nil {
			sup.failLaunch(s, gen, err)
			return
		}
	}
	if err := sup.needsGate(s); err != nil {
		s.mu.Lock()
		s.state, s.ready, s.lastError = "blocked", false, fail.Token(err)
		s.mu.Unlock()
		return
	}
	argv := append([]string{}, s.svc.Exec...)
	if err := sup.launch(context.Background(), s, argv, gen); err != nil {
		return
	}
}

func restartDelay(svc *unit.Service, attempts int) time.Duration {
	base, cap := svc.RestartDelay, svc.RestartMaxDelay
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	if cap <= 0 {
		cap = 30 * time.Second
	}
	for i := 1; i < attempts && base < cap; i++ {
		base *= 2
	}
	if base > cap {
		base = cap
	}
	// Jitter stays within the configured maximum, including at the cap.
	return base*4/5 + time.Duration(rand.Int64N(int64(base/5)+1))
}

func (sup *Supervisor) waitReady(ctx context.Context, s *runtime, procDone chan struct{}, readyCh chan struct{}, gen uint64) error {
	timer := time.NewTimer(timeoutOf(s.svc))
	defer timer.Stop()
	select {
	case <-readyCh:
		return nil
	case <-procDone:
		// lifetime closes readyCh before procDone: a service that was
		// ready and has since exited was started, whichever case select
		// picked.
		select {
		case <-readyCh:
			return nil
		default:
		}
		return sup.exitResult(s, gen)
	case <-timer.C:
		select {
		case <-readyCh:
			return nil
		case <-procDone:
			return sup.exitResult(s, gen)
		default:
			return sup.timeOut(s, procDone, gen)
		}
	case <-ctx.Done():
		select {
		case <-readyCh:
			return nil
		case <-procDone:
			return sup.exitResult(s, gen)
		default:
			return sup.timeOut(s, procDone, gen)
		}
	}
}

func (sup *Supervisor) timeOut(s *runtime, procDone chan struct{}, gen uint64) error {
	s.mu.Lock()
	if s.ready && s.svc.Ready == "notify" {
		s.mu.Unlock()
		return nil
	}
	if s.gen != gen {
		s.mu.Unlock()
		return fail.E("failed")
	}
	s.timedOut = true
	s.lastError = "timeout"
	s.eventLocked("timeout", "timeout", nil)
	pid := s.pid
	s.mu.Unlock()
	if err := s.signalGroup(pid, syscall.SIGKILL); err != nil {
		<-procDone
		return fail.E("failed")
	}
	<-procDone
	return fail.E("timeout")
}

func (sup *Supervisor) exitResult(s *runtime, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return fail.E("failed")
	}
	if s.state == "exited" && s.ready {
		return nil
	}
	if s.lastError != "" {
		return fail.E(s.lastError)
	}
	return fail.E("failed")
}

func (sup *Supervisor) failLaunch(s *runtime, gen uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sandbox = ""
	if s.gen != gen || s.stopReq || sup.shuttingDown.Load() {
		if s.gen != gen && s.state == "starting" {
			s.state = "stopped"
			s.pid = 0
			s.ready = false
		}
		return
	}
	s.state = "failed"
	s.ready = false
	s.pid = 0
	s.lastError = fail.Token(err)
	s.eventLocked("launch_failed", s.lastError, nil)
	if s.lastError == "" {
		s.lastError = "failed"
	}
}

// drainCgroup runs once the main process has exited, before it is reaped:
// everything left in the service cgroup is killed, and the service has
// ended only when cgroup.events says populated 0. A cgroup that does not
// empty within the timeout leaves cgErr set (cgroup_stuck).
func (sup *Supervisor) drainCgroup(s *runtime) {
	s.mu.Lock()
	cg := s.cg
	s.mu.Unlock()
	if cg == nil {
		return
	}
	if err := cg.KillAll(s.svc.Name, timeoutOf(s.svc)); err != nil {
		s.mu.Lock()
		s.cgErr = fail.Token(err)
		s.eventLocked("cgroup_stuck", s.cgErr, nil)
		s.mu.Unlock()
	}
	sup.sweepStrays()
}

// sweepStrays kills processes that left their service cgroup for the
// supervisor's leaf or the root, unless a launch may have a child waiting
// there.
func (sup *Supervisor) sweepStrays() {
	if sup.Cgroups == nil || !sup.launching.TryLock() {
		return
	}
	defer sup.launching.Unlock()
	running := make(map[string]bool, len(sup.runtimes()))
	for name, s := range sup.runtimes() {
		s.mu.Lock()
		running[name] = s.pid > 0 || s.state == "starting" || s.state == "running" || s.state == "stopping"
		s.mu.Unlock()
	}
	sw := sup.Cgroups.SweepStrays(running)
	if sup.Log == nil {
		return
	}
	for _, pid := range sw.Killed {
		fmt.Fprintln(sup.Log, "cgroup_stray", pid)
	}
	for _, p := range sw.Cgroups {
		fmt.Fprintln(sup.Log, "cgroup_stray_cgroup", p)
	}
	for _, pid := range sw.RootMembers {
		fmt.Fprintln(sup.Log, "cgroup_root_member", pid)
	}
}

// SweepEvery runs the stray sweep every d until ctx ends; d <= 0 is off.
// The sweep also runs when a service ends, on each control request, and at
// shutdown.
func (sup *Supervisor) SweepEvery(ctx context.Context, d time.Duration) {
	if d <= 0 || sup.Cgroups == nil {
		return
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sup.sweepStrays()
		}
	}
}

// dropCgroup empties and removes the service cgroup after a failed launch.
func (sup *Supervisor) dropCgroup(s *runtime) {
	if sup.Cgroups != nil {
		sup.Cgroups.KillAll(s.svc.Name, timeoutOf(s.svc))
	}
}

// markExiting waits until the leader can be reaped, then sets exiting under
// mu. The caller reaps only after this returns, so a signal sent under mu
// while exiting is false reaches a process that has not been reaped.
func (s *runtime) markExiting(pid int) {
	waitExited(pid)
	s.mu.Lock()
	if s.group == pid {
		s.exiting = true
	}
	s.mu.Unlock()
}

// signalGroup sends sig to the process group led by pid, only while pid is
// this service's last started process, and with mu held. With a pidfd and
// Linux 6.9 or later the signal goes through the pidfd, which cannot reach a
// reused pid. Otherwise kill(-pid) is used: before the leader is reaped its
// pid cannot be reused; after, the group id stays reserved while any member
// lives.
//
// With cgroups, SIGKILL goes to the whole service cgroup (cgroup.kill),
// and any other signal reaches the process group only through the pidfd or
// while the leader is unreaped, since the cgroup, not the group, is killed
// once the leader has exited.
//
// Threats: without cgroups and without the pidfd path, a group that
// empties just before a signal sent after the leader was reaped could have
// its id reused by an unrelated group; with cgroups kill(-pid) is never
// sent after the leader is reaped. The single-pid fallback is used only
// before the leader is reaped.
func (s *runtime) signalGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.group != pid {
		return nil
	}
	if s.cg != nil && sig == syscall.SIGKILL {
		return s.cg.Kill(s.svc.Name)
	}
	if s.pidfd >= 0 {
		err := pidfdSignalGroup(s.pidfd, sig)
		if err == nil || err == syscall.ESRCH {
			return nil
		}
		if err != syscall.EINVAL && err != syscall.ENOSYS {
			return err
		}
	}
	if s.cg != nil && s.exiting {
		return nil
	}
	err := syscall.Kill(-pid, sig)
	if err == nil || err == syscall.ESRCH {
		return nil
	}
	if s.exiting {
		return err
	}
	err = syscall.Kill(pid, sig)
	if err == nil || err == syscall.ESRCH {
		return nil
	}
	return err
}

// groupGone reports whether the process group led by pid has no members.
func (s *runtime) groupGone(pid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.group != pid {
		return true
	}
	return groupEmpty(pid, s.pidfd)
}

// signalGroup is for a child no lifetime has started on: it is not reaped
// until the caller waits for it.
func signalGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	err := syscall.Kill(-pid, sig)
	if err == nil || err == syscall.ESRCH {
		return nil
	}
	err = syscall.Kill(pid, sig)
	if err == nil || err == syscall.ESRCH {
		return nil
	}
	return err
}

func killCollected(cmd *exec.Cmd, notifyR *os.File) error {
	pid := 0
	if cmd != nil && cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	sigErr := signalGroup(pid, syscall.SIGKILL)
	var waitErr error
	if cmd != nil && cmd.Process != nil {
		waitErr = cmd.Wait()
	}
	var cerr error
	if notifyR != nil {
		cerr = notifyR.Close()
	}
	if sigErr != nil {
		return fail.E("failed")
	}
	if cmd != nil && cmd.Process != nil && cmd.ProcessState == nil {
		if waitErr != nil {
			return fail.E("failed")
		}
		return fail.E("failed")
	}
	if cerr != nil {
		return fail.E("failed")
	}
	return nil
}

// A collected leader does not imply that its process group is empty. With
// cgroups done is closed only after the service cgroup is empty, and the
// process group is not consulted.
func (s *runtime) waitGroup(ctx context.Context, pid int, done chan struct{}, d time.Duration) error {
	s.mu.Lock()
	cg := s.cg
	s.mu.Unlock()
	timer := time.NewTimer(d)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			if pid <= 0 || cg != nil || s.groupGone(pid) {
				return nil
			}
		default:
		}
		select {
		case <-timer.C:
			return fail.E("timeout")
		case <-ctx.Done():
			return fail.E("timeout")
		case <-tick.C:
		}
	}
}

func timeoutOf(svc *unit.Service) time.Duration {
	if svc == nil || svc.Timeout <= 0 {
		return unit.DefaultTimeout
	}
	return svc.Timeout
}

func argOK(arg string) error {
	if arg == "" {
		return fail.E("arg_required")
	}
	if strings.Contains(arg, "..") || !argRE.MatchString(arg) {
		return fail.E("arg_rejected")
	}
	return nil
}

// SetBooted records whether boot finished (true) or the supervisor is
// stopping (false); apply, rollback and activate need it set.
func (sup *Supervisor) SetBooted(v bool) { sup.booted.Store(v) }

// Booted reports SetBooted's value.
func (sup *Supervisor) Booted() bool { return sup.booted.Load() }
