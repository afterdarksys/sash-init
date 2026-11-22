// Package supervise runs a static service catalog in the calling process.
//
// Threats: the control socket is local and uid-gated. A denied peer is
// refused before the body is acted on, and a peer-cred failure denies the
// caller. A peer inside a running service's process group is refused
// (peer_supervised), so a service cannot drive the supervisor. The supervisor holds no keys, does not understand leases, and does
// not log oneshot arguments. A sandbox claim is stored only when Launch
// returns it. Stop signals the process group. This package does not confine
// the network beyond the sandbox package and does not check leases.
package supervise

import (
	"context"
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

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const (
	claimNone = "none"

	defaultBurst  = 5
	defaultWindow = 30 * time.Second
	maxArgv       = 32
)

var argRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Row is one status record. Fields are always encoded, including zeroes.
type Row struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Pid       int    `json:"pid"`
	Ready     bool   `json:"ready"`
	Restarts  int    `json:"restarts"`
	Sandbox   string `json:"sandbox"`
	LastError string `json:"last_error"`
}

// Supervisor is the userspace service supervisor. It is not PID 1.
type Supervisor struct {
	self          string
	rt            map[string]*runtime
	mu            sync.Mutex
	ln            *net.UnixListener
	bound         string
	serving       atomic.Bool
	shuttingDown  atomic.Bool
	RestartBurst  int
	RestartWindow time.Duration
	Allow         map[uint32]struct{}
	// SocketGID is the socket's group when Allow names a uid other than
	// the supervisor's own; the socket is then mode 0660.
	SocketGID    *uint32
	MaxHandlers  int
	ReadDeadline time.Duration
}

type runtime struct {
	stdout     tail
	stderr     tail
	events     []Event
	eventSeq   uint64
	lastExit   *Exit
	svc        *unit.Service
	op         sync.Mutex
	mu         sync.Mutex
	state      string
	pid        int
	ready      bool
	restarts   int
	sandbox    string
	lastError  string
	gen        uint64
	stopReq    bool
	timedOut   bool
	restartsAt []time.Time
	procDone   chan struct{}
	readyCh    chan struct{}
	cmd        *exec.Cmd
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
	var first error
	for _, wave := range waves {
		errs := make([]error, len(wave))
		var wg sync.WaitGroup
		for i, name := range wave {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				allowEmpty := false
				if s := sup.rt[name]; s != nil && s.svc.Type == "oneshot" {
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
	return sup.start(ctx, name, "", false, true)
}

// Oneshot runs a catalog oneshot with one checked arg. The arg is not logged.
func (sup *Supervisor) Oneshot(ctx context.Context, name, arg string) error {
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

	s.mu.Lock()
	state := s.state
	pid := s.pid
	if state == "stopped" || state == "exited" {
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

	if err := signalGroup(pid, syscall.SIGTERM); err != nil {
		return fail.E("failed")
	}
	if err := waitGroup(ctx, pid, procDone, timeoutOf(s.svc)); err != nil {
		if killErr := signalGroup(pid, syscall.SIGKILL); killErr != nil {
			return fail.E("failed")
		}
		<-procDone
		if ctx.Err() != nil {
			s.finishStop(gen)
			return fail.E("timeout")
		}
	}
	s.finishStop(gen)
	return nil
}

func (s *runtime) finishStop(gen uint64) {
	s.mu.Lock()
	if s.state == "stopping" && s.gen == gen {
		s.state = "stopped"
		s.ready = false
		s.pid = 0
		s.stopReq = false
	}
	s.mu.Unlock()
}

// Restart stops and then starts. A user start clears the restart burst.
func (sup *Supervisor) Restart(ctx context.Context, name string) error {
	if err := sup.Stop(ctx, name); err != nil {
		return err
	}
	return sup.Start(ctx, name)
}

// Shutdown bumps every generation and signals live process groups.
// It does not take the per-service operation lock.
func (sup *Supervisor) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sup.shuttingDown.Store(true)
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
	for _, s := range sup.rt {
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
			if err := signalGroup(pid, syscall.SIGTERM); err != nil {
				note(err)
			}
			waitCtx := ctx
			if waitCtx.Err() != nil {
				waitCtx = context.Background()
			}
			if err := waitGroup(waitCtx, pid, procDone, timeoutOf(s.svc)); err != nil {
				if killErr := signalGroup(pid, syscall.SIGKILL); killErr != nil {
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
			}
			s.mu.Unlock()
		}(s, pid, procDone)
	}
	wg.Wait()
	if first != nil {
		return fail.E("failed")
	}
	return nil
}

// Status returns one row, or every row sorted by name when name is empty.
func (sup *Supervisor) Status(name string) ([]Row, error) {
	if name == "" {
		rows := make([]Row, 0, len(sup.rt))
		for _, s := range sup.rt {
			rows = append(rows, s.row())
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		return rows, nil
	}
	s, err := sup.lookup(name)
	if err != nil {
		return nil, err
	}
	return []Row{s.row()}, nil
}

// row reports the sandbox claim only while a process holds it: a stopped,
// exited, or failed service has no sandbox, whatever it had before.
func (s *runtime) row() Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	sandbox := s.sandbox
	if s.pid <= 0 {
		sandbox = ""
	}
	return Row{
		Name:      s.svc.Name,
		State:     s.state,
		Pid:       s.pid,
		Ready:     s.ready,
		Restarts:  s.restarts,
		Sandbox:   sandbox,
		LastError: s.lastError,
	}
}

func (sup *Supervisor) lookup(name string) (*runtime, error) {
	if !unit.NameOK(name) {
		return nil, fail.E("not_found")
	}
	s, ok := sup.rt[name]
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
	state := s.state
	s.mu.Unlock()
	if state == "running" || state == "starting" || state == "stopping" {
		return fail.E("busy")
	}
	if err := sup.needsGate(s); err != nil {
		if fail.Token(err) == "needs_failed" {
			s.mu.Lock()
			s.state = "failed"
			s.ready = false
			s.pid = 0
			s.lastError = "needs_failed"
			s.sandbox = ""
			s.mu.Unlock()
		}
		return err
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
	s.mu.Unlock()
	return sup.launch(ctx, s, argv, gen)
}

func (sup *Supervisor) needsGate(s *runtime) error {
	failedNeed := false
	notReady := false
	for _, dep := range s.svc.Needs {
		other, ok := sup.rt[dep]
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
	s.mu.Unlock()

	notify := s.svc.Ready == "notify"
	cmd, claim, notifyR, err := sandbox.Launch(ctx, sup.self, argv, s.svc.Sandbox, notify, timeoutOf(s.svc), sandbox.Options{Path: s.svc.Path, Execution: s.svc.Execution, Stdout: &s.stdout, Stderr: &s.stderr})
	if err != nil {
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
		if cerr := killCollected(cmd, notifyR); cerr != nil {
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
	s.mu.Lock()
	lost := s.gen != gen || s.stopReq || sup.shuttingDown.Load()
	if lost {
		if s.state == "starting" {
			s.state = "stopped"
			s.pid = 0
			s.ready = false
		}
		s.mu.Unlock()
		if cerr := killCollected(cmd, notifyR); cerr != nil {
			return fail.E("failed")
		}
		return fail.E("failed")
	}
	s.pid = cmd.Process.Pid
	s.eventLocked("started", "", nil)
	s.cmd = cmd
	s.procDone = procDone
	s.readyCh = readyCh
	s.sandbox = claim
	if s.svc.Ready == "exec" {
		s.state = "running"
		s.ready = true
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
		cerr := notifyR.Close()
		published := false
		if rerr == nil && n >= 1 && cerr == nil {
			s.mu.Lock()
			if s.gen == gen && !s.timedOut && !s.stopReq && !sup.shuttingDown.Load() {
				s.state = "running"
				s.ready = true
				s.lastError = ""
				s.eventLocked("ready", "", nil)
				published = true
			}
			s.mu.Unlock()
			if published {
				close(readyCh)
			}
		} else if rerr == nil && n >= 1 && cerr != nil {
			s.mu.Lock()
			pid := s.pid
			s.mu.Unlock()
			if err := signalGroup(pid, syscall.SIGKILL); err != nil {
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

func (sup *Supervisor) onExit(s *runtime, procDone chan struct{}, gen uint64, exitedOK bool) {
	s.mu.Lock()
	if s.gen != gen {
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
	s.mu.Unlock()
	close(procDone)
	go sup.relaunch(s, gen)
}

func (sup *Supervisor) allowRestart(s *runtime) bool {
	burst := sup.RestartBurst
	if burst <= 0 {
		burst = defaultBurst
	}
	window := sup.RestartWindow
	if window <= 0 {
		window = defaultWindow
	}
	now := time.Now()
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
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	if s.gen != gen || s.state != "starting" || s.stopReq || sup.shuttingDown.Load() {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	argv := append([]string{}, s.svc.Exec...)
	if err := sup.launch(context.Background(), s, argv, gen); err != nil {
		return
	}
}

func (sup *Supervisor) waitReady(ctx context.Context, s *runtime, procDone chan struct{}, readyCh chan struct{}, gen uint64) error {
	timer := time.NewTimer(timeoutOf(s.svc))
	defer timer.Stop()
	select {
	case <-readyCh:
		return nil
	case <-procDone:
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
	if err := signalGroup(pid, syscall.SIGKILL); err != nil {
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

// A collected leader does not imply that its process group is empty.
func waitGroup(ctx context.Context, pid int, done chan struct{}, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			if pid <= 0 || syscall.Kill(-pid, 0) == syscall.ESRCH {
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
