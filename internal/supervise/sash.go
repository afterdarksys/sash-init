// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

// Running sash services (docs/design/sash-services-1.md).
//
// Threats: a sash service's script runs as the unit's unprivileged uid,
// sandboxed, inside the service cgroup, and everything it does beyond its
// own process goes through the verb socket, where sahinit re-checks it
// (internal/sash). Before every session sahinit verifies the grant file
// itself: the fleet key, sash/2 purpose service, this service's name, the
// identity sash --describe gave, exp, and the serial against the signed
// floor (sash_grant_revoked). A grant that fails is a configuration error:
// the unit is failed and not restarted. sash gets the very bytes sahinit
// verified on fd 3, the fleet key on fd 4, an emergency key on fd 5 whose
// private half was never kept (a service has no emergency path, and sash
// refuses an empty key), and the verb socket on fd 6. The service is its
// cgroup: the session process lives only as long as its entry, the
// processes it spawned are the service, and when the last of them ends, or
// the service is stopped, the cgroup is killed. The grant body and env
// values are never in status, diagnostics or the log.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// SashConfig is what sahinit needs to run sash units.
type SashConfig struct {
	// Binary is the sash executable, resolved and checked.
	Binary string
	// Fleet is the fleet public key grants and floors are signed with.
	Fleet ed25519.PublicKey
	// Floors holds the signed per-service floors.
	Floors *sash.FloorStore
	// StateDir is a private directory for sahinit's sash state (the
	// mounts it made); "" keeps them in memory only.
	StateDir string
	// Now is the clock for grant expiry; nil is time.Now.
	Now func() time.Time
}

const (
	// describeTimeout and describe output are bounded at load.
	describeTimeout = 5 * time.Second
	// entryTimeout bounds a start, run, reload or check session; stop
	// uses the stop timeout.
	entryTimeout = 2 * time.Minute
	readyPoll    = 100 * time.Millisecond
)

// sashState is a sash unit's runtime, beside runtime's common fields.
type sashState struct {
	table *sash.Table
	// sessions cancels each running session: stop and shutdown end them,
	// so a blocked verb or entry never holds the cgroup kill.
	sessions map[uint64]context.CancelFunc
	nextSess uint64
	serial   uint64
	entries  map[string]EntryResult
	order    []string
}

// EntryResult is the last result of one entry.
type EntryResult struct {
	Entry string    `json:"entry"`
	Exit  int       `json:"exit"`
	Token string    `json:"token,omitempty"`
	Time  time.Time `json:"time"`
}

// SashRow is a sash unit's part of a status row. It never holds the grant
// body or an env value.
type SashRow struct {
	Entry   string        `json:"entry"`
	Serial  uint64        `json:"grant_serial"`
	Entries []EntryResult `json:"entries"`
	Procs   []SashProc    `json:"procs"`
}

// SashProc is one row of the name table.
type SashProc struct {
	Name    string    `json:"name"`
	Pid     int       `json:"pid"`
	State   string    `json:"state"`
	Started time.Time `json:"started_at"`
	Exit    *int      `json:"exit,omitempty"`
	Signal  string    `json:"signal,omitempty"`
}

func (sup *Supervisor) now() time.Time {
	if sup.Sash != nil && sup.Sash.Now != nil {
		return sup.Sash.Now()
	}
	return time.Now()
}

// LookupIDs resolves a user and a group name with the system's databases.
func LookupIDs() (func(string) (uint32, error), func(string) (uint32, error)) {
	u := func(name string) (uint32, error) {
		x, err := user.Lookup(name)
		if err != nil {
			return 0, err
		}
		n, err := strconv.ParseUint(x.Uid, 10, 32)
		return uint32(n), err
	}
	g := func(name string) (uint32, error) {
		x, err := user.LookupGroup(name)
		if err != nil {
			return 0, err
		}
		n, err := strconv.ParseUint(x.Gid, 10, 32)
		return uint32(n), err
	}
	return u, g
}

// Describe runs sash --describe FILE for a sash unit: as the unit's uid
// and gid, sandboxed, in a throwaway cgroup, with a 5 s timeout and a 1 MiB
// output cap, and no fds. A non-zero exit, a timeout, too much output or
// a document that does not parse is sash_describe.
func Describe(ctx context.Context, root *cgroup.Root, self, binary string, svc *unit.Service) (*sash.Description, error) {
	if svc == nil || svc.Sash == nil || svc.Sandbox == nil {
		return nil, fail.E("failed")
	}
	if root == nil {
		return nil, fail.E("sash_cgroups")
	}
	grp, err := root.PrepareScratch(svc.Name, describeTimeout)
	if err != nil {
		return nil, err
	}
	defer root.DropScratch(svc.Name, describeTimeout)
	defer grp.Close()
	out := &capBuffer{max: sash.MaxDescribe}
	ctx, cancel := context.WithTimeout(ctx, describeTimeout)
	defer cancel()
	cmd, _, _, err := sandbox.Launch(ctx, self, []string{binary, "--describe", svc.Sash.File}, svc.Sandbox, false, describeTimeout,
		sandbox.Options{Path: binary, Execution: unit.Execution{UID: svc.Execution.UID, GID: svc.Execution.GID, Groups: []uint32{}}, Stdout: out, Stderr: io.Discard, Cgroup: grp})
	if err != nil {
		return nil, fail.E("sash_describe")
	}
	code, timedOut := waitBounded(ctx, cmd)
	if timedOut || code != 0 || out.over {
		return nil, fail.E("sash_describe")
	}
	return sash.ParseDescribe(out.Bytes())
}

// capBuffer keeps at most max bytes and notes more. It is not a
// bytes.Buffer: io.Copy would use Buffer.ReadFrom and pass the cap by.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capBuffer) Bytes() []byte  { return c.buf.Bytes() }
func (c *capBuffer) String() string { return c.buf.String() }

// waitBounded waits for cmd until ctx ends, then kills it (the caller's
// unreaped child, so its pid is still its) and collects it. It returns the
// exit status (-1 for a signal) and whether ctx ended first.
func waitBounded(ctx context.Context, cmd *exec.Cmd) (int, bool) {
	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		cmd.Process.Signal(syscall.SIGKILL)
		<-done
		return -1, true
	}
	if cmd.ProcessState == nil {
		return -1, false
	}
	return cmd.ProcessState.ExitCode(), false
}

// loadGrant reads and verifies the unit's grant file, then checks its
// bindings: this service, the identity describe gave, and the floor.
func (sup *Supervisor) loadGrant(svc *unit.Service) (sash.Grant, []byte, error) {
	if sup.Sash == nil || sup.Sash.Floors == nil || len(sup.Sash.Fleet) != ed25519.PublicKeySize {
		return sash.Grant{}, nil, fail.E("sash_unavailable")
	}
	if tok := unit.CheckSashFiles(svc); tok != "" {
		return sash.Grant{}, nil, fail.E(tok)
	}
	f, err := os.OpenFile(svc.Sash.Grant, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return sash.Grant{}, nil, fail.E("sash_grant_perm")
	}
	doc, err := io.ReadAll(io.LimitReader(f, sash.MaxGrant+1))
	f.Close()
	if err != nil {
		return sash.Grant{}, nil, fail.E("grant_missing")
	}
	g, err := sash.VerifyGrant(doc, sup.Sash.Fleet, sup.now().Unix())
	if err != nil {
		return sash.Grant{}, nil, err
	}
	d := svc.Sash.Desc
	if g.Service != svc.Name {
		return sash.Grant{}, nil, fail.E("grant_service_mismatch")
	}
	if d == nil || g.User != d.User || g.Group != d.Group {
		return sash.Grant{}, nil, fail.E("grant_identity_mismatch")
	}
	if err := sup.Sash.Floors.Admit(svc.Name, g.Serial); err != nil {
		return sash.Grant{}, nil, err
	}
	return g, doc, nil
}

var stderrToken = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}`)

// session runs sash --session --entry ENTRY FILE with the wire fds and
// serves its verbs until it exits. fresh, when set, is the service cgroup
// just prepared; otherwise the existing one is joined. It returns sash's
// exit status (-1 when it was killed) and its stderr token.
func (sup *Supervisor) session(ctx context.Context, s *runtime, entry string, check bool, timeout time.Duration, g sash.Grant, doc []byte, fresh *cgroup.Group) (int, string) {
	svc := s.svc
	grp := fresh
	if grp == nil {
		j, err := sup.Cgroups.Join(svc.Name)
		if err != nil {
			return -1, "cgroup_join"
		}
		defer j.Close()
		grp = j
	}
	emergency, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return -1, "failed"
	}
	var keep []*os.File
	defer func() {
		for _, f := range keep {
			f.Close()
		}
	}()
	pipeOf := func(b []byte) (*os.File, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		keep = append(keep, r)
		_, werr := w.Write(b)
		cerr := w.Close()
		if werr != nil || cerr != nil {
			return nil, fail.E("failed")
		}
		return r, nil
	}
	var pass []*os.File
	for _, b := range [][]byte{doc, sup.Sash.Fleet, emergency} {
		r, err := pipeOf(b)
		if err != nil {
			return -1, "failed"
		}
		pass = append(pass, r)
	}
	mine, theirs, err := socketPair()
	if err != nil {
		return -1, "failed"
	}
	keep = append(keep, theirs)
	defer mine.Close()
	pass = append(pass, theirs)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id := s.addSession(cancel)
	defer s.dropSession(id)
	srv := &sash.Server{G: g, Table: s.sashTable(), Host: &sashHost{sup: sup, s: s}, Check: check, CapCeiling: svc.Sandbox.Caps, Deadline: time.Now().Add(timeout)}
	served := make(chan struct{})
	go func() {
		sash.Serve(ctx, mine, srv)
		close(served)
	}()
	// The verb server ends with the session; never wait on it for long.
	endServe := func() {
		cancel()
		mine.Close()
		select {
		case <-served:
		case <-time.After(2 * time.Second):
		}
	}
	errb := &capBuffer{max: 4096}
	argv := []string{sup.Sash.Binary, "--session", "--entry", entry, svc.Sash.File}
	sup.launching.RLock()
	cmd, _, _, err := sandbox.Launch(ctx, sup.self, argv, svc.Sandbox, false, timeoutOf(svc), sandbox.Options{
		Path: sup.Sash.Binary, Execution: unit.Execution{UID: svc.Execution.UID, GID: svc.Execution.GID, Groups: []uint32{}},
		Stdout: &s.stdout, Stderr: io.MultiWriter(&s.stderr, errb), Cgroup: grp, Pass: pass,
	})
	sup.launching.RUnlock()
	for _, f := range keep {
		f.Close()
	}
	keep = nil
	if err != nil {
		endServe()
		return -1, fail.Token(err)
	}
	s.mu.Lock()
	if entry == "start" || entry == "run" {
		s.pid = cmd.Process.Pid
	}
	s.mu.Unlock()
	code, _ := waitBounded(ctx, cmd)
	endServe()
	s.mu.Lock()
	if s.pid == cmd.Process.Pid {
		s.pid = 0
	}
	s.mu.Unlock()
	line, _, _ := strings.Cut(errb.String(), "\n")
	tok := stderrToken.FindString(line)
	s.recordEntry(entry, code, tok)
	return code, tok
}

func (s *runtime) addSession(cancel context.CancelFunc) uint64 {
	s.sashTable()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sash.sessions == nil {
		s.sash.sessions = map[uint64]context.CancelFunc{}
	}
	s.sash.nextSess++
	s.sash.sessions[s.sash.nextSess] = cancel
	return s.sash.nextSess
}

func (s *runtime) dropSession(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sash != nil {
		delete(s.sash.sessions, id)
	}
}

// cancelSessions ends every running session of this service: sash is
// killed and its verb server returns.
func (s *runtime) cancelSessions() {
	s.mu.Lock()
	var all []context.CancelFunc
	if s.sash != nil {
		for _, c := range s.sash.sessions {
			all = append(all, c)
		}
	}
	s.mu.Unlock()
	for _, c := range all {
		c()
	}
}

func (s *runtime) sashTable() *sash.Table {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sash == nil {
		s.sash = &sashState{table: sash.NewTable(), entries: map[string]EntryResult{}}
	}
	return s.sash.table
}

func (s *runtime) recordEntry(entry string, code int, tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sash == nil {
		return
	}
	if _, ok := s.sash.entries[entry]; !ok {
		s.sash.order = append(s.sash.order, entry)
	}
	s.sash.entries[entry] = EntryResult{Entry: entry, Exit: code, Token: tok, Time: time.Now().UTC()}
	s.eventLocked("sash_"+entry, tok, &Exit{Code: code, Time: time.Now().UTC()})
}

func (sup *Supervisor) logf(format string, args ...any) {
	if sup.Log != nil {
		fmt.Fprintf(sup.Log, format+"\n", args...)
	}
}

// startSashLocked starts a sash unit: grant, fresh cgroup, the start (or
// run) session, then readiness. Caller holds s.op; the state is starting.
func (sup *Supervisor) startSashLocked(ctx context.Context, s *runtime, gen uint64) error {
	svc := s.svc
	d := svc.Sash.Desc
	if d == nil || sup.Sash == nil {
		return sup.sashFail(s, gen, "sash_unavailable", true)
	}
	g, doc, err := sup.loadGrant(svc)
	if err != nil {
		tok := fail.Token(err)
		sup.logf("sash_grant %s %s", svc.Name, tok)
		// A busy floor store is transient: the restart policy may retry.
		return sup.sashFail(s, gen, tok, tok != "sash_floor_busy")
	}
	if sup.Cgroups == nil {
		return sup.sashFail(s, gen, "sash_cgroups", true)
	}
	sup.launching.RLock()
	grp, err := sup.Cgroups.Prepare(svc.Name, svc.Limits, timeoutOf(svc))
	sup.launching.RUnlock()
	if err != nil {
		return sup.sashFail(s, gen, fail.Token(err), false)
	}
	table := sash.NewTable()
	table.Changed = func() { go sup.sashChanged(s, gen) }
	s.mu.Lock()
	if s.gen != gen || s.stopReq || sup.shuttingDown.Load() {
		s.mu.Unlock()
		grp.Close()
		sup.Cgroups.KillAll(svc.Name, timeoutOf(svc))
		return fail.E("failed")
	}
	s.cg = sup.Cgroups
	old := s.sash
	s.mu.Unlock()
	// Whatever an earlier start left mounted goes before the new table.
	sup.sashUnmount(s)
	s.mu.Lock()
	s.sash = &sashState{table: table, serial: g.Serial, entries: map[string]EntryResult{}, sessions: map[uint64]context.CancelFunc{}}
	if old != nil {
		s.sash.entries, s.sash.order = old.entries, old.order
		s.sash.sessions, s.sash.nextSess = old.sessions, old.nextSess
	}
	s.mu.Unlock()
	entry := d.Entry()
	code, tok := sup.session(ctx, s, entry, false, entryTimeout, g, doc, grp)
	grp.Close()
	if s.lost(gen, sup) {
		return fail.E("failed")
	}
	switch code {
	case 0:
	case 2:
		sup.logf("sash_entry_error %s %s %s", svc.Name, entry, tok)
		return sup.sashFail(s, gen, "sash_config", true)
	case 3:
		return sup.sashFail(s, gen, "sash_not_ready", false)
	default:
		return sup.sashFail(s, gen, "failed", false)
	}
	if !sup.sashReady(ctx, s, gen, g, d) {
		if s.lost(gen, sup) {
			return fail.E("failed")
		}
		return sup.sashFail(s, gen, "timeout", true)
	}
	s.mu.Lock()
	if s.gen != gen || s.stopReq || sup.shuttingDown.Load() {
		s.mu.Unlock()
		return fail.E("failed")
	}
	s.state, s.ready, s.lastError = "running", true, ""
	s.eventLocked("ready", "", nil)
	s.mu.Unlock()
	// A start that left nothing running has ended already.
	if table.Running() == 0 {
		go sup.sashChanged(s, gen)
	}
	return nil
}

func (s *runtime) lost(gen uint64, sup *Supervisor) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen != gen || s.stopReq || sup.shuttingDown.Load()
}

// sashReady waits on the service block's ready: tcp, unix and file are
// probed by sahinit itself under the grant's rules, notify is the main
// process (or, without one, any spawned process) saying it is ready, and
// none means ready at once, unless the file has a check entry, which is
// then run, read-only, until it exits 0.
func (sup *Supervisor) sashReady(ctx context.Context, s *runtime, gen uint64, g sash.Grant, d *sash.Description) bool {
	kind, target, timeout := "none", "", unit.DefaultTimeout
	if d.Ready != nil {
		kind, target = d.Ready.Kind, d.Ready.Target
		if d.Ready.Timeout > 0 {
			timeout = d.Ready.Timeout
		}
	}
	host := &sashHost{sup: sup, s: s}
	table := s.sashTable()
	var probe func() bool
	switch kind {
	case "tcp":
		if !sash.ProbeTarget(target, g.AllowPrivate) {
			return false
		}
		probe = func() bool { return host.DialTCP(target) }
	case "unix", "file":
		root := sash.RootOf(g.FileRead, target)
		if root == "" {
			return false
		}
		probe = func() bool { return host.ProbePath(kind, root, target) }
	case "notify":
		probe = func() bool {
			if p := table.Get("main"); p != nil {
				return p.Ready() && !p.Ended()
			}
			for _, p := range table.All() {
				if p.Ready() && !p.Ended() {
					return true
				}
			}
			return false
		}
	default:
		if !d.Has("check") {
			return true
		}
		probe = func() bool {
			cg, cdoc, err := sup.loadGrant(s.svc)
			if err != nil {
				return false
			}
			code, _ := sup.session(ctx, s, "check", true, timeout, cg, cdoc, nil)
			return code == 0
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		if probe() {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil || s.lost(gen, sup) {
			return false
		}
		time.Sleep(readyPoll)
	}
}

// sashFail ends a start that failed: the cgroup is killed, and the restart
// policy applies unless noRestart (a configuration or grant error).
func (sup *Supervisor) sashFail(s *runtime, gen uint64, tok string, noRestart bool) error {
	if sup.Cgroups != nil {
		sup.Cgroups.KillAll(s.svc.Name, timeoutOf(s.svc))
	}
	sup.sashUnmount(s)
	sup.sashFinish(s, gen, false, tok, noRestart)
	return fail.E(tok)
}

// sashFinish settles a sash unit that has ended (ok or not) and schedules a
// restart when the policy asks for one.
func (sup *Supervisor) sashFinish(s *runtime, gen uint64, ok bool, tok string, noRestart bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen || s.stopReq || sup.shuttingDown.Load() {
		return
	}
	s.pid, s.ready = 0, false
	restart := !noRestart && (s.svc.Restart == "always" || s.svc.Restart == "on-failure" && !ok)
	if !restart {
		if ok {
			s.state, s.lastError = "stopped", ""
		} else {
			s.state, s.lastError = "failed", tok
		}
		s.eventLocked("ended", tok, nil)
		return
	}
	burst, window := sup.RestartBurst, sup.RestartWindow
	var delay time.Duration
	if r := s.svc.Sash.Desc.Restart; r != nil {
		if r.Burst > 0 {
			burst = r.Burst
		}
		if r.Within > 0 {
			window = r.Within
		}
		delay = r.Delay
	}
	if !allowRestartWith(s, burst, window) {
		s.state, s.lastError = "failed", "restart_limit"
		s.eventLocked("restart_limit", "restart_limit", nil)
		return
	}
	s.state, s.lastError = "starting", ""
	go sup.sashRelaunch(s, gen, delay)
}

func (sup *Supervisor) sashRelaunch(s *runtime, gen uint64, delay time.Duration) {
	time.Sleep(delay)
	s.op.Lock()
	defer s.op.Unlock()
	if s.lost(gen, sup) {
		return
	}
	s.mu.Lock()
	if s.state != "starting" {
		s.mu.Unlock()
		return
	}
	s.eventLocked("starting", "", nil)
	s.mu.Unlock()
	sup.startSashLocked(context.Background(), s, gen)
}

// sashChanged runs when a spawned process ends: once none is left of a
// running service, the service has ended.
func (sup *Supervisor) sashChanged(s *runtime, gen uint64) {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	st := s.sash
	if s.gen != gen || s.state != "running" || s.stopReq || sup.shuttingDown.Load() || st == nil || st.table.Running() > 0 {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if sup.Cgroups != nil {
		if err := sup.Cgroups.KillAll(s.svc.Name, timeoutOf(s.svc)); err != nil {
			sup.sashFinish(s, gen, false, fail.Token(err), true)
			return
		}
	}
	sup.sweepStrays()
	sup.sashUnmount(s)
	ok := !st.table.Failed()
	tok := ""
	if !ok {
		tok = "failed"
	}
	sup.sashFinish(s, gen, ok, tok, false)
}

// stopTimeoutOf is the service block's stop timeout, else the unit's.
func stopTimeoutOf(svc *unit.Service) time.Duration {
	if svc.Sash != nil && svc.Sash.Desc != nil && svc.Sash.Desc.Stop != nil && svc.Sash.Desc.Stop.Timeout > 0 {
		return svc.Sash.Desc.Stop.Timeout
	}
	return timeoutOf(svc)
}

// stopSash is Stop for a sash unit. A start still running its entry or
// waiting on readiness is interrupted: it is marked lost, its sessions are
// ended, and the stop proceeds once the start lets go.
func (sup *Supervisor) stopSash(ctx context.Context, s *runtime) error {
	if !s.op.TryLock() {
		// A start, or a reload or check session of a running service,
		// holds s.op: its sessions are ended (the sash process is killed;
		// the spawned processes are left to the stop that follows).
		s.mu.Lock()
		starting := s.state == "starting"
		if starting {
			s.gen++
			s.stopReq = true
		}
		inEntry := s.state == "running" && s.sash != nil && len(s.sash.sessions) > 0
		s.mu.Unlock()
		if !starting && !inEntry {
			return fail.E("busy")
		}
		s.cancelSessions()
		deadline := time.Now().Add(stopTimeoutOf(s.svc) + 5*time.Second)
		for !s.op.TryLock() {
			if time.Now().After(deadline) || ctx.Err() != nil {
				return fail.E("busy")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	defer s.op.Unlock()
	return sup.stopSashLocked(ctx, s)
}

// stopSashLocked stops a sash unit: the stop entry with the stop timeout,
// or the stop signal to every spawned process, then the cgroup kill.
// Caller holds s.op.
func (sup *Supervisor) stopSashLocked(ctx context.Context, s *runtime) error {
	s.mu.Lock()
	switch s.state {
	case "stopped", "exited":
		s.mu.Unlock()
		return nil
	case "stopping":
		s.mu.Unlock()
		return fail.E("busy")
	}
	s.gen++
	s.stopReq = true
	s.state = "stopping"
	s.eventLocked("stopping", "", nil)
	s.mu.Unlock()
	return sup.stopSashBody(ctx, s)
}

func (sup *Supervisor) stopSashBody(ctx context.Context, s *runtime) error {
	svc := s.svc
	timeout := stopTimeoutOf(svc)
	table := s.sashTable()
	if table.Running() > 0 {
		stopped := false
		if svc.Sash.Desc != nil && svc.Sash.Desc.Has("stop") && sup.Cgroups != nil {
			if g, doc, err := sup.loadGrant(svc); err == nil {
				code, tok := sup.session(ctx, s, "stop", false, timeout, g, doc, nil)
				if code == 2 {
					sup.logf("sash_entry_error %s stop %s", svc.Name, tok)
				}
				stopped = true
			} else {
				sup.logf("sash_grant %s %s", svc.Name, fail.Token(err))
			}
		}
		if !stopped {
			sig := "TERM"
			if d := svc.Sash.Desc; d != nil && d.Stop != nil {
				sig = d.Stop.Signal
			}
			host := &sashHost{sup: sup, s: s}
			for _, p := range table.All() {
				if !p.Ended() {
					host.Signal(p, sig)
				}
			}
			deadline := time.Now().Add(timeout)
			for table.Running() > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	var cgErr error
	if sup.Cgroups != nil {
		cgErr = sup.Cgroups.KillAll(svc.Name, timeout)
	}
	sup.sashUnmount(s)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pid, s.ready, s.stopReq = 0, false, false
	if cgErr != nil {
		s.state, s.lastError = "failed", fail.Token(cgErr)
		return cgErr
	}
	s.state = "stopped"
	return nil
}

// Reload runs a running sash unit's reload entry.
func (sup *Supervisor) Reload(ctx context.Context, name string) error {
	return sup.sashEntry(ctx, name, "reload")
}

// Check runs a running sash unit's check entry, read-only: unhealthy when
// it does not exit 0.
func (sup *Supervisor) Check(ctx context.Context, name string) error {
	return sup.sashEntry(ctx, name, "check")
}

func (sup *Supervisor) sashEntry(ctx context.Context, name, entry string) error {
	s, err := sup.lookup(name)
	if err != nil {
		return err
	}
	if s.svc.Sash == nil || s.svc.Sash.Desc == nil {
		return fail.E("not_sash")
	}
	if !s.svc.Sash.Desc.Has(entry) {
		return fail.E("no_entry")
	}
	if !s.op.TryLock() {
		return fail.E("busy")
	}
	defer s.op.Unlock()
	s.mu.Lock()
	running := s.state == "running"
	s.mu.Unlock()
	if !running {
		return fail.E("not_running")
	}
	g, doc, err := sup.loadGrant(s.svc)
	if err != nil {
		return err
	}
	timeout := entryTimeout
	if entry == "check" && s.svc.Sash.Desc.Ready != nil && s.svc.Sash.Desc.Ready.Timeout > 0 {
		timeout = s.svc.Sash.Desc.Ready.Timeout
	}
	code, tok := sup.session(ctx, s, entry, entry == "check", timeout, g, doc, nil)
	switch {
	case code == 0:
		return nil
	case code == 2:
		sup.logf("sash_entry_error %s %s %s", name, entry, tok)
		return fail.E("sash_config")
	case entry == "check":
		return fail.E("unhealthy")
	}
	return fail.E("failed")
}

// sashRow is the sash part of a status row; caller holds s.mu.
func (s *runtime) sashRowLocked() *SashRow {
	if s.svc.Sash == nil {
		return nil
	}
	r := &SashRow{Entries: []EntryResult{}, Procs: []SashProc{}}
	if d := s.svc.Sash.Desc; d != nil {
		r.Entry = d.Entry()
	}
	st := s.sash
	if st == nil {
		return r
	}
	r.Serial = st.serial
	for _, e := range st.order {
		r.Entries = append(r.Entries, st.entries[e])
	}
	for _, p := range st.table.All() {
		row := SashProc{Name: p.Name, Pid: p.Pid(), State: "running", Started: p.StartedAt().UTC()}
		if p.Ended() {
			code, sig, _ := p.Result()
			row.State, row.Exit, row.Signal = "exited", &code, sig
		}
		r.Procs = append(r.Procs, row)
	}
	return r
}

// statusRow is a service's row for svc.status: name, state (ready when
// running and ready), since (its last event) and pid.
func (sup *Supervisor) statusRow(name string) (sash.Row, error) {
	if !unit.NameOK(name) {
		return nil, fail.E("unknown_service")
	}
	s, ok := sup.rt[name]
	if !ok {
		return nil, fail.E("unknown_service")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	if state == "running" && s.ready {
		state = "ready"
	}
	since := ""
	if n := len(s.events); n > 0 {
		since = s.events[n-1].Time.UTC().Format(time.RFC3339)
	}
	return sash.Row{"name": name, "state": state, "since": since, "pid": strconv.Itoa(s.pid)}, nil
}

// lineBucket limits the journal lines one service copies to sahinit's log:
// a token bucket of burst lines refilled at rate a second. Lines over it are
// dropped and counted, and the count is reported with the next line let
// through.
type lineBucket struct {
	mu      sync.Mutex
	tokens  float64
	last    time.Time
	dropped int
	rate    float64
	burst   float64
	now     func() time.Time
}

const (
	journalRate  = 50
	journalBurst = 200
)

func newLineBucket(now func() time.Time) *lineBucket {
	if now == nil {
		now = time.Now
	}
	return &lineBucket{tokens: journalBurst, rate: journalRate, burst: journalBurst, now: now, last: now()}
}

// allow reports whether a line may be logged, and how many were dropped
// since the last one that was.
func (b *lineBucket) allow() (bool, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	b.tokens += t.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = t
	if b.tokens < 1 {
		b.dropped++
		return false, 0
	}
	b.tokens--
	d := b.dropped
	b.dropped = 0
	return true, d
}

// journalLine copies one journal line of a service's process to the log,
// within the service's rate.
func (sup *Supervisor) journalLine(s *runtime, proc, stream, line string) {
	s.mu.Lock()
	if s.journal == nil {
		s.journal = newLineBucket(nil)
	}
	b := s.journal
	s.mu.Unlock()
	ok, dropped := b.allow()
	if !ok {
		return
	}
	if dropped > 0 {
		sup.logf("sash_output_dropped %s %d", s.svc.Name, dropped)
	}
	sup.logf("sash_output %s %s %s: %s", s.svc.Name, proc, stream, printable(line))
}

// printable replaces control characters in a line copied to the log.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// sashUnmount unmounts what the service mounted, newest first, once its
// processes are gone.
func (sup *Supervisor) sashUnmount(s *runtime) {
	s.mu.Lock()
	st := s.sash
	s.mu.Unlock()
	if st != nil {
		(&sashHost{sup: sup, s: s}).unmountAll(st.table)
	}
}
