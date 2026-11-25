// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// sashHost performs a sash service's checked verbs (sash.Host).
//
// Threats: a spawned process runs as the unit's own uid and gid (the
// grant's identity must resolve to them), under the unit's sandbox with at
// most its caps, inside the service cgroup, with only the environment the
// grant allowed. Its program is resolved with the trusted walk and run
// through the checked fd. cwd and a file: stream are resolved beneath
// their grant root with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS); a
// stream file is opened O_NOFOLLOW, must be a regular file, and is handed
// to the child as an open fd. The cwd is passed by path after that check:
// a service that swaps a component of its own writable tree afterwards
// lands its own child elsewhere, still as its uid under its sandbox. A
// signal goes through the process's pidfd, so it cannot reach a reused pid.
type sashHost struct {
	sup *Supervisor
	s   *runtime
}

// sashChild is a spawned process's pidfd, closed once it is reaped.
type sashChild struct {
	mu    sync.Mutex
	pidfd int
}

func (c *sashChild) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	closePidfd(c.pidfd)
	c.pidfd = -1
}

func socketPair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fail.E("failed")
	}
	return os.NewFile(uintptr(fds[0]), "verb"), os.NewFile(uintptr(fds[1]), "verb-sash"), nil
}

func (h *sashHost) Status(service string) (sash.Row, error) { return h.sup.statusRow(service) }

// DialTCP connects once, with a short timeout. localhost is 127.0.0.1:
// nothing is looked up.
func (h *sashHost) DialTCP(addr string) bool {
	if strings.HasPrefix(addr, "localhost:") {
		addr = "127.0.0.1:" + strings.TrimPrefix(addr, "localhost:")
	}
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (h *sashHost) ProbePath(kind, root, p string) bool {
	fd, err := sandbox.OpenBeneath(root, p, unix.O_PATH, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	if kind == "file" {
		return true
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return false
	}
	c, err := net.DialTimeout("unix", "/proc/self/fd/"+strconv.Itoa(fd), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (h *sashHost) Signal(p *sash.Proc, sig string) error {
	c, ok := p.Handle().(*sashChild)
	n, known := signalNumber[sig]
	if !ok || !known {
		return fail.E("failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pidfd < 0 {
		return nil
	}
	err := unix.PidfdSendSignal(c.pidfd, n, nil, 0)
	if err == nil || err == unix.ESRCH {
		return nil
	}
	return fail.E("failed")
}

var signalNumber = map[string]syscall.Signal{
	"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "QUIT": syscall.SIGQUIT, "KILL": syscall.SIGKILL, "USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2, "TERM": syscall.SIGTERM, "CONT": syscall.SIGCONT, "STOP": syscall.SIGSTOP, "WINCH": syscall.SIGWINCH,
}

func signalName(sig syscall.Signal) string {
	for name, n := range signalNumber {
		if n == sig {
			return name
		}
	}
	return strings.TrimPrefix(unix.SignalName(sig), "SIG")
}

func (h *sashHost) Spawn(plan sash.SpawnPlan, p *sash.Proc) error {
	// Threats: Launch would give a spawn's caps to the child, and spawn caps
	// were never reviewed; the sash server refuses them before this.
	if len(plan.Caps) > 0 {
		return fail.E("caps_unsupported")
	}
	sup, s := h.sup, h.s
	svc := s.svc
	if sup.Cgroups == nil || svc.Sandbox == nil || svc.Execution.UID == nil {
		return fail.E("failed")
	}
	lookUser, lookGroup := LookupIDs()
	if sup.lookupUser != nil {
		lookUser, lookGroup = sup.lookupUser, sup.lookupGroup
	}
	uid, uerr := lookUser(plan.User)
	gid, gerr := lookGroup(plan.Group)
	if uerr != nil || gerr != nil || uid != *svc.Execution.UID || gid != *svc.Execution.GID {
		return fail.E("denied")
	}
	resolved, err := unit.ResolveExec(plan.Program)
	if err != nil {
		return fail.E("denied")
	}
	if plan.Cwd != "" {
		fd, err := sandbox.OpenBeneath(plan.CwdRoot, plan.Cwd, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			return fail.E("denied")
		}
		unix.Close(fd)
	}
	env := make([]string, 0, len(plan.Env))
	for _, e := range plan.Env {
		env = append(env, e.Name+"="+e.Value)
	}
	writer := func(st sash.Stream, tail *sash.Tail, label string) (io.Writer, error) {
		switch st.Kind {
		case "journal":
			tail.Copy = func(line string) { sup.journalLine(s, plan.Name, label, line) }
			return tail, nil
		}
		return nil, nil
	}
	out, err := writer(plan.Stdout, p.Stdout, "stdout")
	if err != nil {
		return err
	}
	errw := out
	if plan.Stderr.Kind != "stdout" {
		if errw, err = writer(plan.Stderr, p.Stderr, "stderr"); err != nil {
			return err
		}
	}
	// A spawned child never dumps core: a dump could carry a secret from
	// its environment.
	limits := map[string]uint64{"core": 0}
	for k, v := range plan.Limits {
		limits[k] = v
	}
	sb := *svc.Sandbox
	sb.Caps = append([]string{}, plan.Caps...)
	opts := sandbox.Options{
		Path:      resolved,
		Execution: unit.Execution{UID: &uid, GID: &gid, Groups: []uint32{}, Directory: plan.Cwd, Environment: env},
		Rlimits:   limits,
	}
	opts.Stdout, opts.Stderr = out, errw
	// A file stream is opened by the helper, as the child, beneath its
	// root: sahinit's own permissions never reach it.
	if plan.Stdout.Kind == "file" {
		opts.StdoutFile = &sandbox.StreamFile{Root: plan.Stdout.Root, Path: plan.Stdout.Path}
	}
	if plan.Stderr.Kind == "file" {
		opts.StderrFile = &sandbox.StreamFile{Root: plan.Stderr.Root, Path: plan.Stderr.Path}
	}
	opts.StderrToStdout = plan.Stderr.Kind == "stdout" && plan.Stdout.Kind == "file"
	if plan.Umask >= 0 {
		m := plan.Umask
		opts.Umask = &m
	}
	grp, err := sup.Cgroups.Join(svc.Name)
	if err != nil {
		return err
	}
	defer grp.Close()
	opts.Cgroup = grp
	sup.launching.RLock()
	cmd, _, notifyR, err := sandbox.Launch(context.Background(), sup.self, plan.Argv, &sb, true, timeoutOf(svc), opts)
	sup.launching.RUnlock()
	if err != nil {
		if fail.Token(err) == "stream_denied" {
			return fail.E("denied")
		}
		return fail.E("failed")
	}
	child := &sashChild{pidfd: openPidfd(cmd.Process.Pid)}
	p.Started(cmd.Process.Pid, time.Now().UTC(), child)
	if notifyR != nil {
		go func() {
			var b [1]byte
			if n, _ := notifyR.Read(b[:]); n == 1 {
				p.SetReady()
			}
			notifyR.Close()
		}()
	}
	go func() {
		cmd.Wait()
		child.close()
		code, sig := -1, ""
		if ps := cmd.ProcessState; ps != nil {
			code = ps.ExitCode()
			if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code, sig = 0, signalName(ws.Signal())
			}
		}
		p.Exit(code, sig, time.Now().UTC())
	}()
	return nil
}
