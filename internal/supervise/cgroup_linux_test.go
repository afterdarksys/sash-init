// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/cgroup/cgtest"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// cgSup is mustSup with a fresh delegated cgroup root.
func cgSup(t *testing.T, svcs map[string]*unit.Service) (*Supervisor, *cgroup.Root) {
	t.Helper()
	r, err := cgroup.Open(cgtest.Dir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	sup := mustSup(t, svcs)
	sup.Cgroups = r
	return sup, r
}

// gone reports whether pid has exited (a zombie counts: it runs nothing).
func gone(pid int) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] == 'Z' || s[i+2] == 'X'
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !gone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d alive", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// escapeScript leaves a grandchild in a new session that ignores SIGTERM and
// writes its pid to $2, then becomes sleep: the grandchild is outside the
// service's process group and is not its child.
const escapeScript = `case "$1" in
grand) trap '' TERM; echo $$ > "$2"; while :; do sleep 1; done ;;
child) /bin/sh "$0" grand "$2" & exit 0 ;;
esac
setsid /bin/sh "$0" child "$2" &
exec sleep 60
`

// A setsid double fork is killed on stop, and the stop returns only once
// the service cgroup is empty and removed. With cgroup.kill hidden the
// freeze-and-kill fallback does the same.
func TestCgroupStopKillsSetsidDoubleFork(t *testing.T) {
	for _, hide := range []bool{false, true} {
		t.Run(map[bool]string{false: "cgroup.kill", true: "freeze"}[hide], func(t *testing.T) {
			m := marker(t)
			svc := newSvc("esc", "simple", "exec", "no", false, 2*time.Second, shExec(writeScript(t, escapeScript), "main", m))
			sup, r := cgSup(t, map[string]*unit.Service{"esc": svc})
			r.TestHooks(hide, nil)
			if err := sup.Start(t.Context(), "esc"); err != nil {
				t.Fatal(err)
			}
			grand := readPIDFile(t, m)
			if cg, err := cgtest.Cgroup(grand); err != nil || cg != r.Path("esc") {
				t.Fatalf("grandchild in %q %v", cg, err)
			}
			if pgid, _ := syscall.Getpgid(grand); pgid == rowOf(t, sup, "esc").Pid {
				t.Fatal("grandchild still in the service's process group")
			}
			if err := sup.Stop(t.Context(), "esc"); err != nil {
				t.Fatal(err)
			}
			if !gone(grand) {
				t.Fatalf("grandchild %d alive after stop", grand)
			}
			if _, err := os.Stat(cgroup.Mount + r.Path("esc")); !os.IsNotExist(err) {
				t.Fatalf("service cgroup left after stop: %v", err)
			}
			if row := rowOf(t, sup, "esc"); row.State != "stopped" || row.Usage != nil || row.Cgroups != CgroupsEnabled {
				t.Fatalf("%+v", row)
			}
		})
	}
}

// A leftover child is killed on restart: a user restart, and a restart after
// the main process exits.
func TestCgroupRestartKillsLeftover(t *testing.T) {
	leftover := `setsid sleep 60 &
echo $! >> "$1"
` + `[ "$2" = crash ] && exit 1
exec sleep 60
`
	for _, mode := range []string{"user", "crash"} {
		t.Run(mode, func(t *testing.T) {
			m := marker(t)
			svc := newSvc("left", "simple", "exec", "on-failure", false, 2*time.Second, shExec(writeScript(t, leftover), m, mode))
			sup, _ := cgSup(t, map[string]*unit.Service{"left": svc})
			sup.RestartBurst = 1
			if err := sup.Start(t.Context(), "left"); err != nil {
				t.Fatal(err)
			}
			first := firstPID(t, m)
			if mode == "user" {
				if err := sup.Restart(t.Context(), "left"); err != nil {
					t.Fatal(err)
				}
			}
			waitGone(t, first)
			if mode == "crash" {
				row := waitRow(t, sup, "left", 3*time.Second, func(r Row) bool { return r.State == "failed" })
				if row.LastError != "restart_limit" || row.Restarts != 1 {
					t.Fatalf("%+v", row)
				}
			}
		})
	}
}

// A peer that left its process group with setsid is still refused, because
// it is still in the service cgroup.
func TestCgroupPeerLeftGroup(t *testing.T) {
	out := clientOut(t)
	svc := newSvc("client", "simple", "exec", "no", false, 5*time.Second, []string{"/bin/sh", "-c", "setsid " + os.Args[0] + "; exec sleep 30"})
	sup, _ := cgSup(t, map[string]*unit.Service{"client": svc})
	path := listenServe(t, sup)
	svc.Execution.Environment = []string{"SAHT_CLIENT_SOCK=" + path, "SAHT_CLIENT_OUT=" + out}
	if err := sup.Start(t.Context(), "client"); err != nil {
		t.Fatal(err)
	}
	got := waitResponses(t, out, 1)
	if got[0] != refusedPeer {
		t.Fatalf("response %q", got)
	}
}

// firstPID reads the first pid appended to path.
func firstPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ := os.ReadFile(path)
		line, _, _ := strings.Cut(string(raw), "\n")
		if n, err := strconv.Atoi(line); err == nil && n > 0 {
			return n
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid file %s: %q", path, raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCgroupLimitsEnforced(t *testing.T) {
	t.Run("memory_max", func(t *testing.T) {
		svc := newSvc("hog", "simple", "exec", "no", false, 5*time.Second, []string{os.Args[0]})
		svc.Limits = unit.Limits{MemoryMax: 32 << 20}
		svc.Execution.Environment = []string{"SAHT_ALLOC_MB=512"}
		sup, _ := cgSup(t, map[string]*unit.Service{"hog": svc})
		if err := sup.Start(t.Context(), "hog"); err != nil {
			t.Fatal(err)
		}
		row := waitRow(t, sup, "hog", 10*time.Second, func(r Row) bool { return r.State == "failed" || r.State == "stopped" })
		d, err := sup.Diagnostics("hog")
		if err != nil {
			t.Fatal(err)
		}
		if row.State != "failed" || d.LastExit == nil || d.LastExit.Signal != int(syscall.SIGKILL) {
			t.Fatalf("%+v %+v", row, d.LastExit)
		}
		if row.Limits.MemoryMax != 32<<20 {
			t.Fatalf("%+v", row.Limits)
		}
	})
	t.Run("pids_max", func(t *testing.T) {
		// The forks run in a subshell, which dies when a fork fails.
		svc := newSvc("forks", "simple", "exec", "no", false, 5*time.Second, []string{"/bin/sh", "-c", "(for i in 1 2 3 4 5 6 7 8; do sleep 60 & done; wait); exec sleep 60"})
		svc.Limits = unit.Limits{PidsMax: 4}
		sup, _ := cgSup(t, map[string]*unit.Service{"forks": svc})
		if err := sup.Start(t.Context(), "forks"); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			d, err := sup.Diagnostics("forks")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(d.Stderr.Data)), "fork") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no fork failure: %q", d.Stderr.Data)
			}
			time.Sleep(10 * time.Millisecond)
		}
		row := rowOf(t, sup, "forks")
		if row.Usage == nil || row.Usage.PidsCurrent > 4 || row.Usage.PidsCurrent < 2 || row.Limits.PidsMax != 4 || row.State != "running" {
			t.Fatalf("%+v %+v", row, row.Usage)
		}
	})
	t.Run("cpu_max", func(t *testing.T) {
		svc := newSvc("cpu", "simple", "exec", "no", false, 5*time.Second, []string{"/bin/sleep", "60"})
		svc.Limits = unit.Limits{CPUQuota: 50000, CPUPeriod: 100000}
		sup, r := cgSup(t, map[string]*unit.Service{"cpu": svc})
		if err := sup.Start(t.Context(), "cpu"); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(cgroup.Mount + r.Path("cpu") + "/cpu.max")
		row := rowOf(t, sup, "cpu")
		if err != nil || strings.TrimSpace(string(raw)) != "50000 100000" || row.Limits.CPUMax != "50000 100000" {
			t.Fatalf("%q %v %+v", raw, err, row.Limits)
		}
		if row.Usage == nil || row.Usage.MemoryCurrent == 0 || row.Usage.PidsCurrent != 1 || row.Cgroup != r.Path("cpu") {
			t.Fatalf("%+v %+v", row, row.Usage)
		}
	})
}

// A limit needing a controller that is not available refuses the unit; so
// does any limit without cgroups. It is never silently ignored.
func TestCgroupControllerRefused(t *testing.T) {
	svc := newSvc("capped", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "60"})
	svc.Limits = unit.Limits{PidsMax: 8}
	r, err := cgroup.Open(cgtest.DirOffering(t, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	withRoot := mustSup(t, map[string]*unit.Service{"capped": svc})
	withRoot.Cgroups = r
	without := mustSup(t, map[string]*unit.Service{"capped": svc})
	for _, sup := range []*Supervisor{withRoot, without} {
		if err := sup.Start(t.Context(), "capped"); fail.Token(err) != "cgroup_controller" {
			t.Fatal(err)
		}
		if row := rowOf(t, sup, "capped"); row.State != "failed" || row.LastError != "cgroup_controller" || row.Pid != 0 {
			t.Fatalf("%+v", row)
		}
	}
}

// cgroup.events decides that a service has stopped: while it reports the
// cgroup populated, stop does not succeed, and the service is failed with
// cgroup_stuck once the stop timeout expires.
func TestCgroupEventsDecideStopped(t *testing.T) {
	svc := newSvc("stuck", "simple", "exec", "always", false, 300*time.Millisecond, []string{"/bin/sleep", "60"})
	sup, r := cgSup(t, map[string]*unit.Service{"stuck": svc})
	if err := sup.Start(t.Context(), "stuck"); err != nil {
		t.Fatal(err)
	}
	pid := rowOf(t, sup, "stuck").Pid
	r.TestHooks(false, func(string) (bool, error) { return true, nil })
	start := time.Now()
	if err := sup.Stop(t.Context(), "stuck"); fail.Token(err) != "cgroup_stuck" {
		t.Fatal(err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("stop returned before the timeout")
	}
	waitGone(t, pid)
	row := rowOf(t, sup, "stuck")
	if row.State != "failed" || row.LastError != "cgroup_stuck" {
		t.Fatalf("%+v", row)
	}
	d, err := sup.Diagnostics("stuck")
	if err != nil || d.Cgroups != CgroupsEnabled || !hasEvent(d.Events, "cgroup_stuck") {
		t.Fatalf("%+v %v", d, err)
	}
	// Once the cgroup reads empty, the service starts again.
	r.TestHooks(false, nil)
	if err := sup.Start(t.Context(), "stuck"); err != nil {
		t.Fatal(err)
	}
}

func hasEvent(events []Event, kind string) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// Without cgroups the supervisor behaves as before: process groups decide,
// status says cgroups are disabled, and a setsid escape outlives the stop
// (the residual cgroups close).
func TestNoCgroupsAsBefore(t *testing.T) {
	m := marker(t)
	svc := newSvc("esc", "simple", "exec", "no", false, 2*time.Second, shExec(writeScript(t, escapeScript), "main", m))
	sup := mustSup(t, map[string]*unit.Service{"esc": svc})
	if err := sup.Start(t.Context(), "esc"); err != nil {
		t.Fatal(err)
	}
	grand := readPIDFile(t, m)
	t.Cleanup(func() { syscall.Kill(grand, syscall.SIGKILL) })
	own, err := cgtest.Cgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if cg, err := cgtest.Cgroup(grand); err != nil || cg != own {
		t.Fatalf("service moved to %q %v", cg, err)
	}
	row := rowOf(t, sup, "esc")
	if row.Cgroups != CgroupsDisabled || row.Cgroup != "" || row.Usage != nil {
		t.Fatalf("%+v", row)
	}
	if err := sup.Stop(t.Context(), "esc"); err != nil {
		t.Fatal(err)
	}
	if gone(grand) {
		t.Fatal("setsid grandchild killed without cgroups")
	}
}

// A service process that moves itself into the supervisor's leaf (which a
// service running as the supervisor's uid can) is found and killed when the
// service ends, and named on the log.
func TestCgroupStrayInLeafKilled(t *testing.T) {
	m := marker(t)
	script := `/bin/sh -c 'echo 0 > "$1/cgroup.procs" || exit 1; echo $$ > "$2"; trap "" TERM; while :; do sleep 1; done' x "$1" "$2" &
exec sleep 60
`
	svc := newSvc("esc", "simple", "exec", "no", false, 2*time.Second, nil)
	sup, r := cgSup(t, map[string]*unit.Service{"esc": svc})
	leafDir := cgroup.Mount + strings.TrimSuffix(r.Path("x"), "/x.service") + "/supervisor"
	if err := os.Mkdir(leafDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cgtest.Remove(leafDir) })
	svc.Exec = shExec(writeScript(t, script), leafDir, m)
	log := &logSink{b: &strings.Builder{}}
	sup.Log = log
	if err := sup.Start(t.Context(), "esc"); err != nil {
		t.Fatal(err)
	}
	stray := readPIDFile(t, m)
	if cg, _ := cgtest.Cgroup(stray); cg != cgtest.Rel(leafDir) {
		t.Fatalf("stray in %q", cg)
	}
	if err := sup.Stop(t.Context(), "esc"); err != nil {
		t.Fatal(err)
	}
	waitGone(t, stray)
	if !strings.Contains(log.String(), "cgroup_stray "+strconv.Itoa(stray)) {
		t.Fatalf("log %q", log.String())
	}
}

type logSink struct {
	mu sync.Mutex
	b  *strings.Builder
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// The sweep also runs on a timer: a process hidden in an unknown cgroup
// under the root is killed and the cgroup removed with no other trigger.
func TestCgroupSweepTimer(t *testing.T) {
	svc := newSvc("idle", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "60"})
	sup, r := cgSup(t, map[string]*unit.Service{"idle": svc})
	log := &logSink{b: &strings.Builder{}}
	sup.Log = log
	if err := sup.Start(t.Context(), "idle"); err != nil {
		t.Fatal(err)
	}
	pid := rowOf(t, sup, "idle").Pid
	hide := cgroup.Mount + strings.TrimSuffix(r.Path("idle"), "/idle.service") + "/hide"
	if err := os.Mkdir(hide, 0o755); err != nil {
		t.Fatal(err)
	}
	// A second process of the service hides; the main process stays.
	hider := writeScript(t, "echo 0 > \"$1/cgroup.procs\"; exec sleep 60\n")
	cmd := exec.Command("/bin/sh", hider, hide)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	f, err := os.Open(cgroup.Mount + r.Path("idle"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, int(f.Fd())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go cmd.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if cg, _ := cgtest.Cgroup(cmd.Process.Pid); cg == cgtest.Rel(hide) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never hid")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go sup.SweepEvery(ctx, 50*time.Millisecond)
	waitGone(t, cmd.Process.Pid)
	deadline = time.Now().Add(2 * time.Second)
	for !strings.Contains(log.String(), "cgroup_stray_cgroup "+cgtest.Rel(hide)) {
		if time.Now().After(deadline) {
			t.Fatalf("log %q", log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(hide); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if gone(pid) || rowOf(t, sup, "idle").State != "running" {
		t.Fatal("running service touched")
	}
}

// A second supervisor on the same cgroup root refuses, and the first one's
// service keeps running.
func TestCgroupSecondInstanceBusy(t *testing.T) {
	svc := newSvc("idle", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "60"})
	sup, r := cgSup(t, map[string]*unit.Service{"idle": svc})
	if err := sup.Start(t.Context(), "idle"); err != nil {
		t.Fatal(err)
	}
	pid := rowOf(t, sup, "idle").Pid
	dir := cgroup.Mount + strings.TrimSuffix(r.Path("idle"), "/idle.service")
	if b, err := cgroup.Open(dir); fail.Token(err) != "cgroup_busy" {
		b.Close()
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if gone(pid) || rowOf(t, sup, "idle").State != "running" {
		t.Fatal("first instance's service disturbed")
	}
}

// With no controller enabled below the root, a process in the root itself
// may be an escaped service, and is refused as a peer; with controllers
// enabled, a process in ROOT/.control (systemd's ExecReload) is accepted.
func TestCgroupRootMemberPeer(t *testing.T) {
	for _, protected := range []bool{false, true} {
		t.Run(fmt.Sprintf("protected=%v", protected), func(t *testing.T) {
			dir := cgtest.DirOffering(t)
			into := dir
			if protected {
				dir = cgtest.Dir(t)
				into = dir + "/.control"
				if err := os.Mkdir(into, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			r, err := cgroup.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			if r.Protected() != protected {
				t.Fatal("protected")
			}
			sup := mustSup(t, map[string]*unit.Service{"idle": newSvc("idle", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})})
			sup.Cgroups = r
			f, err := os.Open(into)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			cmd := exec.Command("/bin/sleep", "60")
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
			if err != nil {
				t.Skip("no pidfd_open")
			}
			pin := peerPin{fd: fd, pid: cmd.Process.Pid}
			defer pin.close()
			if sup.peerRefused(pin) == protected {
				t.Fatalf("protected=%v refused=%v", protected, !protected)
			}
		})
	}
}
