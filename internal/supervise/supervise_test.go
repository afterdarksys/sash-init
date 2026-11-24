// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/frame"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "apply" {
		os.Exit(sandbox.ApplyCLI(os.Args[1:]))
	}
	if sock := os.Getenv("SAHT_CLIENT_SOCK"); sock != "" {
		os.Exit(socketClient(sock, os.Getenv("SAHT_CLIENT_OUT")))
	}
	if mb := os.Getenv("SAHT_ALLOC_MB"); mb != "" {
		os.Exit(allocate(mb))
	}
	code := m.Run()
	if dir := tmpDirMade.Load(); dir != nil {
		os.RemoveAll(*dir)
	}
	os.Exit(code)
}

// socketClient runs inside a supervised service: one status request, with
// the raw response written to out-PGID.
func socketClient(sock, out string) int {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return 3
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 3
	}
	if err := frame.Write(c, []byte(`{"op":"status"}`)); err != nil {
		return 3
	}
	raw, err := frame.Read(c)
	if err != nil {
		return 3
	}
	// One file per process group, so several clients can be told apart.
	out += "-" + strconv.Itoa(syscall.Getpgrp())
	if err := os.WriteFile(out+".tmp", raw, 0o600); err != nil {
		return 3
	}
	if err := os.Rename(out+".tmp", out); err != nil {
		return 3
	}
	return 0
}

// allocate touches mb MiB, then exits 0: a service over memory_max is
// killed before it gets there.
func allocate(mb string) int {
	n, err := strconv.Atoi(mb)
	if err != nil || n <= 0 {
		return 3
	}
	var keep [][]byte
	for i := 0; i < n; i++ {
		b := make([]byte, 1<<20)
		for j := 0; j < len(b); j += 4096 {
			b[j] = 1
		}
		keep = append(keep, b)
	}
	return len(keep) - n
}

var pathSeq atomic.Uint64

// tmpRoot is a private 0700 directory under /tmp (short enough for a Unix
// socket path): a socket's directory must be writable by its owner only.
var tmpDirMade atomic.Pointer[string]

var tmpRoot = sync.OnceValue(func() string {
	dir, err := os.MkdirTemp("/tmp", "sah")
	if err != nil {
		panic(err)
	}
	tmpDirMade.Store(&dir)
	return dir
})

func tmpPath(prefix string) string {
	return fmt.Sprintf("%s/%s-%d", tmpRoot(), prefix, pathSeq.Add(1))
}

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Errorf("remove %s: %v", path, err)
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := tmpPath("sahs")
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeFile(t, p) })
	return p
}

func marker(t *testing.T) string {
	t.Helper()
	p := tmpPath("sahm")
	t.Cleanup(func() { removeFile(t, p) })
	return p
}

func shExec(script string, args ...string) []string {
	out := make([]string, 0, 2+len(args))
	out = append(out, "/bin/sh", script)
	return append(out, args...)
}

func newSvc(name, typ, ready, restart string, boot bool, timeout time.Duration, exec []string) *unit.Service {
	if timeout <= 0 {
		timeout = unit.DefaultTimeout
	}
	if restart == "" {
		restart = "no"
	}
	return &unit.Service{
		Name:    name,
		Exec:    exec,
		Type:    typ,
		Restart: restart,
		Ready:   ready,
		Timeout: timeout,
		Boot:    boot,
	}
}

func mustSup(t *testing.T, svcs map[string]*unit.Service) *Supervisor {
	t.Helper()
	sup, err := New(svcs, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sup.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return sup
}

func listenServe(t *testing.T, sup *Supervisor) string {
	t.Helper()
	path := tmpPath("sah")
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove socket: %v", err)
		}
	})
	if err := sup.Listen(path); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("serve did not return")
		}
	})
	t.Cleanup(func() {
		if err := sup.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sup.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	go func() {
		errc <- sup.Serve()
	}()
	return path
}

func rowOf(t *testing.T, sup *Supervisor, name string) Row {
	t.Helper()
	rows, err := sup.Status(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows %d", len(rows))
	}
	return rows[0]
}

func waitPID(t *testing.T, sup *Supervisor, name string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var row Row
	for {
		row = rowOf(t, sup, name)
		if row.Pid > 0 {
			return row.Pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pid: %+v", row)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatal("pid")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if err == syscall.ESRCH {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d alive: %v", pid, err)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last error
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			n, conv := strconv.Atoi(strings.TrimSpace(string(b)))
			if conv == nil && n > 0 {
				return n
			}
			last = conv
		} else {
			last = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid file %s: %v", path, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustPlan(t *testing.T, svcs map[string]*unit.Service) [][]string {
	t.Helper()
	waves, err := graph.Plan(svcs)
	if err != nil {
		t.Fatal(err)
	}
	return waves
}

type sockResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Rows  []Row  `json:"rows"`
}

func rpc(t *testing.T, path, payload string) (sockResp, []byte) {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := frame.Write(conn, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf, err := frame.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	var resp sockResp
	if err := json.Unmarshal(buf, &resp); err != nil {
		t.Fatalf("json %s: %v", buf, err)
	}
	return resp, buf
}

func TestParallelBoot(t *testing.T) {
	script := writeScript(t, `printf 'started\n' > "$1"
i=0
while [ "$i" -lt 160 ]; do
  if [ -f "$2" ]; then
    printf 'ok\n' > "$3"
    exit 0
  fi
  /bin/sleep 0.05
  i=$((i + 1))
done
exit 1
`)
	startedA := marker(t)
	startedB := marker(t)
	okA := marker(t)
	okB := marker(t)
	gate := marker(t)
	svcs := map[string]*unit.Service{
		"a": newSvc("a", "oneshot", "exit", "no", true, 15*time.Second, shExec(script, startedA, gate, okA)),
		"b": newSvc("b", "oneshot", "exit", "no", true, 15*time.Second, shExec(script, startedB, gate, okB)),
	}
	sup := mustSup(t, svcs)
	gateErr := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, e1 := os.Stat(startedA)
			_, e2 := os.Stat(startedB)
			if e1 == nil && e2 == nil {
				gateErr <- os.WriteFile(gate, []byte("go\n"), 0o644)
				return
			}
			if time.Now().After(deadline) {
				gateErr <- fmt.Errorf("started files missing")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, mustPlan(t, svcs)); err != nil {
		t.Fatalf("boot: %v", err)
	}
	if err := <-gateErr; err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{okA, okB} {
		b, err := os.ReadFile(p)
		if err != nil || string(b) != "ok\n" {
			t.Fatalf("%s: %q %v", p, b, err)
		}
	}
	for _, name := range []string{"a", "b"} {
		row := rowOf(t, sup, name)
		if row.State != "exited" || !row.Ready {
			t.Fatalf("%s %+v", name, row)
		}
	}
}

func TestNeedsOrder(t *testing.T) {
	markA := marker(t)
	markB := marker(t)
	scriptA := writeScript(t, "printf 'a\\n' > \"$1\"\nexit 0\n")
	scriptB := writeScript(t, `if [ -f "$1" ]; then
  printf 'b\n' > "$2"
  exit 0
fi
exit 1
`)
	a := newSvc("a", "oneshot", "exit", "no", true, 5*time.Second, shExec(scriptA, markA))
	b := newSvc("b", "oneshot", "exit", "no", true, 5*time.Second, shExec(scriptB, markA, markB))
	b.Needs = []string{"a"}
	svcs := map[string]*unit.Service{"a": a, "b": b}
	sup := mustSup(t, svcs)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, mustPlan(t, svcs)); err != nil {
		t.Fatal(err)
	}
	bdy, err := os.ReadFile(markB)
	if err != nil || string(bdy) != "b\n" {
		t.Fatalf("marker %q %v", bdy, err)
	}
	for _, name := range []string{"a", "b"} {
		row := rowOf(t, sup, name)
		if row.State != "exited" || !row.Ready {
			t.Fatalf("%s %+v", name, row)
		}
	}
}

func TestWantsFailureContinues(t *testing.T) {
	script := writeScript(t, "exit 1\n")
	helper := newSvc("helper", "oneshot", "exit", "no", true, 3*time.Second, shExec(script))
	agent := newSvc("agent", "simple", "exec", "no", true, 2*time.Second, []string{"/bin/sleep", "30"})
	agent.Wants = []string{"helper"}
	svcs := map[string]*unit.Service{"helper": helper, "agent": agent}
	waves := mustPlan(t, svcs)
	if len(waves) != 2 || len(waves[0]) != 1 || waves[0][0] != "helper" || waves[1][0] != "agent" {
		t.Fatalf("waves %#v", waves)
	}
	sup := mustSup(t, svcs)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := sup.Boot(ctx, waves)
	if fail.Token(err) != "failed" {
		t.Fatalf("boot %v", err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "running" || !row.Ready || row.Pid <= 0 || row.Sandbox != "none" {
		t.Fatalf("%+v", row)
	}
}

func TestAfterNonBoot(t *testing.T) {
	mark := marker(t)
	script := writeScript(t, "printf 'a\\n' > \"$1\"\nexit 0\n")
	a := newSvc("a", "oneshot", "exit", "no", true, 3*time.Second, shExec(script, mark))
	a.After = []string{"b"}
	b := newSvc("b", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	svcs := map[string]*unit.Service{"a": a, "b": b}
	sup := mustSup(t, svcs)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, mustPlan(t, svcs)); err != nil {
		t.Fatal(err)
	}
	if row := rowOf(t, sup, "b"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("b %+v", row)
	}
	if row := rowOf(t, sup, "a"); row.State != "exited" || !row.Ready {
		t.Fatalf("a %+v", row)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsFailed(t *testing.T) {
	mark := marker(t)
	brokeScript := writeScript(t, "exit 1\n")
	agentScript := writeScript(t, "printf 'ran\\n' > \"$1\"\n/bin/sleep 30\n")
	broke := newSvc("broke", "oneshot", "exit", "no", false, 3*time.Second, shExec(brokeScript))
	later := newSvc("later", "oneshot", "exit", "no", false, 3*time.Second, []string{"/bin/sh", "-c", "exit 0"})
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, shExec(agentScript, mark))
	agent.Needs = []string{"broke", "later"}
	sup := mustSup(t, map[string]*unit.Service{"broke": broke, "later": later, "agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.start(ctx, "broke", "", true, true); fail.Token(err) != "failed" {
		t.Fatalf("broke %v", err)
	}
	err := sup.Start(ctx, "agent")
	if fail.Token(err) != "needs_failed" {
		t.Fatalf("start %v", err)
	}
	if _, statErr := os.Stat(mark); !os.IsNotExist(statErr) {
		t.Fatalf("marker %v", statErr)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "blocked" || row.LastError != "needs_failed" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	if laterRow := rowOf(t, sup, "later"); laterRow.State != "stopped" {
		t.Fatalf("later %+v", laterRow)
	}
}

func TestNeedsNotReady(t *testing.T) {
	mark := marker(t)
	script := writeScript(t, "printf 'ran\\n' > \"$1\"\n/bin/sleep 30\n")
	later := newSvc("later", "oneshot", "exit", "no", false, 3*time.Second, []string{"/bin/sh", "-c", "exit 0"})
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, shExec(script, mark))
	agent.Needs = []string{"later"}
	sup := mustSup(t, map[string]*unit.Service{"later": later, "agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := sup.Start(ctx, "agent")
	if fail.Token(err) != "needs_not_ready" {
		t.Fatalf("%v", err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "blocked" || row.LastError != "needs_not_ready" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	if _, statErr := os.Stat(mark); !os.IsNotExist(statErr) {
		t.Fatalf("marker %v", statErr)
	}
}

func TestProcessGroupStop(t *testing.T) {
	shellFile := marker(t)
	childFile := marker(t)
	script := writeScript(t, `printf '%s\n' "$$" > "$1"
/bin/sleep 30 &
printf '%s\n' "$!" > "$2"
/bin/sleep 30
`)
	agent := newSvc("agent", "simple", "exec", "no", false, 3*time.Second, shExec(script, shellFile, childFile))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	shell := readPIDFile(t, shellFile)
	child := readPIDFile(t, childFile)
	if err := sup.Stop(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitDead(t, shell)
	waitDead(t, child)
	row := rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestNotifyReady(t *testing.T) {
	script := writeScript(t, "printf '\\n' >&3\n/bin/sleep 30\n")
	agent := newSvc("agent", "simple", "notify", "no", false, 3*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "running" || !row.Ready || row.Pid <= 0 || row.Sandbox != "none" {
		t.Fatalf("%+v", row)
	}
	if err := sup.Stop(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyTimeout(t *testing.T) {
	script := writeScript(t, "/bin/sleep 30\n")
	agent := newSvc("agent", "simple", "notify", "no", false, time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- sup.Start(ctx, "agent")
	}()
	pid := waitPID(t, sup, "agent")
	err := <-errc
	if fail.Token(err) != "timeout" {
		t.Fatalf("%v", err)
	}
	waitDead(t, pid)
	row := rowOf(t, sup, "agent")
	if row.State != "failed" || row.LastError != "timeout" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestOneshotTimeout(t *testing.T) {
	script := writeScript(t, "/bin/sleep 30\n")
	job := newSvc("job", "oneshot", "exit", "no", false, time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- sup.start(ctx, "job", "", true, true)
	}()
	pid := waitPID(t, sup, "job")
	err := <-errc
	if fail.Token(err) != "timeout" {
		t.Fatalf("%v", err)
	}
	waitDead(t, pid)
	row := rowOf(t, sup, "job")
	if row.State != "failed" || row.LastError != "timeout" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestRestartBurst(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "exec", "always", false, 2*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.RestartBurst = 2
	sup.RestartWindow = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var row Row
	for {
		row = rowOf(t, sup, "agent")
		if row.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %+v", row)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if row.Restarts != 2 || row.LastError != "restart_limit" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines %q", b)
	}
}

func TestStopStoppedAndExited(t *testing.T) {
	script := writeScript(t, "exit 0\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, shExec(script))
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"job": job, "agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Stop(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if row := rowOf(t, sup, "agent"); row.State != "stopped" || row.LastError != "" {
		t.Fatalf("%+v", row)
	}
	if err := sup.start(ctx, "job", "", true, true); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "job")
	if row.State != "exited" || !row.Ready {
		t.Fatalf("%+v", row)
	}
	if err := sup.Stop(ctx, "job"); err != nil {
		t.Fatal(err)
	}
	row = rowOf(t, sup, "job")
	if row.State != "exited" || !row.Ready {
		t.Fatalf("after stop %+v", row)
	}
}

func TestBusyStart(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	err := sup.Start(ctx, "agent")
	if fail.Token(err) != "busy" {
		t.Fatalf("%v", err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "running" || !row.Ready || row.Pid <= 0 {
		t.Fatalf("%+v", row)
	}
}

func TestOneshotArg(t *testing.T) {
	out := marker(t)
	script := writeScript(t, "printf '%s\\n' \"$2\" > \"$1\"\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, shExec(script, out))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	path := listenServe(t, sup)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sup.Oneshot(ctx, "job", ""); fail.Token(err) != "arg_required" {
		t.Fatalf("empty %v", err)
	}
	for _, arg := range []string{"a..b", "..", "a/b", "has space", strings.Repeat("a", 65)} {
		err := sup.Oneshot(ctx, "job", arg)
		if fail.Token(err) != "arg_rejected" {
			t.Fatalf("%q %v", arg, err)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("ran early %v", err)
	}

	resp, raw := rpc(t, path, `{"op":"oneshot","name":"job","arg":"a..b"}`)
	if resp.Error != "arg_rejected" || strings.Contains(string(raw), "a..b") {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"oneshot","name":"job"}`)
	if resp.Error != "arg_required" || len(resp.Rows) != 1 || resp.Rows[0].State != "stopped" {
		t.Fatalf("%s", raw)
	}

	if err := sup.Oneshot(ctx, "job", "."); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != ".\n" {
		t.Fatalf("%q %v", b, err)
	}

	resp, raw = rpc(t, path, `{"op":"oneshot","name":"job","arg":"marker-arg"}`)
	if !resp.OK || resp.Error != "" || strings.Contains(string(raw), "marker-arg") {
		t.Fatalf("%s", raw)
	}
	if len(resp.Rows) != 1 || resp.Rows[0].State != "exited" || !resp.Rows[0].Ready {
		t.Fatalf("%s", raw)
	}
	b, err = os.ReadFile(out)
	if err != nil || string(b) != "marker-arg\n" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestSocketStartStop(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	path := listenServe(t, sup)
	resp, raw := rpc(t, path, `{"op":"start","name":"agent"}`)
	if !resp.OK || resp.Error != "" || !strings.Contains(string(raw), `"error":""`) {
		t.Fatalf("%s", raw)
	}
	if len(resp.Rows) != 1 || resp.Rows[0].State != "running" || !resp.Rows[0].Ready || resp.Rows[0].Pid <= 0 || resp.Rows[0].Sandbox != "none" {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"stop","name":"agent"}`)
	if !resp.OK || resp.Error != "" || len(resp.Rows) != 1 || resp.Rows[0].State != "stopped" || resp.Rows[0].Pid != 0 {
		t.Fatalf("%s", raw)
	}
	if _, raw = rpc(t, path, `{"op":"start","name":"agent"}`); !strings.Contains(string(raw), `"state":"running"`) {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"restart","name":"agent"}`)
	if !resp.OK || resp.Error != "" || len(resp.Rows) != 1 || resp.Rows[0].State != "running" || resp.Rows[0].Pid <= 0 || !resp.Rows[0].Ready {
		t.Fatalf("%s", raw)
	}
}

func TestSocketProtocol(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	helper := newSvc("helper", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent, "helper": helper})
	path := listenServe(t, sup)

	resp, raw := rpc(t, path, `{"op":"status"}`)
	if !resp.OK || resp.Error != "" || len(resp.Rows) != 2 {
		t.Fatalf("%s", raw)
	}
	if resp.Rows[0].Name != "agent" || resp.Rows[1].Name != "helper" {
		t.Fatalf("%s", raw)
	}
	body := string(raw)
	if !strings.Contains(body, `"error":""`) || !strings.Contains(body, `"pid":0`) || !strings.Contains(body, `"ready":false`) {
		t.Fatalf("%s", raw)
	}

	_, raw = rpc(t, path, `{"op":"status","name":"zz-missing"}`)
	if string(raw) != `{"ok":false,"error":"not_found"}` {
		t.Fatalf("%s", raw)
	}
	_, raw = rpc(t, path, `{"op":"status","name":"BADNAME"}`)
	if string(raw) != `{"ok":false,"error":"not_found"}` || strings.Contains(string(raw), "BADNAME") {
		t.Fatalf("%s", raw)
	}
	_, raw = rpc(t, path, `{"name":"agent"}`)
	if string(raw) != `{"ok":false,"error":"failed"}` || strings.Contains(string(raw), "agent") {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"","name":"agent"}`)
	if resp.Error != "unknown_op" || len(resp.Rows) != 1 || resp.Rows[0].Name != "agent" {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"nope","name":"agent"}`)
	if resp.Error != "unknown_op" || len(resp.Rows) != 1 || resp.Rows[0].Name != "agent" {
		t.Fatalf("%s", raw)
	}
	_, raw = rpc(t, path, `{"op":"nope","name":"BADNAME"}`)
	if string(raw) != `{"ok":false,"error":"unknown_op"}` || strings.Contains(string(raw), "BADNAME") {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"oneshot","name":"agent","arg":"ok"}`)
	if resp.Error != "not_oneshot" || len(resp.Rows) != 1 || resp.Rows[0].State != "stopped" {
		t.Fatalf("%s", raw)
	}
}

func TestSocketBusy(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.MaxHandlers = 1
	path := listenServe(t, sup)
	c1, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	time.Sleep(40 * time.Millisecond)
	c2, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf, err := frame.Read(c2)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != `{"ok":false,"error":"busy"}` {
		t.Fatalf("%s", buf)
	}
}

func TestSocketOneshotWhileBusy(t *testing.T) {
	script := writeScript(t, "/bin/sleep 30\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 30*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	path := listenServe(t, sup)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		done <- sup.Oneshot(ctx, "job", "marker-arg")
	}()
	waitPID(t, sup, "job")
	started := time.Now()
	resp, raw := rpc(t, path, `{"op":"start","name":"job"}`)
	if time.Since(started) > time.Second {
		t.Fatalf("slow %s", raw)
	}
	if resp.Error != "arg_required" || strings.Contains(string(raw), "marker-arg") {
		t.Fatalf("%s", raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("oneshot did not return")
	}
}

func TestSocketMode(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	if err := sup.Listen(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if err := sup.Listen(path); fail.Token(err) != "socket_busy" {
		t.Fatal(err)
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unlink %v", err)
	}
}

func TestSocketExists(t *testing.T) {
	path := tmpPath("sah")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeFile(t, path) })
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	if err := sup.Listen(path); fail.Token(err) != "socket_exists" {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "keep" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestSocketFrameSize(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	path := listenServe(t, sup)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(frame.Max)+1)
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	buf, err := frame.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != `{"ok":false,"error":"frame_size"}` {
		t.Fatalf("%s", buf)
	}
}

func TestSocketUIDDeny(t *testing.T) {
	if os.Geteuid() == 65534 {
		t.Skip()
	}
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.Allow = map[uint32]struct{}{65534: {}}
	gid := uint32(os.Getegid())
	sup.SocketGID = &gid
	path := listenServe(t, sup)
	_, raw := rpc(t, path, `{"op":"status","name":"agent"}`)
	if string(raw) != `{"ok":false,"error":"uid_denied"}` {
		t.Fatalf("%s", raw)
	}
}

func TestSocketEmptyAllow(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.Allow = map[uint32]struct{}{}
	path := listenServe(t, sup)
	_, raw := rpc(t, path, `{"op":"status"}`)
	if string(raw) != `{"ok":false,"error":"uid_denied"}` {
		t.Fatalf("%s", raw)
	}
}

func TestStopAndShutdownKillStubbornDescendant(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprintf("shutdown=%v", shutdown), func(t *testing.T) {
			childFile := marker(t)
			childScript := writeScript(t, "trap '' TERM\nprintf '%s\\n' \"$$\" > \"$1\"\nwhile :; do /bin/sleep 1; done\n")
			parentScript := writeScript(t, "/bin/sh \"$1\" \"$2\" &\nwait\n")
			svc := newSvc("agent", "simple", "exec", "no", false, 150*time.Millisecond, shExec(parentScript, childScript, childFile))
			sup := mustSup(t, map[string]*unit.Service{"agent": svc})
			if err := sup.Start(context.Background(), "agent"); err != nil {
				t.Fatal(err)
			}
			leader := rowOf(t, sup, "agent").Pid
			t.Cleanup(func() { syscall.Kill(-leader, syscall.SIGKILL) })
			child := readPIDFile(t, childFile)
			var err error
			if shutdown {
				err = sup.Shutdown(context.Background())
			} else {
				err = sup.Stop(context.Background(), "agent")
			}
			if err != nil {
				t.Fatal(err)
			}
			waitDead(t, child)
			if row := rowOf(t, sup, "agent"); row.State != "stopped" || row.Pid != 0 {
				t.Fatalf("%+v", row)
			}
		})
	}
}
