package supervise

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/frame"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func fileLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func waitRow(t *testing.T, sup *Supervisor, name string, d time.Duration, pred func(Row) bool) Row {
	t.Helper()
	deadline := time.Now().Add(d)
	var row Row
	for {
		row = rowOf(t, sup, name)
		if pred(row) {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %+v", name, row)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func stopRetry(t *testing.T, sup *Supervisor, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := sup.Stop(ctx, name)
		if err == nil {
			return
		}
		if fail.Token(err) != "busy" || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func holdStill(t *testing.T, d time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !pred() {
			t.Fatal("state changed")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s %v", path, err)
	}
}

func wantExact(t *testing.T, path, payload, exact string) {
	t.Helper()
	_, raw := rpc(t, path, payload)
	if string(raw) != exact {
		t.Fatalf("%s\n%s", payload, raw)
	}
}

func stoppedRow(name, sandbox string) string {
	return `{"name":"` + name + `","state":"stopped","pid":0,"ready":false,"restarts":0,"sandbox":"` + sandbox + `","last_error":""}`
}

func exactErr(token string) string {
	return `{"ok":false,"error":"` + token + `"}`
}

func exactErrRow(token, row string) string {
	return `{"ok":false,"error":"` + token + `","rows":[` + row + `]}`
}

func ctxFor(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}

func TestRestartAlwaysClean(t *testing.T) {
	log := marker(t)
	gate := marker(t)
	script := writeScript(t, `printf 'x\n' >> "$1"
if [ -f "$2" ]; then
  /bin/sleep 30
else
  : > "$2"
  exit 0
fi
`)
	agent := newSvc("agent", "simple", "exec", "always", false, 30*time.Second, shExec(script, log, gate))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.Restarts >= 1 && (row.State == "running" || row.State == "starting") && row.Pid > 0 && fileLines(t, log) >= 2
	})
	stopRetry(t, sup, "agent")
	row := rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	holdStill(t, 200*time.Millisecond, func() bool {
		row = rowOf(t, sup, "agent")
		return row.State == "stopped" && row.Pid == 0
	})
}

func TestRestartOnFailureCrash(t *testing.T) {
	gate := marker(t)
	slept := marker(t)
	script := writeScript(t, `if [ -f "$1" ]; then
  printf 'slept\n' > "$2"
  /bin/sleep 30
else
  : > "$1"
  exit 1
fi
`)
	agent := newSvc("agent", "simple", "exec", "on-failure", false, 30*time.Second, shExec(script, gate, slept))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.Restarts == 1 && row.State == "running" && row.Pid > 0 && fileLines(t, slept) == 1
	})
	stopRetry(t, sup, "agent")
	row := rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Restarts != 1 {
		t.Fatalf("%+v", row)
	}
}

func TestRestartOnFailureClean(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 0\n")
	agent := newSvc("agent", "simple", "exec", "on-failure", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitRow(t, sup, "agent", 5*time.Second, func(row Row) bool {
		return row.State == "stopped" && row.Restarts == 0 && fileLines(t, log) == 1
	})
	holdStill(t, 200*time.Millisecond, func() bool {
		row := rowOf(t, sup, "agent")
		return row.State == "stopped" && row.Restarts == 0 && row.LastError == "" && fileLines(t, log) == 1
	})
}

func TestRestartNoClean(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 0\n")
	agent := newSvc("agent", "simple", "exec", "no", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "agent", 5*time.Second, func(row Row) bool {
		return row.State == "stopped" && row.Restarts == 0 && row.LastError == "" && fileLines(t, log) == 1
	})
	if row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	holdStill(t, 200*time.Millisecond, func() bool {
		row = rowOf(t, sup, "agent")
		return row.State == "stopped" && row.Restarts == 0 && row.LastError == "" && fileLines(t, log) == 1
	})
}

func TestRestartNoCrash(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "exec", "no", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "agent", 5*time.Second, func(row Row) bool {
		return row.State == "failed" && row.LastError == "failed" && row.Restarts == 0 && fileLines(t, log) == 1
	})
	if row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	holdStill(t, 200*time.Millisecond, func() bool {
		row = rowOf(t, sup, "agent")
		return row.State == "failed" && row.LastError == "failed" && row.Restarts == 0 && fileLines(t, log) == 1
	})
}

func TestRestartNotifyBeforeReady(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "notify", "always", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "failed" || row.Restarts != 0 || row.Pid != 0 || fileLines(t, log) != 1 {
		t.Fatalf("%+v lines %d", row, fileLines(t, log))
	}
	holdStill(t, 200*time.Millisecond, func() bool {
		row = rowOf(t, sup, "agent")
		return row.State == "failed" && row.Restarts == 0 && fileLines(t, log) == 1
	})
}

func TestRestartNotifyAfterReady(t *testing.T) {
	log := marker(t)
	gate := marker(t)
	script := writeScript(t, `printf '\n' >&3
printf 'x\n' >> "$1"
if [ -f "$2" ]; then
  /bin/sleep 30
else
  : > "$2"
  exit 1
fi
`)
	agent := newSvc("agent", "simple", "notify", "always", false, 30*time.Second, shExec(script, log, gate))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.Restarts >= 1 && row.State == "running" && row.Pid > 0 && fileLines(t, log) >= 2
	})
	stopRetry(t, sup, "agent")
	row := rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestRestartNotifyClean(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf '\\n' >&3\nprintf 'x\\n' >> \"$1\"\nexit 0\n")
	agent := newSvc("agent", "simple", "notify", "on-failure", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitRow(t, sup, "agent", 5*time.Second, func(row Row) bool {
		return row.State == "stopped" && row.Restarts == 0 && fileLines(t, log) == 1
	})
	holdStill(t, 200*time.Millisecond, func() bool {
		row := rowOf(t, sup, "agent")
		return row.State == "stopped" && row.Restarts == 0 && row.LastError == "" && fileLines(t, log) == 1
	})
}

func TestRestartWindowPrune(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "/bin/sleep 0.2\nprintf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "exec", "always", false, 30*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.RestartBurst = 1
	sup.RestartWindow = 50 * time.Millisecond
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.Restarts >= 2 && (row.State == "running" || row.State == "starting") && row.Pid > 0
	})
	if fileLines(t, log) < 2 {
		t.Fatalf("lines %d %+v", fileLines(t, log), row)
	}
	stopRetry(t, sup, "agent")
	holdStill(t, 200*time.Millisecond, func() bool {
		row = rowOf(t, sup, "agent")
		return row.State == "stopped" && row.Pid == 0
	})
}

func TestRestartBurstDefault(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "exec", "always", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.RestartBurst = 0
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.State == "failed" && row.LastError == "restart_limit"
	})
	if row.Restarts != 5 || row.Pid != 0 || fileLines(t, log) != 6 {
		t.Fatalf("%+v lines %d", row, fileLines(t, log))
	}
}

func TestRestartWindowDefault(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "exec", "always", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.RestartBurst = 2
	sup.RestartWindow = 0
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.State == "failed" && row.LastError == "restart_limit"
	})
	if row.Restarts != 2 || fileLines(t, log) != 3 {
		t.Fatalf("%+v lines %d", row, fileLines(t, log))
	}
}

func TestRestartAfterLimit(t *testing.T) {
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 1\n")
	agent := newSvc("agent", "simple", "exec", "always", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.RestartBurst = 2
	ctx, cancel := ctxFor(t, 8*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.State == "failed" && row.Restarts == 2 && row.LastError == "restart_limit" && fileLines(t, log) == 3
	})
	if row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	if err := sup.Restart(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row = waitRow(t, sup, "agent", 8*time.Second, func(row Row) bool {
		return row.State == "failed" && row.Restarts == 2 && row.LastError == "restart_limit" && fileLines(t, log) == 6
	})
	if row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestStopFailedClears(t *testing.T) {
	script := writeScript(t, "exit 1\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.start(ctx, "job", "", true, true); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "job")
	if row.State != "failed" || row.Pid != 0 || row.LastError != "failed" {
		t.Fatalf("%+v", row)
	}
	if err := sup.Stop(ctx, "job"); err != nil {
		t.Fatal(err)
	}
	row = rowOf(t, sup, "job")
	if row.State != "stopped" || row.Ready || row.LastError != "" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestRetryFailedOneshot(t *testing.T) {
	out := marker(t)
	gate := marker(t)
	script := writeScript(t, `if [ -f "$2" ]; then
  printf 'ok\n' > "$1"
  exit 0
fi
exit 1
`)
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, shExec(script, out, gate))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.start(ctx, "job", "", true, true); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	absent(t, out)
	if err := os.WriteFile(gate, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sup.start(ctx, "job", "", true, true); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "job")
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "ok\n" || row.State != "exited" || !row.Ready {
		t.Fatalf("%q %+v %v", b, row, err)
	}
}

func TestStartCanceled(t *testing.T) {
	out := marker(t)
	script := writeScript(t, "printf 'ran\\n' > \"$1\"\n/bin/sleep 30\n")
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, shExec(script, out))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	if err := sup.Start(nil, "agent"); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sup.Start(ctx, "agent"); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	absent(t, out)
	row := rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Pid != 0 || row.LastError != "" {
		t.Fatalf("%+v", row)
	}
}

func TestStopNilAndCanceled(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	if err := sup.Stop(nil, "agent"); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	if row := rowOf(t, sup, "agent"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	pid := rowOf(t, sup, "agent").Pid
	stopCtx, stopCancel := context.WithCancel(context.Background())
	stopCancel()
	if err := sup.Stop(stopCtx, "agent"); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "running" || row.Pid != pid || pid <= 0 {
		t.Fatalf("%+v", row)
	}
	if err := sup.Stop(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	waitDead(t, pid)
	if row = rowOf(t, sup, "agent"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestCancelDuringOneshot(t *testing.T) {
	script := writeScript(t, "/bin/sleep 30\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 30*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sup.start(ctx, "job", "", true, true)
	}()
	pid := waitPID(t, sup, "job")
	cancel()
	select {
	case err := <-done:
		if fail.Token(err) != "timeout" {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start stuck")
	}
	row := rowOf(t, sup, "job")
	if row.State != "failed" || row.LastError != "timeout" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	waitDead(t, pid)
}

func TestStopDuringNotifyStart(t *testing.T) {
	script := writeScript(t, "/bin/sleep 30\nprintf '\\n' >&3\n")
	agent := newSvc("agent", "simple", "notify", "no", false, 30*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sup.Start(ctx, "agent")
	}()
	pid := waitPID(t, sup, "agent")
	if err := sup.Stop(ctx, "agent"); fail.Token(err) != "busy" {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "starting" || row.Pid != pid {
		t.Fatalf("%+v", row)
	}
	shut, shutCancel := ctxFor(t, 5*time.Second)
	defer shutCancel()
	if err := sup.Shutdown(shut); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("start returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start stuck")
	}
	row = rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	waitDead(t, pid)
}

func TestShutdownNil(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	pid := rowOf(t, sup, "agent").Pid
	if err := sup.Shutdown(nil); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	waitDead(t, pid)
	if err := sup.Shutdown(nil); err != nil {
		t.Fatal(err)
	}
}

func TestStartAgain(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	log := marker(t)
	script := writeScript(t, "printf 'x\\n' >> \"$1\"\nexit 0\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, shExec(script, log))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent, "job": job})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	pid1 := rowOf(t, sup, "agent").Pid
	if err := sup.Stop(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "running" || row.Pid == pid1 || row.Pid <= 0 {
		t.Fatalf("pid %d %+v", pid1, row)
	}
	if err := sup.start(ctx, "job", "", true, true); err != nil {
		t.Fatal(err)
	}
	if fileLines(t, log) != 1 || rowOf(t, sup, "job").State != "exited" {
		t.Fatalf("%+v", rowOf(t, sup, "job"))
	}
	if err := sup.start(ctx, "job", "", true, true); err != nil {
		t.Fatal(err)
	}
	row = rowOf(t, sup, "job")
	if row.State != "exited" || !row.Ready || fileLines(t, log) != 2 {
		t.Fatalf("%+v lines %d", row, fileLines(t, log))
	}
}

func TestAPIRejects(t *testing.T) {
	out := marker(t)
	script := writeScript(t, "printf 'ran\\n' > \"$1\"\n")
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	helper := newSvc("helper", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, shExec(script, out))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent, "helper": helper, "job": job})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Oneshot(ctx, "zz-missing", "a..b"); fail.Token(err) != "not_found" {
		t.Fatal(err)
	}
	if err := sup.Oneshot(ctx, "agent", "a..b"); fail.Token(err) != "not_oneshot" {
		t.Fatal(err)
	}
	if err := sup.Oneshot(ctx, "job", "a..b"); fail.Token(err) != "arg_rejected" {
		t.Fatal(err)
	}
	absent(t, out)
	for _, name := range []string{"zz-missing", "BADNAME"} {
		if err := sup.Start(ctx, name); fail.Token(err) != "not_found" {
			t.Fatalf("start %s %v", name, err)
		}
		if err := sup.Stop(ctx, name); fail.Token(err) != "not_found" {
			t.Fatalf("stop %s %v", name, err)
		}
		if err := sup.Restart(ctx, name); fail.Token(err) != "not_found" {
			t.Fatalf("restart %s %v", name, err)
		}
	}
	for _, name := range []string{"BADNAME", "nope"} {
		rows, err := sup.Status(name)
		if fail.Token(err) != "not_found" || rows != nil {
			t.Fatalf("%s %v %v", name, rows, err)
		}
	}
	rows, err := sup.Status("")
	if err != nil || len(rows) != 3 {
		t.Fatalf("%v %v", rows, err)
	}
	if rows[0].Name != "agent" || rows[1].Name != "helper" || rows[2].Name != "job" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].Pid != 0 || rows[0].Ready || rows[0].State != "stopped" {
		t.Fatalf("%+v", rows[0])
	}
}

func TestArgRejectedWhileBusy(t *testing.T) {
	script := writeScript(t, "/bin/sleep 30\n")
	job := newSvc("job", "oneshot", "exit", "no", false, 30*time.Second, shExec(script))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	done := make(chan error, 1)
	go func() {
		ctx, cancel := ctxFor(t, 20*time.Second)
		defer cancel()
		done <- sup.start(ctx, "job", "", true, true)
	}()
	waitPID(t, sup, "job")
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	started := time.Now()
	err := sup.Oneshot(ctx, "job", "a..b")
	if time.Since(started) > time.Second || fail.Token(err) != "arg_rejected" {
		t.Fatal(err)
	}
	shut, shutCancel := ctxFor(t, 5*time.Second)
	defer shutCancel()
	if err := sup.Shutdown(shut); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("start stuck")
	}
}

func TestNewRejects(t *testing.T) {
	svc := newSvc("agent", "simple", "exec", "no", false, time.Second, []string{"/bin/sh"})
	other := newSvc("other", "simple", "exec", "no", false, time.Second, []string{"/bin/sh"})
	if sup, err := New(nil, "/bin/sh"); sup != nil || fail.Token(err) != "failed" {
		t.Fatalf("%v %v", sup, err)
	}
	if sup, err := New(map[string]*unit.Service{}, "/bin/sh"); sup != nil || fail.Token(err) != "failed" {
		t.Fatalf("%v %v", sup, err)
	}
	if sup, err := New(map[string]*unit.Service{"agent": svc}, ""); sup != nil || fail.Token(err) != "failed" {
		t.Fatalf("%v %v", sup, err)
	}
	missing := tmpPath("sahm")
	if sup, err := New(map[string]*unit.Service{"agent": svc}, missing); sup != nil || fail.Token(err) != "exec_not_file" {
		t.Fatalf("%v %v", sup, err)
	}
	if sup, err := New(map[string]*unit.Service{"agent": nil}, "/bin/sh"); sup != nil || fail.Token(err) != "failed" {
		t.Fatalf("%v %v", sup, err)
	}
	if sup, err := New(map[string]*unit.Service{"agent": other}, "/bin/sh"); sup != nil || fail.Token(err) != "failed" {
		t.Fatalf("%v %v", sup, err)
	}
	link := tmpPath("sahs")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeFile(t, link) })
	// A link to a good binary is followed once and accepted.
	if sup, err := New(map[string]*unit.Service{"agent": svc}, link); sup == nil || err != nil {
		t.Fatalf("%v %v", sup, err)
	}
	writable := tmpPath("sahs")
	if err := os.WriteFile(writable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeFile(t, writable) })
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if sup, err := New(map[string]*unit.Service{"agent": svc}, writable); sup != nil || fail.Token(err) != "exec_perm" {
		t.Fatalf("%v %v", sup, err)
	}
}

func TestServeEdges(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	path := listenServe(t, sup)
	resp, raw := rpc(t, path, `{"op":"status","name":"agent"}`)
	if !resp.OK || resp.Error != "" {
		t.Fatalf("%s", raw)
	}
	started := time.Now()
	if err := sup.Serve(); fail.Token(err) != "failed" || time.Since(started) > time.Second {
		t.Fatal(err)
	}
	fresh := mustSup(t, map[string]*unit.Service{"agent": newSvc("agent", "simple", "exec", "no", false, time.Second, []string{"/bin/sh"})})
	started = time.Now()
	if err := fresh.Serve(); fail.Token(err) != "failed" || time.Since(started) > time.Second {
		t.Fatal(err)
	}
	if err := fresh.Serve(); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	if err := fresh.Listen(""); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOneshotArgvFull(t *testing.T) {
	out := marker(t)
	script := writeScript(t, "printf 'ran\\n' > \"$1\"\n")
	exec := shExec(script, out)
	for len(exec) < 32 {
		exec = append(exec, "x")
	}
	if len(exec) != 32 {
		t.Fatalf("len %d", len(exec))
	}
	job := newSvc("job", "oneshot", "exit", "no", false, 3*time.Second, exec)
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.start(ctx, "job", "", true, true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "ran\n" {
		t.Fatalf("%q %v", b, err)
	}
	if row := rowOf(t, sup, "job"); row.State != "exited" || !row.Ready || row.LastError != "" {
		t.Fatalf("%+v", row)
	}
	if err := sup.Oneshot(ctx, "job", "more"); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "job")
	b, err = os.ReadFile(out)
	if err != nil || string(b) != "ran\n" || row.State != "exited" || row.LastError != "" {
		t.Fatalf("%q %+v %v", b, row, err)
	}
}

func TestSignalGroupNonPositive(t *testing.T) {
	if err := signalGroup(0, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := signalGroup(-1, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
}

func TestBootEmpty(t *testing.T) {
	out := marker(t)
	script := writeScript(t, "printf 'ran\\n' > \"$1\"\n")
	job := newSvc("job", "oneshot", "exit", "no", true, 3*time.Second, shExec(script, out))
	sup := mustSup(t, map[string]*unit.Service{"job": job})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := sup.Boot(ctx, [][]string{}); err != nil {
		t.Fatal(err)
	}
	if err := sup.Boot(ctx, [][]string{{}}); err != nil {
		t.Fatal(err)
	}
	absent(t, out)
	if row := rowOf(t, sup, "job"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestBootUnknownName(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", true, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, [][]string{{"missing"}}); fail.Token(err) != "not_found" {
		t.Fatal(err)
	}
	if row := rowOf(t, sup, "agent"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestBootWaveContinues(t *testing.T) {
	badOut := marker(t)
	goodOut := marker(t)
	badScript := writeScript(t, "printf 'bad\\n' > \"$1\"\nexit 1\n")
	goodScript := writeScript(t, "printf 'good\\n' > \"$1\"\nexit 0\n")
	bad := newSvc("bad", "oneshot", "exit", "no", true, 3*time.Second, shExec(badScript, badOut))
	good := newSvc("good", "oneshot", "exit", "no", true, 3*time.Second, shExec(goodScript, goodOut))
	sup := mustSup(t, map[string]*unit.Service{"bad": bad, "good": good})
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, [][]string{{"bad", "good"}}); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	badRow := rowOf(t, sup, "bad")
	goodRow := rowOf(t, sup, "good")
	badBody, err := os.ReadFile(badOut)
	if err != nil || string(badBody) != "bad\n" || badRow.State != "failed" {
		t.Fatalf("%q %+v %v", badBody, badRow, err)
	}
	goodBody, err := os.ReadFile(goodOut)
	if err != nil || string(goodBody) != "good\n" || goodRow.State != "exited" || !goodRow.Ready {
		t.Fatalf("%q %+v %v", goodBody, goodRow, err)
	}
}

func TestBootContinuesNextWave(t *testing.T) {
	aOut := marker(t)
	bOut := marker(t)
	cOut := marker(t)
	aScript := writeScript(t, "printf 'a\\n' > \"$1\"\nexit 1\n")
	bScript := writeScript(t, "printf 'b\\n' > \"$1\"\nexit 0\n")
	cScript := writeScript(t, `if [ -s "$1" ]; then
  printf 'ok\n' > "$2"
else
  exit 1
fi
exit 0
`)
	a := newSvc("a", "oneshot", "exit", "no", true, 3*time.Second, shExec(aScript, aOut))
	b := newSvc("b", "oneshot", "exit", "no", true, 3*time.Second, shExec(bScript, bOut))
	c := newSvc("c", "oneshot", "exit", "no", true, 3*time.Second, shExec(cScript, bOut, cOut))
	c.After = []string{"b"}
	svcs := map[string]*unit.Service{"a": a, "b": b, "c": c}
	waves := mustPlan(t, svcs)
	if len(waves) != 2 || strings.Join(waves[0], ",") != "a,b" || strings.Join(waves[1], ",") != "c" {
		t.Fatalf("%#v", waves)
	}
	sup := mustSup(t, svcs)
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, waves); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	cBody, err := os.ReadFile(cOut)
	cRow := rowOf(t, sup, "c")
	if err != nil || string(cBody) != "ok\n" || cRow.State != "exited" || !cRow.Ready {
		t.Fatalf("%q %+v %v", cBody, cRow, err)
	}
}

func TestBootNeedsFailedSkipsDependent(t *testing.T) {
	aOut := marker(t)
	bOut := marker(t)
	aScript := writeScript(t, "printf 'a\\n' > \"$1\"\nexit 1\n")
	bScript := writeScript(t, "printf 'b\\n' > \"$1\"\nexit 0\n")
	a := newSvc("a", "oneshot", "exit", "no", true, 3*time.Second, shExec(aScript, aOut))
	b := newSvc("b", "oneshot", "exit", "no", true, 3*time.Second, shExec(bScript, bOut))
	b.Needs = []string{"a"}
	svcs := map[string]*unit.Service{"a": a, "b": b}
	waves := mustPlan(t, svcs)
	if len(waves) != 2 || strings.Join(waves[0], ",") != "a" || strings.Join(waves[1], ",") != "b" {
		t.Fatalf("%#v", waves)
	}
	sup := mustSup(t, svcs)
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, waves); fail.Token(err) != "failed" {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(aOut); err != nil {
		t.Fatal(err)
	}
	absent(t, bOut)
	row := rowOf(t, sup, "b")
	if row.State != "failed" || row.LastError != "needs_failed" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
}

func TestBootAfterOrder(t *testing.T) {
	aOut := marker(t)
	bOut := marker(t)
	aScript := writeScript(t, "printf 'a\\n' > \"$1\"\nexit 0\n")
	bScript := writeScript(t, `if [ -s "$1" ]; then
  printf 'ok\n' > "$2"
else
  exit 1
fi
exit 0
`)
	a := newSvc("a", "oneshot", "exit", "no", true, 3*time.Second, shExec(aScript, aOut))
	b := newSvc("b", "oneshot", "exit", "no", true, 3*time.Second, shExec(bScript, aOut, bOut))
	b.After = []string{"a"}
	svcs := map[string]*unit.Service{"a": a, "b": b}
	waves := mustPlan(t, svcs)
	if len(waves) != 2 || strings.Join(waves[0], ",") != "a" || strings.Join(waves[1], ",") != "b" {
		t.Fatalf("%#v", waves)
	}
	sup := mustSup(t, svcs)
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, waves); err != nil {
		t.Fatal(err)
	}
	bBody, err := os.ReadFile(bOut)
	row := rowOf(t, sup, "b")
	if err != nil || string(bBody) != "ok\n" || row.State != "exited" || !row.Ready {
		t.Fatalf("%q %+v %v", bBody, row, err)
	}
}

func TestWantsMissingBoots(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", true, 30*time.Second, []string{"/bin/sleep", "30"})
	agent.Wants = []string{"gone"}
	svcs := map[string]*unit.Service{"agent": agent}
	waves := mustPlan(t, svcs)
	if len(waves) != 1 || len(waves[0]) != 1 || waves[0][0] != "agent" {
		t.Fatalf("%#v", waves)
	}
	sup := mustSup(t, svcs)
	ctx, cancel := ctxFor(t, 5*time.Second)
	defer cancel()
	if err := sup.Boot(ctx, waves); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, sup, "agent")
	if row.State != "running" || !row.Ready || row.Pid <= 0 {
		t.Fatalf("%+v", row)
	}
}

func TestSocketFailClosed(t *testing.T) {
	out := marker(t)
	script := writeScript(t, "printf 'ran\\n' > \"$1\"\n/bin/sleep 30\n")
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	job := newSvc("job", "oneshot", "exit", "no", false, 30*time.Second, shExec(script, out))
	sup := mustSup(t, map[string]*unit.Service{"agent": agent, "job": job})
	path := listenServe(t, sup)
	stoppedAgent := stoppedRow("agent", "")
	stoppedJob := stoppedRow("job", "")

	for _, op := range []string{"start", "stop", "restart", "oneshot"} {
		wantExact(t, path, `{"op":"`+op+`","name":"zz-missing"}`, exactErr("not_found"))
		wantExact(t, path, `{"op":"`+op+`"}`, exactErr("not_found"))
	}
	wantExact(t, path, `{"op":"oneshot","name":"zz-missing","arg":"a..b"}`, exactErr("not_found"))
	_, raw := rpc(t, path, `{"op":"oneshot","name":"zz-missing","arg":"marker-arg"}`)
	if string(raw) != exactErr("not_found") || strings.Contains(string(raw), "marker-arg") {
		t.Fatalf("%s", raw)
	}
	wantExact(t, path, `{"op":"oneshot","name":"agent","arg":"a..b"}`, exactErrRow("not_oneshot", stoppedAgent))
	wantExact(t, path, `{"op":"status","name":"agent","extra":1}`, exactErr("unknown_field"))
	wantExact(t, path, `{"op":"status","name":"agent","name":"agent"}`, exactErr("duplicate_field"))
	wantExact(t, path, `{"op":"status"}{}`, exactErr("failed"))
	wantExact(t, path, `{"op":1,"name":"agent"}`, exactErr("failed"))
	wantExact(t, path, `{"op":"oneshot","name":"job","arg":1}`, exactErr("failed"))
	_, raw = rpc(t, path, `{"op":"oneshot","name":"job","arg":"line\nbreak-arg"}`)
	if string(raw) != exactErrRow("arg_rejected", stoppedJob) || strings.Contains(string(raw), "break-arg") {
		t.Fatalf("%s", raw)
	}
	_, raw = rpc(t, path, `{"op":"oneshot","name":"job","arg":"has space"}`)
	if string(raw) != exactErrRow("arg_rejected", stoppedJob) || strings.Contains(string(raw), "has space") {
		t.Fatalf("%s", raw)
	}
	_, raw = rpc(t, path, `{"op":"start","name":"job","arg":"marker-arg"}`)
	if string(raw) != exactErrRow("arg_required", stoppedJob) || strings.Contains(string(raw), "marker-arg") {
		t.Fatalf("%s", raw)
	}
	absent(t, out)
	if row := rowOf(t, sup, "agent"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}
	if row := rowOf(t, sup, "job"); row.State != "stopped" || row.Pid != 0 {
		t.Fatalf("%+v", row)
	}

	resp, raw := rpc(t, path, `{"op":"start","name":"agent"}`)
	if !resp.OK || resp.Error != "" || len(resp.Rows) != 1 || resp.Rows[0].State != "running" || resp.Rows[0].Pid <= 0 {
		t.Fatalf("%s", raw)
	}
	resp, raw = rpc(t, path, `{"op":"start","name":"agent"}`)
	if resp.Error != "busy" || len(resp.Rows) != 1 || resp.Rows[0].State != "running" || resp.Rows[0].Pid <= 0 {
		t.Fatalf("%s", raw)
	}
	if _, raw = rpc(t, path, `{"op":"stop","name":"agent"}`); !strings.Contains(string(raw), `"state":"stopped"`) {
		t.Fatalf("%s", raw)
	}
	wantExact(t, path, `{"op":"stop","name":"agent"}`, `{"ok":true,"error":"","rows":[`+stoppedRow("agent", "")+`]}`)
	resp, raw = rpc(t, path, `{"op":"restart","name":"agent"}`)
	if !resp.OK || resp.Error != "" || len(resp.Rows) != 1 || resp.Rows[0].State != "running" || !resp.Rows[0].Ready || resp.Rows[0].Sandbox != "none" || resp.Rows[0].Pid <= 0 {
		t.Fatalf("%s", raw)
	}
}

func TestSocketReadDeadline(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.ReadDeadline = 80 * time.Millisecond
	path := listenServe(t, sup)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf, err := frame.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != exactErr("failed") {
		t.Fatalf("%s", buf)
	}
}

func TestSocketZeroFrame(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
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
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	buf, err := frame.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != exactErr("frame_size") {
		t.Fatalf("%s", buf)
	}
}

func TestSocketEmptyAllowOversize(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.Allow = map[uint32]struct{}{}
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
	if string(buf) != exactErr("uid_denied") {
		t.Fatalf("%s", buf)
	}
}

func TestSocketFullDeniesEmptyAllow(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.MaxHandlers = 1
	sup.Allow = map[uint32]struct{}{}
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
	if string(buf) != exactErr("uid_denied") {
		t.Fatalf("%s", buf)
	}
}

func TestSocketAllowEuid(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.Allow = map[uint32]struct{}{uint32(os.Geteuid()): {}}
	path := listenServe(t, sup)
	resp, raw := rpc(t, path, `{"op":"status","name":"agent"}`)
	if !resp.OK || resp.Error != "" || len(resp.Rows) != 1 {
		t.Fatalf("%s", raw)
	}
}

func TestSocketAllowOnlyRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip()
	}
	agent := newSvc("agent", "simple", "exec", "no", false, 30*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	sup.Allow = map[uint32]struct{}{0: {}}
	path := listenServe(t, sup)
	_, raw := rpc(t, path, `{"op":"status","name":"agent"}`)
	if string(raw) != exactErr("uid_denied") {
		t.Fatalf("%s", raw)
	}
}
