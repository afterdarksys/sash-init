package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/afterdarksys/sahinit/internal/frame"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func putUnit(t *testing.T, dir string, fields map[string]any) {
	t.Helper()
	name, ok := fields["name"].(string)
	if !ok || name == "" {
		t.Fatal("name")
	}
	buf, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/"+name+".json", buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func simpleUnit(name string, needs []string) map[string]any {
	fields := map[string]any{
		"name":  name,
		"exec":  []string{"/bin/sh"},
		"type":  "simple",
		"ready": "exec",
	}
	if needs != nil {
		fields["needs"] = needs
	}
	return fields
}

func TestRunUsage(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		nil,
		{"nope"},
		{"plan"},
		{"supervise"},
		{"supervise", "--dir", dir},
		{"plan", "--dir", dir, "extra"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || stderr.String() != usageText {
			t.Fatalf("%q code %d out %q err %q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestRunApplySilent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	got := stdout.String() + stderr.String()
	if got != "" || strings.Contains(got, "apply") {
		t.Fatalf("%q", got)
	}
}

func TestPlanWaves(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("a", nil))
	putUnit(t, dir, simpleUnit("b", []string{"a"}))
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--dir", dir}, &stdout, &stderr)
	if code != 0 || stdout.String() != "a\nb\n" || stderr.Len() != 0 {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
}

func TestPlanSameWave(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("b", nil))
	putUnit(t, dir, simpleUnit("a", nil))
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--dir", dir}, &stdout, &stderr)
	if code != 0 || stdout.String() != "a b\n" || stderr.Len() != 0 {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
}

func TestPlanEmptyBoot(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, map[string]any{
		"name":  "job",
		"exec":  []string{"/bin/sh"},
		"type":  "oneshot",
		"ready": "exit",
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--dir", dir}, &stdout, &stderr)
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
}

func TestPlanEmptyDir(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--dir", dir}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || stderr.String() != "empty\n" {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
}

func TestPlanCycle(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("a", []string{"b"}))
	putUnit(t, dir, simpleUnit("b", []string{"a"}))
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--dir", dir}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || stderr.String() != "cycle\n" {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
}

func TestSuperviseNegativeUID(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sahc-%d-neg", os.Getpid())
	t.Cleanup(func() {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s: %v", sock, err)
		}
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"supervise", "--dir", dir, "--socket", sock, "--uid", "-1"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || stderr.String() != usageText {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "empty") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket %v", err)
	}
}

func TestSuperviseUIDZeroEmpty(t *testing.T) {
	dir := t.TempDir()
	sock := fmt.Sprintf("/tmp/sahc-%d-zero", os.Getpid())
	t.Cleanup(func() {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s: %v", sock, err)
		}
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"supervise", "--dir", dir, "--socket", sock, "--uid", "0"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || stderr.String() != "empty\n" {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket %v", err)
	}
}

func TestSuperviseCycleNoSocket(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("a", []string{"b"}))
	putUnit(t, dir, simpleUnit("b", []string{"a"}))
	sock := fmt.Sprintf("/tmp/sahc-%d-cycle", os.Getpid())
	t.Cleanup(func() {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s: %v", sock, err)
		}
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"supervise", "--dir", dir, "--socket", sock}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || stderr.String() != "cycle\n" {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket %v", err)
	}
}

func sockPath(t *testing.T, tag string) string {
	t.Helper()
	sock := fmt.Sprintf("/tmp/sahc-%d-%s", os.Getpid(), tag)
	t.Cleanup(func() {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s: %v", sock, err)
		}
	})
	return sock
}

func wantRun(t *testing.T, args []string, code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	got := run(args, &out, &errb)
	if got != code || out.String() != stdout || errb.String() != stderr {
		t.Fatalf("%q code %d out %q err %q", args, got, out.String(), errb.String())
	}
}

func absentSock(t *testing.T, sock string) {
	t.Helper()
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket %v", err)
	}
}

func TestPlanBootNeeds(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, map[string]any{
		"name":  "job",
		"exec":  []string{"/bin/sh"},
		"type":  "oneshot",
		"ready": "exit",
	})
	putUnit(t, dir, simpleUnit("a", []string{"job"}))
	wantRun(t, []string{"plan", "--dir", dir}, 2, "", "boot_needs\n")
}

func TestPlanMissingNeeds(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("a", []string{"gone"}))
	wantRun(t, []string{"plan", "--dir", dir}, 2, "", "missing_needs\n")
}

func TestPlanNotADir(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/unit.json"
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantRun(t, []string{"plan", "--dir", file}, 2, "", "failed\n")
	wantRun(t, []string{"plan", "--dir", dir + "/missing"}, 2, "", "failed\n")
}

func TestSuperviseStray(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/note.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock := sockPath(t, "stray")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock}, 2, "", "stray_file\n")
	absentSock(t, sock)
}

func TestPlanWantsMissing(t *testing.T) {
	dir := t.TempDir()
	fields := simpleUnit("agent", nil)
	fields["wants"] = []string{"gone"}
	putUnit(t, dir, fields)
	wantRun(t, []string{"plan", "--dir", dir}, 0, "agent\n", "")
}

func TestPlanBogusFlag(t *testing.T) {
	wantRun(t, []string{"plan", "--bogus"}, 2, "", usageText)
}

func TestSuperviseBogusFlag(t *testing.T) {
	dir := t.TempDir()
	sock := sockPath(t, "bogus")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--bogus"}, 2, "", usageText)
	absentSock(t, sock)
}

func TestSuperviseUIDMax(t *testing.T) {
	dir := t.TempDir()
	sock := sockPath(t, "uidmax")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--uid", "4294967295"}, 2, "", "empty\n")
	absentSock(t, sock)
}

func TestSuperviseUIDOverflow(t *testing.T) {
	dir := t.TempDir()
	sock := sockPath(t, "uidover")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--uid", "4294967296"}, 2, "", usageText)
	absentSock(t, sock)
}

func TestSuperviseRepeatedUID(t *testing.T) {
	dir := t.TempDir()
	sock := sockPath(t, "uidrep")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--uid", "0", "--uid", "1"}, 2, "", "empty\n")
	absentSock(t, sock)
}

func TestSuperviseNotADir(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/unit.json"
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sockFile := sockPath(t, "notdir")
	wantRun(t, []string{"supervise", "--dir", file, "--socket", sockFile}, 2, "", "failed\n")
	absentSock(t, sockFile)
	sockMissing := sockPath(t, "missing")
	wantRun(t, []string{"supervise", "--dir", dir + "/missing", "--socket", sockMissing}, 2, "", "failed\n")
	absentSock(t, sockMissing)
}

func TestBootSignalHelper(t *testing.T) {
	if os.Getenv("SAHINIT_BOOT_SIGNAL_HELPER") != "1" {
		return
	}
	os.Exit(run([]string{"supervise", "--dir", os.Getenv("SAHINIT_TEST_UNITS"), "--socket", os.Getenv("SAHINIT_TEST_SOCKET")}, os.Stdout, os.Stderr))
}

func TestSignalDuringBoot(t *testing.T) {
	dir := t.TempDir()
	// Keep the Unix socket path below the platform length limit.
	sock := fmt.Sprintf("/tmp/sahboot-%d.sock", os.Getpid())
	defer os.Remove(sock)
	marker := dir + "/pid"
	script := dir + "/start.sh"
	if err := os.WriteFile(script, []byte("printf '%s\\n' \"$$\" > \"$1\"\nexec /bin/sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	units := dir + "/units"
	if err := os.Mkdir(units, 0o700); err != nil {
		t.Fatal(err)
	}
	putUnit(t, units, map[string]any{"name": "slow", "exec": []string{"/bin/sh", script, marker}, "type": "simple", "ready": "notify", "timeout": "30s"})
	cmd := exec.Command(os.Args[0], "-test.run=^TestBootSignalHelper$")
	cmd.Env = append(os.Environ(), "SAHINIT_BOOT_SIGNAL_HELPER=1", "SAHINIT_TEST_UNITS="+units, "SAHINIT_TEST_SOCKET="+sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()
	deadline := time.Now().Add(5 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(marker)
		if err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("service never launched")
	}
	defer syscall.Kill(-pid, syscall.SIGKILL)
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if err := frame.Write(c, []byte(`{"op":"status","name":"slow"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := frame.Read(c); err != nil {
		t.Fatalf("control socket unavailable during boot: %v", err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unclean shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown blocked on boot")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket not cleaned up: %v", err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("service remains after shutdown: %v", err)
	}
}

func TestPlanNamesRefusedUnit(t *testing.T) {
	dir := t.TempDir()
	putUnit(t, dir, simpleUnit("agent", nil))
	putUnit(t, dir, simpleUnit("other", nil))
	if err := os.Chmod(dir+"/other.json", 0o666); err != nil {
		t.Fatal(err)
	}
	wantRun(t, []string{"plan", "--dir", dir}, 0, "agent\n", "unit_perm other.json\n")
}

func TestSuperviseGIDFlag(t *testing.T) {
	dir := t.TempDir()
	sock := sockPath(t, "gid")
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--gid", "x"}, 2, "", usageText)
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--gid", "1", "--gid", "2"}, 2, "", usageText)
	wantRun(t, []string{"supervise", "--dir", dir, "--socket", sock, "--gid", "1"}, 2, "", "empty\n")
	absentSock(t, sock)
}
