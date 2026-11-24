// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStrictBootHelper(t *testing.T) {
	if os.Getenv("SAHINIT_STRICT_HELPER") != "1" {
		return
	}
	args := []string{"supervise", "--dir", os.Getenv("SAHINIT_TEST_UNITS"), "--socket", os.Getenv("SAHINIT_TEST_SOCKET"), "--no-cgroups", "--boot-strict"}
	if d := os.Getenv("SAHINIT_TEST_LOGDIR"); d != "" {
		args = append(args, "--log-dir", d)
	}
	os.Exit(run(args, os.Stdout, os.Stderr))
}

// Under --boot-strict every boot unit is essential unless its unit says
// "essential": false: an unmarked unit that fails, or a long-running one
// that stops on its own, ends the supervisor (PID 1's recovery); an
// opted-out failure leaves the rest running.
func TestStrictBootEssentialByDefault(t *testing.T) {
	cases := []struct {
		name string
		bad  map[string]any
		fail bool
	}{
		{"failed_unmarked", map[string]any{"name": "bad", "exec": []string{"/bin/sh", "-c", "exit 3"}, "type": "oneshot", "ready": "exit", "boot": true}, true},
		{"stopped_unmarked", map[string]any{"name": "bad", "exec": []string{"/bin/sh", "-c", "/bin/sleep 0.3"}, "type": "simple", "ready": "exec", "boot": true}, true},
		{"failed_optional", map[string]any{"name": "bad", "exec": []string{"/bin/sh", "-c", "exit 3"}, "type": "oneshot", "ready": "exit", "boot": true, "essential": false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			units := t.TempDir()
			sock := privTmp(t) + "/s"
			defer os.Remove(sock)
			putUnit(t, units, tc.bad)
			putUnit(t, units, map[string]any{"name": "ok", "exec": []string{"/bin/sleep", "30"}, "type": "simple", "ready": "exec", "boot": true})
			cmd := exec.Command(os.Args[0], "-test.run=^TestStrictBootHelper$")
			cmd.Env = append(os.Environ(), "SAHINIT_STRICT_HELPER=1", "SAHINIT_TEST_UNITS="+units, "SAHINIT_TEST_SOCKET="+sock)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer cmd.Process.Kill()
			select {
			case err := <-done:
				if !tc.fail {
					t.Fatalf("optional failure ended the boot: %v %q", err, stderr.String())
				}
				if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.Contains(stderr.String(), "boot_service_failed bad") {
					t.Fatalf("exit %v stderr %q", err, stderr.String())
				}
				return
			case <-time.After(3 * time.Second):
			}
			if tc.fail {
				t.Fatalf("essential failure did not end the boot: %q", stderr.String())
			}
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("unclean shutdown: %v %q", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("shutdown blocked")
			}
		})
	}
}

// An unusable --log-dir is reported (journal_unavailable) and the boot goes
// on without a journal instead of failing.
func TestJournalUnavailableDoesNotFailBoot(t *testing.T) {
	units := t.TempDir()
	sock := privTmp(t) + "/s"
	defer os.Remove(sock)
	notDir := t.TempDir() + "/file"
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	putUnit(t, units, map[string]any{"name": "ok", "exec": []string{"/bin/sleep", "30"}, "type": "simple", "ready": "exec", "boot": true})
	cmd := exec.Command(os.Args[0], "-test.run=^TestStrictBootHelper$")
	cmd.Env = append(os.Environ(), "SAHINIT_STRICT_HELPER=1", "SAHINIT_TEST_UNITS="+units, "SAHINIT_TEST_SOCKET="+sock, "SAHINIT_TEST_LOGDIR="+notDir+"/journal")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()
	select {
	case err := <-done:
		t.Fatalf("boot ended: %v %q", err, stderr.String())
	case <-time.After(1500 * time.Millisecond):
	}
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil || !strings.Contains(stderr.String(), "journal_unavailable") {
			t.Fatalf("exit %v stderr %q", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown blocked")
	}
}
