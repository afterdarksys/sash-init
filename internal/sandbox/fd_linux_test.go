// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// helperSelf returns a copy of the test binary that a non-root helper can
// run, with the identity to run it as. Without root the identity is kept.
func helperSelf(t *testing.T) (string, unit.Execution) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		return self, unit.Execution{}
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp("/tmp", "sahinit-helper-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.Name(), 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(65534), uint32(65534)
	return f.Name(), unit.Execution{UID: &uid, GID: &gid}
}

// The service lists its own open fds. Only stdio and the readiness fd when
// notify is on may be open; a binary keeps no exec fd.
func TestServiceFDs(t *testing.T) {
	self, ident := helperSelf(t)
	// No pipeline: the shell holds a pipe end of its own while ls lists its
	// fds, which ls sees when it runs before the shell forks the reader.
	script := `ls -1 /proc/$$/fd; printf '%s' "${SAHINIT_READY_FD-unset}"`
	cases := []struct {
		name      string
		sandboxed bool
		notify    bool
		want      string
	}{
		{"direct", false, false, "0 1 2 unset"},
		{"direct-notify", false, true, "0 1 2 3 3"},
		{"sandbox", true, false, "0 1 2 unset"},
		{"sandbox-notify", true, true, "0 1 2 3 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sb *unit.Sandbox
			opts := Options{}
			if tc.sandboxed {
				sb = &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}
				opts.Execution = ident
				opts.Execution.Environment = []string{"SAHT_STRAY_FD=1"}
			}
			var out, errb bytes.Buffer
			opts.Stdout, opts.Stderr = &out, &errb
			cmd, _, nf, err := Launch(context.Background(), self, []string{"/bin/sh", "-c", script}, sb, tc.notify, 5*time.Second, opts)
			if err != nil {
				if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
					t.Skipf("kernel lacks sandbox: %v", err)
				}
				t.Fatal(err)
			}
			if nf != nil {
				defer nf.Close()
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err, errb.String())
			}
			if got := strings.ReplaceAll(out.String(), "\n", " "); got != tc.want {
				t.Fatalf("fds %q, want %q (stderr %q)", got, tc.want, errb.String())
			}
		})
	}
}

// A #! script keeps fd 4, which its interpreter reads the script through.
func TestDirectScriptKeepsExecFD(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahinit-script")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := dir + "/run"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nls -1 /proc/$$/fd\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd, _, _, err := Launch(context.Background(), "/bin/sh", []string{script}, nil, false, time.Second, Options{Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+out.String(), "\n4\n") {
		t.Fatalf("fds %q", out.String())
	}
}

// The helper refuses notify when fd 3 is not the readiness pipe, instead of
// trusting whatever happens to be open there.
func TestApplyNotifyNeedsPipe(t *testing.T) {
	const box = `"no_new_privs":true,"read_only_paths":[],"read_write_paths":[],"caps":[]`
	// notify, sandbox and cgroup are each required, never inferred.
	for _, raw := range []string{
		`{` + box + `,"sandbox":true,"cgroup":false}`,
		`{` + box + `,"notify":false,"cgroup":false}`,
		`{` + box + `,"notify":false,"sandbox":true}`,
	} {
		if _, notify, _, err := decodeSpec([]byte(raw)); err == nil {
			t.Fatalf("%s accepted: %v", raw, notify)
		}
	}
	for _, raw := range []string{
		`{` + box + `,"sandbox":true,"cgroup":false,"notify":false}`,
		`{` + box + `,"sandbox":true,"cgroup":false,"notify":true}`,
	} {
		sb, notify, join, err := decodeSpec([]byte(raw))
		if err != nil || sb == nil || join || notify != strings.Contains(raw, "true}") {
			t.Fatalf("%s: %v %v", raw, notify, err)
		}
	}
	sb, _, join, err := decodeSpec([]byte(`{` + box + `,"sandbox":false,"cgroup":true,"notify":false}`))
	if err != nil || sb != nil || !join {
		t.Fatalf("join-only spec: %v %v %v", sb, join, err)
	}
}

// The file checked is the file run: replacing the path after the check does
// not change what the launch executes.
func TestLaunchRunsCheckedFile(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahinit-swap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	target := dir + "/run"
	if err := os.WriteFile(target, []byte("#!/bin/sh\nprintf checked\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	execF, err := openExec(target)
	if err != nil {
		t.Fatal(err)
	}
	defer execF.Close()
	swap := dir + "/swap"
	if err := os.WriteFile(swap, []byte("#!/bin/sh\nprintf swapped\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(swap, target); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd, _, err := direct("", target, []string{target}, execF, true, false, Options{Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil || out.String() != "checked" {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestOpenExecRefuses(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahinit-open")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	link := dir + "/link"
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	if _, err := openExec(link); fail.Token(err) != "exec_not_file" {
		t.Fatal(err)
	}
	wr := dir + "/wr"
	if err := os.WriteFile(wr, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wr, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openExec(wr); fail.Token(err) != "exec_perm" {
		t.Fatal(err)
	}
}

// Concurrent direct launches of a binary, with fds opened and closed
// around them, each run the binary: the child's fd shuffle before execve
// must never land on the exec fd it runs through /proc/self/fd/N.
func TestDirectLaunchConcurrentExecFD(t *testing.T) {
	stop := make(chan struct{})
	churned := make(chan struct{})
	go func() {
		defer close(churned)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if f, err := os.Open("/dev/null"); err == nil {
				f.Close()
			}
		}
	}()
	defer func() { close(stop); <-churned }()
	const workers, launches = 8, 100
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < launches; i++ {
				var out, errb bytes.Buffer
				cmd, _, _, err := Launch(context.Background(), "/bin/sh", []string{"/bin/true"}, nil, false, 5*time.Second, Options{Stdout: &out, Stderr: &errb})
				if err != nil {
					errs <- fmt.Errorf("launch %d: %v", i, err)
					return
				}
				if err := cmd.Wait(); err != nil {
					errs <- fmt.Errorf("wait %d: %v", i, err)
					return
				}
			}
			errs <- nil
		}()
	}
	for w := 0; w < workers; w++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
