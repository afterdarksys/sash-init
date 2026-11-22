//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestExecutionIdentityLinux(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to test credential changes")
	}
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Go's test binary may be in a non-traversable build directory for the new UID.
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp("/tmp", "sahinit-identity-*")
	if err != nil {
		t.Fatal(err)
	}
	self = f.Name()
	defer os.Remove(self)
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chmod(self, 0755); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(65534), uint32(65534)
	for _, sandboxed := range []bool{false, true} {
		name := "direct"
		if sandboxed {
			name = "sandbox"
		}
		t.Run(name, func(t *testing.T) {
			for _, groups := range [][]uint32{nil, {12345}} {
				var out, stderr bytes.Buffer
				var sb *unit.Sandbox
				if sandboxed {
					sb = &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}
				}
				cmd, claim, notify, err := Launch(context.Background(), self, []string{shell, "-c", `id -u; id -g; id -G; pwd; printf '%s' "$APP"; printf err >&2; printf '\n' >&3`}, sb, true, 5*time.Second, Options{Execution: unit.Execution{UID: &uid, GID: &gid, Groups: groups, Directory: "/tmp", Environment: []string{"APP=hello"}}, Stdout: &out, Stderr: &stderr})
				if err != nil {
					if sandboxed && (fail.Token(err) == "landlock_unavailable" || fail.Token(err) == "openat2_unavailable") {
						t.Skipf("kernel lacks sandbox: %v", err)
					}
					t.Fatal(err)
				}
				defer notify.Close()
				notify.SetReadDeadline(time.Now().Add(5 * time.Second))
				var b [1]byte
				if _, err := notify.Read(b[:]); err != nil {
					t.Fatal(err)
				}
				if err := cmd.Wait(); err != nil {
					t.Fatal(err, stderr.String())
				}
				lines := strings.Split(out.String(), "\n")
				if len(lines) != 5 || lines[0] != "65534" || lines[1] != "65534" || lines[3] != "/tmp" || lines[4] != "hello" || stderr.String() != "err" {
					t.Fatalf("output %q stderr %q", out.String(), stderr.String())
				}
				expected := "65534"
				if len(groups) > 0 {
					expected += " 12345"
				}
				if lines[2] != expected {
					t.Fatalf("groups %q, want %q", lines[2], expected)
				}
				if sandboxed && claim != claimFull {
					t.Fatal(claim)
				}
			}
		})
	}
}

func TestExecutionInvalidFailsBeforeLaunch(t *testing.T) {
	uid := uint32(1)
	if _, _, _, err := Launch(context.Background(), "/unused", []string{"/usr/bin/true"}, nil, false, time.Second, Options{Execution: unit.Execution{UID: &uid}}); fail.Token(err) != "execution_invalid" {
		t.Fatal(err)
	}
}
