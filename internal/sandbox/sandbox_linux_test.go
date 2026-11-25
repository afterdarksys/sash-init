// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if os.Getenv("SAHINIT_SANDBOX_PROBE") == "1" {
		runProbe()
		unix.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "apply" {
		if os.Getenv("SAHT_STRAY_FD") == "1" {
			// An fd opened without close-on-exec, like a stray runtime fd.
			if _, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0); err != nil {
				unix.Exit(3)
			}
		}
		if claim := os.Getenv("SAHT_FAKE_CLAIM"); claim != "" {
			unix.Exit(fakeHelper(claim))
		}
		unix.Exit(ApplyCLI(os.Args[1:]))
	}
	if mode := os.Getenv("SAHT_CAPS_PROBE"); mode != "" {
		unix.Exit(capsProbe(mode))
	}
	if path.Base(os.Args[0]) == "sinetd" && len(os.Args) > 1 && os.Args[1] == "run" {
		unix.Exit(sinetdStandIn())
	}
	os.Exit(m.Run())
}

func runProbe() {
	runtime.LockOSThread()
	rw := os.Getenv("SAHINIT_PROBE_RW")
	allow := os.Getenv("SAHINIT_PROBE_ALLOW")
	deny := os.Getenv("SAHINIT_PROBE_DENY")
	sym := os.Getenv("SAHINIT_PROBE_SYM")
	sb := &unit.Sandbox{NoNewPrivs: true, ReadWrite: []string{rw}}
	h, _, err := restrict(sb)
	if err != nil {
		unix.Exit(1)
	}
	if err := closeHeld(h); err != nil {
		unix.Exit(1)
	}
	allowTag := openTag(allow)
	denyTag := openTag(deny)
	eff := "err"
	var data [2]unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	if err := unix.Capget(&hdr, &data[0]); err == nil {
		if data[0].Effective == 0 && data[1].Effective == 0 {
			eff = "0"
		} else {
			eff = "nz"
		}
	}
	r1, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(unix.PR_GET_NO_NEW_PRIVS), 0, 0, 0, 0, 0)
	nnp := "0"
	if errno == 0 && r1 == 1 {
		nnp = "1"
	}
	symTag := openTag(sym)
	var buf [80]byte
	n := 0
	n = put(buf[:], n, "allow=")
	n = put(buf[:], n, allowTag)
	n = put(buf[:], n, " deny=")
	n = put(buf[:], n, denyTag)
	n = put(buf[:], n, " eff=")
	n = put(buf[:], n, eff)
	n = put(buf[:], n, " nnp=")
	n = put(buf[:], n, nnp)
	n = put(buf[:], n, " sym=")
	n = put(buf[:], n, symTag)
	n = put(buf[:], n, "\n")
	writeAll(1, buf[:n])
	unix.Exit(0)
}

func openTag(p string) string {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		if e, ok := err.(syscall.Errno); ok && e == syscall.EACCES {
			return "eacces"
		}
		return "err"
	}
	if err := unix.Close(fd); err != nil {
		unix.Exit(1)
	}
	return "ok"
}

func put(buf []byte, n int, s string) int {
	if n+len(s) > len(buf) {
		unix.Exit(1)
	}
	return n + copy(buf[n:], s)
}

func writeAll(fd int, buf []byte) {
	for len(buf) > 0 {
		n, err := unix.Write(fd, buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil || n == 0 {
			unix.Exit(1)
		}
	}
}

func linkedAncestor(p string) bool {
	for {
		st, err := os.Lstat(p)
		if err != nil {
			return true
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return true
		}
		if p == "/" {
			return false
		}
		next := path.Dir(p)
		if next == p {
			return false
		}
		p = next
	}
}

func TestLandlockProbe(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if linkedAncestor(dir) {
		t.Skip("symlink ancestor")
	}
	allowPath := dir + "/allow"
	if err := os.WriteFile(allowPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	symPath := dir + "/sym"
	if err := os.Symlink("/etc/passwd", symPath); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"SAHINIT_SANDBOX_PROBE=1",
		"SAHINIT_PROBE_RW=" + dir,
		"SAHINIT_PROBE_ALLOW=" + allowPath,
		"SAHINIT_PROBE_DENY=/etc/passwd",
		"SAHINIT_PROBE_SYM=" + symPath,
	}
	out, err := cmd.CombinedOutput()
	const want = "allow=ok deny=eacces eff=0 nnp=1 sym=eacces\n"
	if err != nil || string(out) != want {
		t.Fatalf("probe: %v %q", err, out)
	}
}

func TestSysadminCapRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	dir, err := os.MkdirTemp("/tmp", "sahp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if linkedAncestor(dir) {
		t.Skip("symlink ancestor")
	}
	script := dir + "/run"
	marker := dir + "/ran"
	body := "#!/bin/sh\nprintf 'ran\\n' > \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sb := &unit.Sandbox{NoNewPrivs: true, ReadWrite: []string{dir}, Caps: []string{"sys_admin"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, os.Args[0], []string{script, marker}, sb, false, 3*time.Second)
	if cmd != nil || nf != nil || claim != "" {
		t.Fatalf("cmd=%v nf=%v claim=%q", cmd, nf, claim)
	}
	tok := fail.Token(err)
	switch tok {
	case "sandbox_cap", "landlock_unavailable", "openat2_unavailable", "sandbox_path":
	default:
		t.Fatalf("token %s", tok)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestApplyNoSpecFD(t *testing.T) {
	cmd := exec.Command(os.Args[0], "apply", "--", "/bin/true")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || len(out) != 0 {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

// A setup success line must not release the caller before exec closes fd 4.
func TestChildStatusWaitsForExec(t *testing.T) {
	for _, execFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("execFails=%v", execFails), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			result := make(chan error, 1)
			go func() {
				claim, err := readChildStatus(context.Background(), r, time.Second, true)
				if err == nil && claim != SandboxClaim(3) {
					err = fmt.Errorf("claim %q", claim)
				}
				result <- err
			}()
			if _, err := w.Write(okLine(3, false)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				t.Fatalf("returned before exec: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			if execFails {
				if _, err := w.Write(errLines["failed"]); err != nil {
					t.Fatal(err)
				}
			}
			w.Close()
			if err := <-result; (err != nil) != execFails {
				t.Fatalf("execFails=%v, err=%v", execFails, err)
			}
		})
	}
}

func TestLaunchSandboxedExecFailure(t *testing.T) {
	self, ident := helperSelf(t)
	dir, err := os.MkdirTemp("/tmp", "sahinit-interp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := dir + "/missing-interpreter"
	if err := os.WriteFile(target, []byte("#!/sahinit-nonexistent-interpreter\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// First establish that sandbox setup works, so setup failure cannot make
	// the broken-interpreter assertion pass accidentally.
	good, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}
	cmd, claim, _, err := Launch(context.Background(), self, []string{good}, sb, false, time.Second, Options{Execution: ident})
	if err != nil {
		t.Fatalf("sandbox setup: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if claim != SandboxClaim(min(landlockABI(), MaxLandlockABI)) {
		t.Fatalf("claim %q", claim)
	}
	cmd, claim, _, err = Launch(context.Background(), self, []string{target}, sb, false, time.Second, Options{Execution: ident})
	if cmd != nil {
		defer reap(cmd)
	}
	if err == nil || claim != "" {
		t.Fatalf("failed exec accepted: cmd=%v claim=%q err=%v", cmd, claim, err)
	}
}

// The helper itself refuses to apply a sandbox while it runs as root, even
// when the caller skipped the check in Launch.
func TestHelperRefusesRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target, err := unit.ResolveExec("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	execF, err := openExec(target)
	if err != nil {
		t.Fatal(err)
	}
	defer execF.Close()
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}
	cmd, claim, _, err := launchHelper(context.Background(), self, []string{"/bin/true"}, execF, sb, false, time.Second, Options{}, false)
	if cmd != nil || claim != "" || fail.Token(err) != "sandbox_root" {
		t.Fatalf("cmd=%v claim=%q err=%v", cmd, claim, err)
	}
}
