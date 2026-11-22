//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path"
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
		unix.Exit(ApplyCLI(os.Args[1:]))
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
	h, err := restrict(sb)
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
