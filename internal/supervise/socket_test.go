package supervise

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func idleSup(t *testing.T) *Supervisor {
	t.Helper()
	return mustSup(t, map[string]*unit.Service{"agent": newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})})
}

func socketStat(t *testing.T, path string) (os.FileMode, uint32) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid
}

// The socket mode follows the allowlist instead of always being 0600, which
// made every other allowed uid unable to connect.
func TestSocketModeFollowsAllowlist(t *testing.T) {
	euid := uint32(os.Geteuid())
	other := uint32(65534)
	if euid == other {
		other = 65533
	}
	for _, allow := range []map[uint32]struct{}{nil, {}, {euid: {}}} {
		sup := idleSup(t)
		sup.Allow = allow
		path := tmpPath("sah")
		t.Cleanup(func() { removeFile(t, path) })
		if err := sup.Listen(path); err != nil {
			t.Fatal(err)
		}
		if mode, _ := socketStat(t, path); mode != 0o600 {
			t.Fatalf("allow %v: mode %o", allow, mode)
		}
		if err := sup.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sup := idleSup(t)
	sup.Allow = map[uint32]struct{}{euid: {}, other: {}}
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	if err := sup.Listen(path); fail.Token(err) != "socket_group" {
		t.Fatal(err)
	}
	absent(t, path)
	gid := uint32(os.Getegid())
	sup.SocketGID = &gid
	if err := sup.Listen(path); err != nil {
		t.Fatal(err)
	}
	if mode, g := socketStat(t, path); mode != 0o660 || g != gid {
		t.Fatalf("mode %o gid %d", mode, g)
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
}

func staleAt(t *testing.T, path string) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
}

// A socket left by a crash no longer blocks startup.
func TestSocketStaleRemoved(t *testing.T) {
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	staleAt(t, path)
	sup := idleSup(t)
	if err := sup.Listen(path); err != nil {
		t.Fatal(err)
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
}

// A live socket is never taken over.
func TestSocketLiveKept(t *testing.T) {
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sup := idleSup(t)
	if err := sup.Listen(path); fail.Token(err) != "socket_exists" {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
}

// A stale socket owned by another uid is left in place.
func TestSocketStaleOtherOwnerKept(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown")
	}
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	staleAt(t, path)
	if err := os.Lchown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	sup := idleSup(t)
	if err := sup.Listen(path); fail.Token(err) != "socket_exists" {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
}
