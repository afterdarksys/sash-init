// SPDX-License-Identifier: GPL-3.0-or-later

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

// Two supervisors on one path: the second is refused while the first holds
// the lock, even if the socket file looks stale, and may start after Close.
func TestSocketLockedBySupervisor(t *testing.T) {
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	first, second := idleSup(t), idleSup(t)
	if err := first.Listen(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	staleAt(t, path)
	if err := second.Listen(path); fail.Token(err) != "socket_busy" {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket removed under a held lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	staleAt(t, path)
	if err := second.Listen(path); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lock file left: %v", err)
	}
}

// The socket's directory must be trusted like an executable's.
func TestSocketUntrustedDir(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	sup := idleSup(t)
	if err := sup.Listen(dir + "/s"); fail.Token(err) != "socket_perm" {
		t.Fatal(err)
	}
	// A sticky directory, like /tmp, is not a socket directory: anyone
	// could pre-create the socket or its lock there.
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatal(err)
	}
	if err := sup.Listen(dir + "/s"); fail.Token(err) != "socket_perm" {
		t.Fatalf("sticky: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sup.Listen(dir + "/s"); err != nil {
		t.Fatal(err)
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
}

// A link at the socket path is never followed: nothing is created or
// chmodded through it, and its target keeps its mode.
func TestSocketPathLinkNotFollowed(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	target := dir + "/target"
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir+"/s"); err != nil {
		t.Fatal(err)
	}
	sup := idleSup(t)
	if err := sup.Listen(dir + "/s"); fail.Token(err) != "socket_exists" {
		t.Fatal(err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("%v %v", fi, err)
	}
	// Nothing private is left behind in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("%v %v", entries, err)
	}
}

func TestSocketForeignLockFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown")
	}
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path); removeFile(t, path+".lock") })
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path+".lock", 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := idleSup(t).Listen(path); fail.Token(err) != "socket_exists" {
		t.Fatal(err)
	}
}
