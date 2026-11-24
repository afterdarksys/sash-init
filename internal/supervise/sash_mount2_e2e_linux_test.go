//go:build linux

package supervise

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// superOf is the superblock options of the mount at dir (after " - TYPE
// SOURCE "), or "".
func superOf(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	opts := ""
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) > 5 && f[4] == dir {
			if i := strings.Index(line, " - "); i >= 0 {
				g := strings.Fields(line[i+3:])
				if len(g) == 3 {
					opts = g[2]
				}
			}
		}
	}
	return opts
}

func mountServer(t *testing.T, name string) (*sash.Server, *Supervisor, string, string, string, string, *sashEnv) {
	t.Helper()
	e := newSashEnv(t)
	g, work, src, m1, m2 := filesGrant(e, name)
	g.MountSources = append(g.MountSources, "sysfs")
	e.add(name, refusalScript(name, "spawn main /usr/bin/sleep 300"), g, e.fleet)
	var log syncBuf
	sup, _ := e.load(&log)
	s := sup.rt[name]
	return &sash.Server{G: g, Table: s.sashTable(), Host: &sashHost{sup: sup, s: s}}, sup, work, src, m1, m2, e
}

// A remount changes only the service's own mount: the bind source's
// filesystem stays writable, and the host's /sys stays rw after the
// service's sysfs mount is remounted read-only. Superblock options are
// refused on remount.
func TestSashRemountLeavesSuperblock(t *testing.T) {
	srv, _, _, src, m1, m2, _ := mountServer(t, "rsb")
	adminfs := filepath.Join(filepath.Dir(src), "adminfs")
	os.MkdirAll(adminfs, 0o755)
	if err := unix.Mount("tmpfs", adminfs, "tmpfs", 0, "size=10m"); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(adminfs, unix.MNT_DETACH)
	os.Mkdir(adminfs+"/data", 0o755)
	srv.G.MountSources = append(srv.G.MountSources, adminfs+"/data")
	mount := func(a ...string) sash.Response { return srv.Handle(sash.Request{Key: "fs.mount", Argv: a}) }
	if r := mount("mount", adminfs+"/data", m1, "opts", "bind,nosuid,nodev"); r.Error != "" {
		t.Fatalf("bind: %+v", r)
	}
	if r := mount("mount", adminfs+"/data", m1, "opts", "bind,remount,ro,nosuid,nodev"); r.Error != "" {
		t.Fatalf("remount ro: %+v", r)
	}
	if r := mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "remount,ro,size=4k,nosuid,nodev"); r.Error != "mount_opt_refused" {
		t.Fatalf("remount with a size: %+v", r)
	}
	if err := os.WriteFile(adminfs+"/x", []byte("x"), 0o644); err != nil {
		t.Fatalf("the admin's filesystem was made read-only: %v (%s)", err, superOf(t, adminfs))
	}
	if err := os.WriteFile(m1+"/y", []byte("y"), 0o644); err == nil {
		t.Fatal("the service's bind is still writable")
	}
	if r := mount("umount", m1); r.Error != "" {
		t.Fatalf("umount: %+v", r)
	}
	if !strings.HasPrefix(superOf(t, "/sys"), "rw") {
		t.Skipf("host /sys is %q here", superOf(t, "/sys"))
	}
	if r := mount("mount", "sysfs", m2, "type", "sysfs", "opts", "nosuid,nodev"); r.Error != "" {
		t.Fatalf("sysfs: %+v", r)
	}
	if r := mount("mount", "sysfs", m2, "type", "sysfs", "opts", "remount,ro,nosuid,nodev"); r.Error != "" {
		t.Fatalf("sysfs remount: %+v", r)
	}
	if o := superOf(t, "/sys"); !strings.HasPrefix(o, "rw") {
		t.Fatalf("host /sys superblock became %q", o)
	}
	if r := mount("umount", m2); r.Error != "" {
		t.Fatalf("umount sysfs: %+v", r)
	}
}

// An rbind's nested mounts get nosuid, nodev and ro too.
func TestSashRbindNestedFlags(t *testing.T) {
	srv, _, _, src, m1, _, _ := mountServer(t, "rnb")
	os.Mkdir(src+"/inner", 0o755)
	if err := unix.Mount("tmpfs", src+"/inner", "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(src+"/inner", unix.MNT_DETACH)
	if r := srv.Handle(sash.Request{Key: "fs.mount", Argv: []string{"mount", src, m1, "opts", "rbind,ro,nosuid,nodev"}}); r.Error != "" {
		t.Fatalf("rbind: %+v", r)
	}
	for _, d := range []string{m1, m1 + "/inner"} {
		o := mountOpts(t, d)
		if !strings.HasPrefix(o, "ro") || !strings.Contains(o, "nosuid") || !strings.Contains(o, "nodev") {
			t.Errorf("%s: %q", d, o)
		}
	}
	if r := srv.Handle(sash.Request{Key: "fs.mount", Argv: []string{"umount", m1}}); r.Error != "" {
		t.Fatalf("umount: %+v", r)
	}
	if mountOpts(t, m1+"/inner") != "" || mountOpts(t, m1) != "" {
		t.Fatal("rbind left mounts")
	}
}

// umount acts only on the mount sahinit made: one replaced underneath is
// not_mounted and stays. Another service's mount point is exists. A
// mount left by a sahinit that died is removed at the next start.
func TestSashMountIdentity(t *testing.T) {
	srv, sup, _, _, m1, m2, e := mountServer(t, "mid")
	mount := func(a ...string) sash.Response { return srv.Handle(sash.Request{Key: "fs.mount", Argv: a}) }
	if r := mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "nosuid,nodev"); r.Error != "" {
		t.Fatal(r)
	}
	// The admin unmounts it and mounts their own there.
	unix.Unmount(m1, 0)
	if err := unix.Mount("tmpfs", m1, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(m1, unix.MNT_DETACH)
	if r := mount("umount", m1); r.Error != "not_mounted" {
		t.Fatalf("umount of a replaced mount: %+v", r)
	}
	if r := mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "remount,ro,nosuid,nodev"); r.Error != "not_mounted" {
		t.Fatalf("remount of a replaced mount: %+v", r)
	}
	if mountOpts(t, m1) == "" || strings.HasPrefix(mountOpts(t, m1), "ro") {
		t.Fatalf("the admin's mount was touched: %q", mountOpts(t, m1))
	}
	// A mount still in use is busy, and stays; then it unmounts.
	if r := mount("mount", "tmpfs", m2, "type", "tmpfs", "opts", "nosuid,nodev"); r.Error != "" {
		t.Fatal(r)
	}
	held, err := os.Create(m2 + "/held")
	if err != nil {
		t.Fatal(err)
	}
	if r := mount("umount", m2); r.Error != "busy" || mountOpts(t, m2) == "" {
		t.Fatalf("umount in use: %+v %q", r, mountOpts(t, m2))
	}
	held.Close()
	if r := mount("umount", m2); r.Error != "" {
		t.Fatalf("umount: %+v", r)
	}
	// Another service may not take a point this one holds.
	if r := mount("mount", "tmpfs", m2, "type", "tmpfs", "opts", "nosuid,nodev"); r.Error != "" {
		t.Fatal(r)
	}
	uid := uint32(65534)
	unit2 := unit.Service{Name: "other", Execution: unit.Execution{UID: &uid, GID: &uid}}
	other := &sash.Server{G: srv.G, Table: sash.NewTable(), Host: &sashHost{sup: sup, s: &runtime{svc: &unit2}}}
	if r := other.Handle(sash.Request{Key: "fs.mount", Argv: []string{"mount", "tmpfs", m2, "type", "tmpfs", "opts", "nosuid,nodev"}}); r.Error != "exists" {
		t.Fatalf("another service's point: %+v", r)
	}
	// A new supervisor with the same state removes what this one left.
	var log syncBuf
	next, err := New(map[string]*unit.Service{"mid": sup.rt["mid"].svc}, e.self)
	if err != nil {
		t.Fatal(err)
	}
	next.Log, next.Sash = &log, sup.Sash
	next.CleanSashMounts()
	if mountOpts(t, m2) != "" || !strings.Contains(log.String(), "sash_mount_leftover mid "+m2) {
		t.Fatalf("leftover not removed: %q %s", mountOpts(t, m2), log.String())
	}
	if mountOpts(t, m1) == "" {
		t.Fatal("cleanup removed a mount it did not make")
	}
}

func otherServer(sup *Supervisor, g sash.Grant, name string) *sash.Server {
	uid := uint32(65534)
	svc := &unit.Service{Name: name, Execution: unit.Execution{UID: &uid, GID: &uid}}
	return &sash.Server{G: g, Table: sash.NewTable(), Host: &sashHost{sup: sup, s: &runtime{svc: svc}}}
}

// Two services mounting one point at once: exactly one wins, the other is
// exists; nothing is stacked.
func TestSashConcurrentMountOnePoint(t *testing.T) {
	srv, sup, _, _, m1, _, _ := mountServer(t, "cca")
	a, b := srv, otherServer(sup, srv.G, "ccb")
	req := sash.Request{Key: "fs.mount", Argv: []string{"mount", "tmpfs", m1, "type", "tmpfs", "opts", "nosuid,nodev"}}
	for round := 0; round < 40; round++ {
		var ra, rb sash.Response
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); ra = a.Handle(req) }()
		go func() { defer wg.Done(); rb = b.Handle(req) }()
		wg.Wait()
		ok := 0
		for _, r := range []sash.Response{ra, rb} {
			if r.Error == "" {
				ok++
			} else if r.Error != "exists" {
				t.Fatalf("round %d: %+v", round, r)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d mounts succeeded", round, ok)
		}
		for _, s := range []*sash.Server{a, b} {
			if s.Table.Mounted(m1) {
				if r := s.Handle(sash.Request{Key: "fs.mount", Argv: []string{"umount", m1}}); r.Error != "" {
					t.Fatalf("umount: %+v", r)
				}
			}
		}
		if mountOpts(t, m1) != "" {
			t.Fatalf("round %d: stacked mounts left", round)
		}
	}
}

// Without mount IDs no mount is made; and a mount whose ID cannot be read
// afterwards is detached, not left untracked.
func TestSashMountWithoutIDs(t *testing.T) {
	srv, sup, _, _, m1, _, _ := mountServer(t, "nid")
	real := statMountID
	defer func() { statMountID = real }()
	req := sash.Request{Key: "fs.mount", Argv: []string{"mount", "tmpfs", m1, "type", "tmpfs", "opts", "nosuid,nodev"}}
	statMountID = func(int) (uint64, error) { return 0, errors.New("no STATX_MNT_ID") }
	if r := srv.Handle(req); r.Error != "unsupported" || mountOpts(t, m1) != "" {
		t.Fatalf("no IDs: %+v %q", r, mountOpts(t, m1))
	}
	calls := 0
	statMountID = func(fd int) (uint64, error) {
		calls++
		if calls > 1 {
			return 0, errors.New("gone")
		}
		return real(fd)
	}
	if r := srv.Handle(req); r.Error != "failed" || mountOpts(t, m1) != "" {
		t.Fatalf("ID lost after mounting: %+v %q", r, mountOpts(t, m1))
	}
	if _, held := sup.mounts().get(m1); held || srv.Table.Mounted(m1) {
		t.Fatal("record left")
	}
}

// A mount no longer the one sahinit made is forgotten when found: logged,
// and the point is free again.
func TestSashMountForgotten(t *testing.T) {
	srv, sup, _, _, m1, _, _ := mountServer(t, "fgt")
	var log syncBuf
	sup.Log = &log
	mount := func(s *sash.Server, a ...string) sash.Response { return s.Handle(sash.Request{Key: "fs.mount", Argv: a}) }
	if r := mount(srv, "mount", "tmpfs", m1, "type", "tmpfs", "opts", "nosuid,nodev"); r.Error != "" {
		t.Fatal(r)
	}
	unix.Unmount(m1, 0)
	if err := unix.Mount("tmpfs", m1, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(m1, unix.MNT_DETACH)
	if r := mount(srv, "umount", m1); r.Error != "not_mounted" {
		t.Fatalf("umount: %+v", r)
	}
	if !strings.Contains(log.String(), "sash_mount_forgotten fgt "+m1) {
		t.Fatalf("not audited: %s", log.String())
	}
	if _, held := sup.mounts().get(m1); held || srv.Table.Mounted(m1) {
		t.Fatal("stale record kept")
	}
	other := otherServer(sup, srv.G, "fgu")
	if r := mount(other, "mount", "tmpfs", m1, "type", "tmpfs", "opts", "nosuid,nodev"); r.Error != "" {
		t.Fatalf("point still held: %+v", r)
	}
	if r := mount(other, "umount", m1); r.Error != "" {
		t.Fatalf("umount: %+v", r)
	}
}
