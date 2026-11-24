//go:build linux

package supervise

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
)

// mountOpts is the mount at dir in sahinit's mount namespace: its per-mount
// options, or "" when nothing is mounted there.
func mountOpts(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	opts := ""
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) > 5 && f[4] == dir {
			opts = f[5] // the last (top) mount wins
		}
	}
	return opts
}

func filesGrant(e *sashEnv, name string) (sash.Grant, string, string, string, string) {
	work := filepath.Join(e.base, name+"-work")
	src := filepath.Join(e.base, name+"-src")
	m1, m2 := filepath.Join(e.base, name+"-m1"), filepath.Join(e.base, name+"-m2")
	for _, d := range []string{work, src, m1, m2} {
		os.MkdirAll(d, 0o755)
	}
	os.Chown(work, 65534, 65534)
	os.WriteFile(filepath.Join(src, "hello"), []byte("hi\n"), 0o644)
	g := e2eGrant(name, []string{"/usr/bin/sleep"}, []string{})
	g.Entitlements = append(g.Entitlements, "file.write", "fs.mount")
	g.FileWrite = []string{work}
	g.Mounts = []string{m1, m2}
	g.MountSources = []string{"tmpfs", src}
	return g, work, src, m1, m2
}

// A script makes, chmods, chowns, touches, links and removes files beneath
// its file_write root, and mounts a tmpfs and a read-only bind, which are
// unmounted when the service stops.
func TestSashFilesAndMountsEndToEnd(t *testing.T) {
	e := newSashEnv(t)
	g, work, src, m1, m2 := filesGrant(e, "files")
	script := "service {\n  name files\n  user nobody\n  group nogroup\n}\n\nfn start() {\n" +
		"  mkdir " + work + "/d mode 0750 owner nobody:nogroup\n" +
		"  touch " + work + "/d/f\n" +
		"  chmod " + work + "/d/f 0600\n" +
		"  chown " + work + "/d/f nobody:nogroup\n" +
		"  ln " + work + "/d/l " + work + "/d/f\n" +
		"  touch " + work + "/d/gone\n" +
		"  rm " + work + "/d/gone\n" +
		"  mount tmpfs " + m1 + " type tmpfs opts \"size=1m,noexec\"\n" +
		"  mount " + src + " " + m2 + " opts \"bind,ro\"\n" +
		"  spawn main /usr/bin/sleep 300\n}\n"
	e.add("files", script, g, e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	if err := sup.Start(t.Context(), "files"); err != nil {
		d, _ := sup.Diagnostics("files")
		t.Fatalf("start: %v %s %+v stderr %s", err, log.String(), rowOf(t, sup, "files").Sash, d.Stderr.Data)
	}
	st := func(p string) *syscall.Stat_t {
		var s syscall.Stat_t
		if err := syscall.Lstat(p, &s); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return &s
	}
	if d := st(work + "/d"); d.Mode&0o7777 != 0o750 || d.Uid != 65534 || d.Gid != 65534 {
		t.Fatalf("dir %o %d", d.Mode, d.Uid)
	}
	if f := st(work + "/d/f"); f.Mode&0o7777 != 0o600 || f.Uid != 65534 {
		t.Fatalf("file %o %d", f.Mode, f.Uid)
	}
	if l, err := os.Readlink(work + "/d/l"); err != nil || l != work+"/d/f" || st(work+"/d/l").Uid != 65534 {
		t.Fatalf("link %q %v", l, err)
	}
	if _, err := os.Lstat(work + "/d/gone"); !os.IsNotExist(err) {
		t.Fatal("rm left the file")
	}
	o1, o2 := mountOpts(t, m1), mountOpts(t, m2)
	if !strings.Contains(o1, "nosuid") || !strings.Contains(o1, "nodev") || !strings.Contains(o1, "noexec") || !strings.Contains(o2, "ro") || !strings.Contains(o2, "nosuid") {
		raw, _ := os.ReadFile("/proc/self/mountinfo")
		var mine []string
		for _, l := range strings.Split(string(raw), "\n") {
			if strings.Contains(l, "files-") {
				mine = append(mine, l)
			}
		}
		t.Fatalf("mounts %q %q\n%s\n%s", o1, o2, strings.Join(mine, "\n"), log.String())
	}
	if raw, err := os.ReadFile(m2 + "/hello"); err != nil || string(raw) != "hi\n" {
		t.Fatalf("bind content %q %v", raw, err)
	}
	if err := sup.Stop(t.Context(), "files"); err != nil {
		t.Fatal(err)
	}
	if mountOpts(t, m1) != "" || mountOpts(t, m2) != "" {
		t.Fatalf("mounts left after stop: %q %q", mountOpts(t, m1), mountOpts(t, m2))
	}
}

// Attacks a sash script cannot see coming fail at sahinit: a symlink in
// the path, a hard link to a file outside the root, and a root-owned file.
// Each start fails, and nothing outside the root changes.
func TestSashFileAttacksEndToEnd(t *testing.T) {
	e := newSashEnv(t)
	outside := filepath.Join(e.base, "outside")
	os.Mkdir(outside, 0o755)
	victim := filepath.Join(outside, "victim")
	os.WriteFile(victim, []byte("x"), 0o644)
	os.Chown(victim, 65534, 65534) // even the service's own file is not reached through a link
	cases := map[string]struct {
		setup  func(work string)
		action string
		want   string
	}{
		"symlink swap": {func(w string) { os.Symlink(outside, w+"/sub") }, "touch WORK/sub/new", "failed"},
		"symlink last": {func(w string) { os.Symlink(victim, w+"/l") }, "chmod WORK/l 0777", "failed"},
		"hard link":    {func(w string) { os.Link(victim, w+"/h") }, "chmod WORK/h 0777", "failed"},
		"root file": {func(w string) {
			os.WriteFile(w+"/secret", []byte("s"), 0o600)
		}, "chown WORK/secret nobody:nogroup", "sash_config"},
	}
	works := map[string]string{}
	i := 0
	for name, c := range cases {
		i++
		svc := "atk" + string(rune('a'+i))
		g, work, _, _, _ := filesGrant(e, svc)
		c.setup(work)
		works[name] = svc
		e.add(svc, refusalScript(svc, strings.ReplaceAll(c.action, "WORK", work)), g, e.fleet)
	}
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	for name, c := range cases {
		svc := works[name]
		if err := sup.Start(t.Context(), svc); err == nil || rowOf(t, sup, svc).LastError != c.want {
			t.Errorf("%s: %v %+v, want %s", name, err, rowOf(t, sup, svc), c.want)
		}
	}
	var v syscall.Stat_t
	syscall.Stat(victim, &v)
	if v.Mode&0o777 != 0o644 {
		t.Fatalf("victim mode %o", v.Mode&0o777)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Fatalf("outside changed: %v", entries)
	}
}

// sahinit refuses these itself, whatever sash sent: the requests reach the
// verb server as a misbehaving sash would send them, with the real host.
func TestSashFileAndMountHostRechecks(t *testing.T) {
	e := newSashEnv(t)
	g, work, src, m1, _ := filesGrant(e, "raw")
	e.add("raw", refusalScript("raw", "spawn main /usr/bin/sleep 300"), g, e.fleet)
	var log syncBuf
	sup, _ := e.load(&log)
	s := sup.rt["raw"]
	outside := filepath.Join(e.base, "rawout")
	os.Mkdir(outside, 0o755)
	victim := filepath.Join(outside, "victim")
	os.WriteFile(victim, []byte("x"), 0o644)
	os.Symlink(outside, work+"/sub")
	os.Link(victim, work+"/h")
	os.WriteFile(work+"/secret", []byte("s"), 0o600)
	os.Mkdir(work+"/rootdir", 0o755)
	os.Mkdir(work+"/real", 0o755)
	os.Chown(work+"/real", 65534, 65534)
	os.Symlink(work+"/real", work+"/inner") // a link that stays beneath the root
	os.WriteFile(work+"/dfile", nil, 0o644)
	os.Chown(work+"/dfile", 1, 1) // daemon's
	os.WriteFile(work+"/mine", []byte("m"), 0o644)
	os.Chown(work+"/mine", 65534, 65534)
	srv := &sash.Server{G: g, Table: s.sashTable(), Host: &sashHost{sup: sup, s: s}}
	file := func(a ...string) sash.Response {
		return srv.Handle(sash.Request{Key: "file.write", Argv: a, Path: a[1]})
	}
	mount := func(a ...string) sash.Response { return srv.Handle(sash.Request{Key: "fs.mount", Argv: a}) }
	for name, c := range map[string]struct {
		r    sash.Response
		want string
	}{
		"symlink component": {file("touch", work+"/sub/x"), "symlink"},
		"symlink parent":    {file("mkdir", work+"/sub/d"), "symlink"},
		"hard link chmod":   {file("chmod", work+"/h", "0777"), "hardlink"},
		"hard link chown":   {file("chown", work+"/h", "nobody:nogroup"), "hardlink"},
		"hard link rm":      {file("rm", work+"/h"), "hardlink"},
		"root file chown":   {file("chown", work+"/secret", "nobody:nogroup"), "denied"},
		"root file chmod":   {file("chmod", work+"/secret", "0644"), "denied"},
		"root file rm":      {file("rm", work+"/secret"), "denied"},
		"root file touch":   {file("touch", work+"/secret"), "denied"},
		"root dir mode":     {file("mkdir", work+"/rootdir", "mode", "0777"), "denied"},
		"symlink last":      {file("chmod", work+"/sub", "0777"), "symlink"},
		"symlink inside":    {file("touch", work+"/inner/x"), "symlink"},
		"dotdot":            {file("touch", work+"/../rawout/x"), "denied"},
		"chown to root":     {file("chown", work+"/mine", "root:root"), "denied"},
		"setuid":            {file("chmod", work+"/mine", "4755"), "denied"},
		"bind of /":         {mount("mount", "/", m1, "opts", "bind,nosuid,nodev"), "denied"},
		"bind outside":      {mount("mount", "/etc", m1, "opts", "bind,nosuid,nodev"), "denied"},
		"overlay":           {mount("mount", "overlay", m1, "type", "overlay", "opts", "lowerdir=/etc,nosuid,nodev"), "mount_opt_refused"},
		"lowerdir":          {mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "lowerdir=/etc,nosuid,nodev"), "mount_opt_refused"},
		"suid mount":        {mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "suid,nodev"), "mount_opt_refused"},
		"mount in root":     {mount("mount", "tmpfs", work, "type", "tmpfs", "opts", "nosuid,nodev"), "denied"},
		"umount not ours":   {mount("umount", m1), "not_mounted"},
	} {
		if c.r.Error != c.want {
			t.Errorf("%s: %+v, want %s", name, c.r, c.want)
		}
	}
	// The host refuses a mount without nosuid and nodev, whatever the
	// server let through.
	if err := (&sashHost{sup: sup, s: s}).Mount(sash.MountPlan{Src: "tmpfs", Dir: m1, Type: "tmpfs", Flags: []string{"nodev"}}); fail.Token(err) != "mount_opt_refused" {
		t.Errorf("host mount without nosuid: %v", err)
	}
	// A grant identity that is not the unit's uid and gid owns nothing.
	srv.G.User, srv.G.Group = "daemon", "daemon"
	if r := file("chown", work+"/dfile", "daemon:daemon"); r.Error != "denied" {
		t.Errorf("another account: %+v", r)
	}
	srv.G.User, srv.G.Group = "nobody", "nogroup"
	// probe file does not count a symlink as the file.
	srv.G.Entitlements = append(srv.G.Entitlements, "svc.probe")
	srv.G.FileRead = []string{work}
	if r := srv.Handle(sash.Request{Key: "svc.probe", Argv: []string{"probe", "file", work + "/inner"}}); r.Error != "" || r.Exit != 1 {
		t.Errorf("probe file through a link: %+v", r)
	}
	if r := srv.Handle(sash.Request{Key: "svc.probe", Argv: []string{"probe", "file", work + "/real"}}); r.Error != "" || r.Exit != 0 {
		t.Errorf("probe file: %+v", r)
	}
	// A good tmpfs with a size, remounted read-only, then unmounted.
	if r := mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "size=1m,mode=0750,nosuid,nodev"); r.Error != "" {
		t.Fatalf("tmpfs: %+v", r)
	}
	if o := mountOpts(t, m1); !strings.Contains(o, "nosuid") || !strings.Contains(o, "nodev") {
		t.Fatalf("tmpfs options %q", o)
	}
	if r := mount("mount", "tmpfs", m1, "type", "tmpfs", "opts", "remount,ro,nosuid,nodev"); r.Error != "" || !strings.HasPrefix(mountOpts(t, m1), "ro") {
		t.Fatalf("remount: %+v %q", r, mountOpts(t, m1))
	}
	if r := mount("umount", m1); r.Error != "" || mountOpts(t, m1) != "" {
		t.Fatalf("umount: %+v", r)
	}
	// A bind whose source was swapped for a symlink after the grant was
	// signed is refused at the open.
	os.RemoveAll(src)
	os.Symlink("/etc", src)
	if r := mount("mount", src, m1, "opts", "bind,nosuid,nodev"); r.Error != "symlink" {
		t.Errorf("swapped source: %+v", r)
	}
	if mountOpts(t, m1) != "" {
		t.Fatal("something was mounted")
	}
	var v syscall.Stat_t
	syscall.Stat(victim, &v)
	if v.Mode&0o777 != 0o644 || v.Uid != 0 {
		t.Fatalf("victim changed: %o %d", v.Mode&0o777, v.Uid)
	}
	if raw, _ := json.Marshal(srv.Table.Mounts()); string(raw) != "[]" {
		t.Fatalf("table mounts %s", raw)
	}
}
