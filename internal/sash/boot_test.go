// SPDX-License-Identifier: GPL-3.0-or-later

package sash

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// bootHost is fakeHost with the boot verbs: a fixture catalog, a module
// tree's modules.dep, and a record of every call.
type bootHost struct {
	fakeHost
	units  map[string]UnitInfo
	status map[string]string
	dep    string
	live   map[string]bool
	calls  []string
	err    error
}

func (h *bootHost) Status(service string) (Row, error) {
	if st, ok := h.status[service]; ok {
		return Row{"name": service, "state": st, "since": "", "pid": "0"}, nil
	}
	return nil, fail.E("unknown_service")
}

func (h *bootHost) LoadModule(_ context.Context, name string) (ModuleResult, error) {
	h.calls = append(h.calls, "module "+name)
	if h.err != nil {
		return ModuleResult{}, h.err
	}
	own, deps, err := ResolveModule([]byte(h.dep), name)
	if err != nil {
		return ModuleResult{}, err
	}
	r := ModuleResult{State: "done"}
	for _, d := range deps {
		r.Deps = append(r.Deps, d.Name)
	}
	if h.live[own.Name] {
		r.State = "already"
	}
	h.live[own.Name] = true
	return r, nil
}

func (h *bootHost) WaitDevice(_ context.Context, name string, decl DeviceDecl, d time.Duration) (DevID, error) {
	h.calls = append(h.calls, "device "+name+" "+decl.Path+" "+d.String())
	return DevID{Major: 254, Minor: 16}, h.err
}

func (h *bootHost) EnsureMount(_ context.Context, p HostMountPlan) (string, error) {
	dev := "none"
	if p.Device != nil {
		dev = p.Device.Path
	}
	h.calls = append(h.calls, "mount "+p.Name+" "+p.Decl.Target+" "+dev)
	return "done", h.err
}

func (h *bootHost) ApplyNetwork(_ context.Context, name string, decl NetworkDecl) (NetResult, error) {
	h.calls = append(h.calls, "net "+name+" "+decl.Link)
	return NetResult{Link: "eth0", State: "done", Changes: 3}, h.err
}

func (h *bootHost) Unit(name string) (UnitInfo, error) {
	u, ok := h.units[name]
	if !ok {
		return UnitInfo{}, fail.E("not_found")
	}
	return u, nil
}

func (h *bootHost) StartUnit(_ context.Context, name string) (Row, bool, error) {
	h.calls = append(h.calls, "start "+name)
	return Row{"name": name, "state": "ready", "since": "", "pid": "7", "secret": "x"}, false, h.err
}

func (h *bootHost) StopUnit(_ context.Context, name string) (Row, bool, error) {
	h.calls = append(h.calls, "stop "+name)
	return Row{"name": name, "state": "stopped", "since": "", "pid": "0"}, true, h.err
}

const testModulesDep = `kernel/drivers/block/virtio_blk.ko.xz: kernel/drivers/virtio/virtio_ring.ko.xz kernel/drivers/virtio/virtio.ko.xz
kernel/drivers/net/virtio_net.ko.zst: kernel/drivers/net/net_failover.ko.zst
kernel/drivers/virtio/virtio_ring.ko.xz:
kernel/drivers/virtio/virtio.ko.xz:
kernel/drivers/net/net_failover.ko.zst:
kernel/fs/fat/vfat-mod.ko:
`

func testBootGrant() Grant {
	g := SampleBootGrant("hostprep", "hostprep", "hostprep")
	g.Host = "web1"
	g.FileWrite = []string{"/run/hostprep"}
	g.Modules = []string{"virtio_blk", "virtio_net", "vfat_mod", "missing"}
	g.Devices = []string{"data", "logs", "ghost"}
	g.HostMounts = []string{"data", "scratch", "ghost", "logs"}
	g.NetProfiles = []string{"lan", "wan", "dhcp", "ghost"}
	g.UnitsStart = []string{"dhcp", "app", "hostprep", "other-ops", "late", "ghost", "loop"}
	g.UnitsStop = []string{"getty", "app", "fw", "hostprep", "other-ops"}
	return g
}

func newBootServer(t *testing.T) (*Server, *bootHost) {
	t.Helper()
	decl, err := ParseHostDecl([]byte(HostFixture))
	if err != nil {
		t.Fatal(err)
	}
	h := &bootHost{
		units: map[string]UnitInfo{
			"dhcp": {}, "getty": {}, "late": {After: []string{"hostprep"}},
			"loop": {Needs: []string{"mid"}}, "mid": {After: []string{"hostprep"}},
			"app": {Boot: true, Essential: true, Needs: []string{"hostprep"}},
			"fw":  {Boot: true, Essential: true}, "hostprep": {Boot: true, Essential: true, BootOps: true},
			"other-ops": {Boot: true, Essential: true, BootOps: true},
		},
		status: map[string]string{"firewall": "starting"},
		dep:    testModulesDep,
		live:   map[string]bool{},
	}
	booted := false
	s := &Server{G: testBootGrant(), Table: NewTable(), Host: h, BootOps: true, Entry: "start", Decl: decl,
		Boot: NewBootState(func() bool { return booted })}
	t.Cleanup(func() { booted = false })
	return s, h
}

func bootReq(key string, argv ...string) Request { return Request{Key: key, Argv: argv} }

func call(s *Server, key string, argv ...string) (Response, string) {
	r := s.Handle(bootReq(key, argv...))
	return r, r.Error
}

func TestBootVerbsPerform(t *testing.T) {
	s, h := newBootServer(t)
	r, tok := call(s, "boot.module", "module", "load", "virtio_blk")
	if tok != "" || r.Rows[0]["state"] != "done" || r.Rows[0]["deps"] != "virtio_ring,virtio" || strings.Join(r.Cols, ",") != "name,state,deps" {
		t.Fatalf("module: %+v", r)
	}
	if r, _ := call(s, "boot.module", "module", "load", "virtio_blk"); r.Rows[0]["state"] != "already" {
		t.Fatalf("module again: %+v", r)
	}
	r, tok = call(s, "boot.device", "device", "wait", "data", "timeout", "30")
	if tok != "" || r.Rows[0]["path"] != "/dev/vdb" || r.Rows[0]["major"] != "254" || r.Rows[0]["minor"] != "16" {
		t.Fatalf("device: %+v", r)
	}
	r, tok = call(s, "boot.mount", "mount", "ensure", "data")
	if tok != "" || r.Rows[0]["target"] != "/data" || r.Rows[0]["fstype"] != "ext4" || r.Rows[0]["state"] != "done" {
		t.Fatalf("mount: %+v", r)
	}
	if _, tok := call(s, "boot.mount", "mount", "ensure", "scratch"); tok != "" {
		t.Fatalf("tmpfs needs no device wait: %s", tok)
	}
	r, tok = call(s, "boot.net", "network", "apply", "lan")
	if tok != "" || r.Rows[0]["link"] != "eth0" || r.Rows[0]["changes"] != "3" {
		t.Fatalf("net: %+v", r)
	}
	r, tok = call(s, "boot.net", "network", "apply", "dhcp")
	if tok != "" || r.Rows[0]["state"] != "done" || r.Rows[0]["link"] != "" {
		t.Fatalf("unit profile: %+v", r)
	}
	if _, tok := call(s, "boot.start", "service", "start", "dhcp"); tok != "boot_once" {
		t.Fatalf("the unit profile started dhcp once already: %s", tok)
	}
	r, tok = call(s, "boot.stop", "service", "stop", "getty")
	if tok != "" || strings.Join(r.Cols, ",") != "name,state,since,pid" || r.Rows[0]["state"] != "stopped" {
		t.Fatalf("stop: %+v", r)
	}
	if _, ok := r.Rows[0]["secret"]; ok {
		t.Fatal("a host row field beyond the columns reached the script")
	}
	want := []string{"module virtio_blk", "module virtio_blk", "device data /dev/vdb 30s", "mount data /data /dev/vdb", "mount scratch /scratch none",
		"net lan 52:54:00:12:34:56", "start dhcp", "stop getty"}
	if strings.Join(h.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls\n%v\n%v", h.calls, want)
	}
	if s.Boot.Calls("hostprep") != 9 {
		t.Fatalf("calls counted %d", s.Boot.Calls("hostprep"))
	}
}

// The gates, in the contract's order, each before the host is called.
func TestBootGates(t *testing.T) {
	ok := bootReq("boot.module", "module", "load", "virtio_blk")
	for name, c := range map[string]struct {
		edit func(*Server, *Request)
		want string
	}{
		"key not listed": {func(s *Server, _ *Request) { s.G.Entitlements = []string{"boot.device"} }, "denied"},
		"sash/2 lists the key": {func(s *Server, _ *Request) {
			s.G.V, s.G.Purpose = "sash/2", PurposeService
		}, "denied"},
		"sash/1 lists the key": {func(s *Server, _ *Request) { s.G.V, s.G.Purpose = "sash/1", "open" }, "denied"},
		"not opted in":         {func(s *Server, _ *Request) { s.BootOps = false }, "sash_boot_ops"},
		"stop entry":           {func(s *Server, _ *Request) { s.Entry = "stop" }, "boot_entry"},
		"reload entry":         {func(s *Server, _ *Request) { s.Entry = "reload" }, "boot_entry"},
		"run entry":            {func(s *Server, _ *Request) { s.Entry = "run" }, "boot_entry"},
		"check session":        {func(s *Server, _ *Request) { s.Entry, s.Check = "check", true }, "boot_entry"},
		"check flag":           {func(s *Server, _ *Request) { s.Check = true }, "boot_entry"},
		"boot over":            {func(s *Server, _ *Request) { s.Boot.Over = func() bool { return true } }, "boot_over"},
		"no boot record":       {func(s *Server, _ *Request) { s.Boot = nil }, "boot_over"},
		"path":                 {func(_ *Server, r *Request) { r.Path = "/x" }, "denied"},
		"body":                 {func(_ *Server, r *Request) { r.Body = []byte("{}") }, "denied"},
		"mode":                 {func(_ *Server, r *Request) { r.Mode = "0644" }, "denied"},
	} {
		s, h := newBootServer(t)
		req := ok
		req.Argv = append([]string(nil), ok.Argv...)
		c.edit(s, &req)
		if got := s.Handle(req).Error; got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
		if len(h.calls) != 0 {
			t.Errorf("%s: the host was called", name)
		}
	}
}

func TestBootCallLimit(t *testing.T) {
	s, _ := newBootServer(t)
	other := *s
	for i := 0; i < MaxBootCalls; i++ {
		// Refused calls count too: the budget is spent at the door.
		if _, tok := call(s, "boot.module", "module", "load", "nope"); tok != "denied" {
			t.Fatalf("call %d: %s", i, tok)
		}
	}
	if _, tok := call(s, "boot.module", "module", "load", "virtio_blk"); tok != "boot_call_limit" {
		t.Fatalf("65th: %s", tok)
	}
	// A new session of the same service in the same boot has no fresh
	// budget; another service has its own.
	fresh := &Server{G: s.G, Table: NewTable(), Host: s.Host, BootOps: true, Entry: "start", Decl: s.Decl, Boot: s.Boot}
	if _, tok := call(fresh, "boot.module", "module", "load", "virtio_blk"); tok != "boot_call_limit" {
		t.Fatalf("restarted session: %s", tok)
	}
	other.G.Service, other.G.Actor = "netprep", "boot:netprep"
	if _, tok := call(&other, "boot.module", "module", "load", "virtio_blk"); tok != "" {
		t.Fatalf("another service: %s", tok)
	}
}

func TestBootShapesAndNames(t *testing.T) {
	for name, c := range map[string]struct {
		key  string
		argv []string
		want string
	}{
		"module traversal":       {"boot.module", []string{"module", "load", "../x"}, "denied"},
		"module path":            {"boot.module", []string{"module", "load", "a/b"}, "denied"},
		"module file":            {"boot.module", []string{"module", "load", "x.ko"}, "denied"},
		"module alias":           {"boot.module", []string{"module", "load", "virtio-net"}, "denied"},
		"module flag":            {"boot.module", []string{"module", "load", "-f"}, "denied"},
		"module parameter":       {"boot.module", []string{"module", "load", "virtio_blk", "x=1"}, "denied"},
		"module not granted":     {"boot.module", []string{"module", "load", "e1000"}, "denied"},
		"module verb":            {"boot.module", []string{"module", "unload", "virtio_blk"}, "denied"},
		"module under wrong key": {"boot.device", []string{"module", "load", "virtio_blk"}, "denied"},
		"device path":            {"boot.device", []string{"device", "wait", "a/b", "timeout", "5"}, "denied"},
		"device not granted":     {"boot.device", []string{"device", "wait", "root", "timeout", "5"}, "denied"},
		"device undeclared":      {"boot.device", []string{"device", "wait", "ghost", "timeout", "5"}, "not_found"},
		"device timeout 0":       {"boot.device", []string{"device", "wait", "data", "timeout", "0"}, "denied"},
		"device timeout 61":      {"boot.device", []string{"device", "wait", "data", "timeout", "61"}, "denied"},
		"device timeout 30s":     {"boot.device", []string{"device", "wait", "data", "timeout", "30s"}, "denied"},
		"device timeout 030":     {"boot.device", []string{"device", "wait", "data", "timeout", "030"}, "denied"},
		"device timeout +5":      {"boot.device", []string{"device", "wait", "data", "timeout", "+5"}, "denied"},
		"device no timeout":      {"boot.device", []string{"device", "wait", "data"}, "denied"},
		"device timeout word":    {"boot.device", []string{"device", "wait", "data", "until", "30"}, "denied"},
		"mount path":             {"boot.mount", []string{"mount", "ensure", "/mnt/x"}, "denied"},
		"mount two names":        {"boot.mount", []string{"mount", "ensure", "data", "scratch"}, "denied"},
		"mount not granted":      {"boot.mount", []string{"mount", "ensure", "home"}, "denied"},
		"mount undeclared":       {"boot.mount", []string{"mount", "ensure", "ghost"}, "not_found"},
		"mount without wait":     {"boot.mount", []string{"mount", "ensure", "data"}, "device_changed"},
		"net not granted":        {"boot.net", []string{"network", "apply", "dmz"}, "denied"},
		"net undeclared":         {"boot.net", []string{"network", "apply", "ghost"}, "not_found"},
		"net unguarded":          {"boot.net", []string{"network", "apply", "wan"}, "net_unguarded"},
		"start flag":             {"boot.start", []string{"service", "start", "-x"}, "denied"},
		"start underscore":       {"boot.start", []string{"service", "start", "a_b"}, "denied"},
		"start not granted":      {"boot.start", []string{"service", "start", "getty"}, "denied"},
		"start with stop key":    {"boot.stop", []string{"service", "start", "dhcp"}, "denied"},
		"start missing":          {"boot.start", []string{"service", "start", "ghost"}, "not_found"},
		"start self":             {"boot.start", []string{"service", "start", "hostprep"}, "boot_self"},
		"start chain":            {"boot.start", []string{"service", "start", "other-ops"}, "boot_chain"},
		"start boot unit":        {"boot.start", []string{"service", "start", "app"}, "boot_unit_auto"},
		"start after caller":     {"boot.start", []string{"service", "start", "late"}, "boot_cycle"},
		"start through a chain":  {"boot.start", []string{"service", "start", "loop"}, "boot_cycle"},
		"stop essential":         {"boot.stop", []string{"service", "stop", "fw"}, "boot_essential"},
		"stop self":              {"boot.stop", []string{"service", "stop", "hostprep"}, "boot_self"},
		"stop chain":             {"boot.stop", []string{"service", "stop", "other-ops"}, "boot_chain"},
		"stop not granted":       {"boot.stop", []string{"service", "stop", "dhcp"}, "denied"},
		"unknown boot verb":      {"boot.module", []string{}, "denied"},
	} {
		s, h := newBootServer(t)
		if _, tok := call(s, c.key, c.argv...); tok != c.want {
			t.Errorf("%s: %q, want %q", name, tok, c.want)
		}
		if len(h.calls) != 0 {
			t.Errorf("%s: the host was called: %v", name, h.calls)
		}
	}
}

func TestBootOnceAndOverlap(t *testing.T) {
	s, h := newBootServer(t)
	if _, tok := call(s, "boot.start", "service", "start", "dhcp"); tok != "" {
		t.Fatal(tok)
	}
	if _, tok := call(s, "boot.start", "service", "start", "dhcp"); tok != "boot_once" {
		t.Fatalf("twice: %s", tok)
	}
	if _, tok := call(s, "boot.stop", "service", "stop", "app"); tok != "boot_essential" {
		t.Fatalf("stop app: %s", tok)
	}
	h.units["app"] = UnitInfo{}
	if _, tok := call(s, "boot.stop", "service", "stop", "app"); tok != "" {
		t.Fatal(tok)
	}
	if _, tok := call(s, "boot.stop", "service", "stop", "app"); tok != "boot_once" {
		t.Fatalf("stop twice: %s", tok)
	}
	// Once per unit per boot, whichever way: start then stop, and stop
	// then start, are both boot_once.
	s.G.UnitsStop = append(s.G.UnitsStop, "dhcp")
	if _, tok := call(s, "boot.stop", "service", "stop", "dhcp"); tok != "boot_once" {
		t.Fatalf("start then stop: %s", tok)
	}
	s.G.UnitsStart = append(s.G.UnitsStart, "getty")
	if _, tok := call(s, "boot.stop", "service", "stop", "getty"); tok != "" {
		t.Fatal(tok)
	}
	if _, tok := call(s, "boot.start", "service", "start", "getty"); tok != "boot_once" {
		t.Fatalf("stop then start: %s", tok)
	}
	// A host mount at, under or above a file_write root is mount_overlap.
	for _, root := range []string{"/scratch", "/scratch/run", "/scratch/a/b"} {
		s, _ := newBootServer(t)
		s.G.FileWrite = []string{root}
		if _, tok := call(s, "boot.mount", "mount", "ensure", "scratch"); tok != "mount_overlap" {
			t.Errorf("root %s: %s", root, tok)
		}
	}
	// A host mount under a file_write root is mount_overlap too.
	s, _ = newBootServer(t)
	m := s.Decl.Mounts["scratch"]
	m.Target = "/srv/scratch"
	s.Decl.Mounts["scratch"] = m
	s.G.FileWrite = []string{"/srv"}
	if _, tok := call(s, "boot.mount", "mount", "ensure", "scratch"); tok != "mount_overlap" {
		t.Errorf("under a root: %s", tok)
	}
	// A requires unit that is running but not ready does not guard.
	s, _ = newBootServer(t)
	s.Host.(*bootHost).status["firewall"] = "running"
	if _, tok := call(s, "boot.net", "network", "apply", "wan"); tok != "net_unguarded" {
		t.Fatalf("running, not ready: %s", tok)
	}
	// Ready or exited requires let a guarded profile through.
	s, _ = newBootServer(t)
	s.Host.(*bootHost).status["firewall"] = "exited"
	if _, tok := call(s, "boot.net", "network", "apply", "wan"); tok != "" {
		t.Fatalf("guarded: %s", tok)
	}
}

// Host errors reach the script only as contract codes.
func TestBootHostErrors(t *testing.T) {
	for in, want := range map[string]string{
		"module_failed": "module_failed", "device_mismatch": "device_mismatch", "mount_conflict": "mount_conflict",
		"net_unknown_link": "net_unknown_link", "timeout": "timeout", "errno 13 /lib/modules/x": "failed", "sandbox_cap": "failed",
	} {
		s, h := newBootServer(t)
		h.err = fail.E(in)
		if _, tok := call(s, "boot.module", "module", "load", "virtio_blk"); tok != want {
			t.Errorf("%s: %s, want %s", in, tok, want)
		}
	}
	s, h := newBootServer(t)
	if _, tok := call(s, "boot.module", "module", "load", "missing"); tok != "module_unknown" {
		t.Fatalf("unknown: %s", tok)
	}
	h.dep = "kernel/a.ko: /etc/evil.ko\n"
	s.G.Modules = []string{"a"}
	if _, tok := call(s, "boot.module", "module", "load", "a"); tok != "module_tree" {
		t.Fatalf("forged line: %s", tok)
	}
}

func TestBootDeviceWaitDeadline(t *testing.T) {
	s, h := newBootServer(t)
	now := time.Unix(1_700_000_000, 0)
	s.Now = func() time.Time { return now }
	s.Deadline = now.Add(5 * time.Second)
	if _, tok := call(s, "boot.device", "device", "wait", "data", "timeout", "30"); tok != "" || !strings.HasSuffix(h.calls[0], " 5s") {
		t.Fatalf("bounded by the session: %s %v", tok, h.calls)
	}
	s.Deadline = now
	if _, tok := call(s, "boot.device", "device", "wait", "data", "timeout", "30"); tok != "timeout" {
		t.Fatalf("no time left: %s", tok)
	}
}

// A host without the boot verbs answers unsupported, after the gates.
func TestBootUnsupportedHost(t *testing.T) {
	s, _ := newBootServer(t)
	s.Host = &fakeHost{}
	if _, tok := call(s, "boot.module", "module", "load", "virtio_blk"); tok != "unsupported" {
		t.Fatalf("%s", tok)
	}
}

func TestResolveModule(t *testing.T) {
	own, deps, err := ResolveModule([]byte(testModulesDep), "virtio_blk")
	if err != nil || own.File != "kernel/drivers/block/virtio_blk.ko.xz" || len(deps) != 2 || deps[0].Name != "virtio_ring" || deps[1].File != "kernel/drivers/virtio/virtio.ko.xz" {
		t.Fatalf("%+v %+v %v", own, deps, err)
	}
	if own, _, err := ResolveModule([]byte(testModulesDep), "vfat_mod"); err != nil || own.File != "kernel/fs/fat/vfat-mod.ko" {
		t.Fatalf("dash as underscore: %+v %v", own, err)
	}
	for name, c := range map[string]struct {
		dep, mod, want string
	}{
		"absolute dependency":  {"kernel/a.ko: /lib/x.ko\n", "a", "module_tree"},
		"absolute module":      {"/kernel/a.ko:\n", "a", "module_tree"},
		"dot-dot":              {"kernel/a.ko: ../../etc/x.ko\n", "a", "module_tree"},
		"dot-dot in the path":  {"kernel/../a.ko:\n", "a", "module_tree"},
		"unclean":              {"kernel//a.ko:\n", "a", "module_tree"},
		"dependency not a .ko": {"kernel/a.ko: kernel/b.so\n", "a", "module_tree"},
		"two lines":            {"kernel/a.ko:\nextra/a.ko.xz:\n", "a", "module_unknown"},
		"bad line elsewhere":   {"kernel/a.ko:\n/abs/b.ko:\n", "a", "module_tree"},
		"line without a colon": {"kernel/a.ko:\nkernel/b.ko\n", "a", "module_tree"},
		"dots in a name":       {"kernel/a..b.ko:\nkernel/a.ko:\n", "a", "module_tree"},
		"dependency grammar":   {"kernel/a.ko: kernel/A-B.ko\n", "a", "module_tree"},
		"two suffixes":         {"kernel/a.ko.gz.xz:\n", "a", "module_unknown"},
		"no .ko":               {"kernel/a.xz:\n", "a", "module_unknown"},
		"suffix only":          {"kernel/a.ko.bz2:\n", "a", "module_unknown"},
		"prefix match":         {"kernel/ab.ko:\n", "a", "module_unknown"},
		"bad name":             {"kernel/a.ko:\n", "../a", "module_unknown"},
		"oversized":            {strings.Repeat("x", MaxModulesDep+1), "a", "module_tree"},
	} {
		if _, _, err := ResolveModule([]byte(c.dep), c.mod); fail.Token(err) != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
}

// The device wait record is per service: another service's wait does not
// let this one mount through that dev_t.
func TestBootDeviceRecordPerService(t *testing.T) {
	s, _ := newBootServer(t)
	if _, tok := call(s, "boot.device", "device", "wait", "data", "timeout", "5"); tok != "" {
		t.Fatal(tok)
	}
	other := &Server{G: s.G, Table: NewTable(), Host: s.Host, BootOps: true, Entry: "start", Decl: s.Decl, Boot: s.Boot}
	other.G.Service, other.G.Actor = "netprep", "boot:netprep"
	if _, tok := call(other, "boot.mount", "mount", "ensure", "data"); tok != "device_changed" {
		t.Fatalf("another service's wait: %s", tok)
	}
	if _, tok := call(s, "boot.mount", "mount", "ensure", "data"); tok != "" {
		t.Fatalf("own wait: %s", tok)
	}
}
