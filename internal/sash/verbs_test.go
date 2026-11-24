package sash

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

type fakeHost struct {
	spawned []SpawnPlan
	signals []string
	ready   map[string]bool
	err     error
	pid     int
	files   []FileOp
	mounts  []MountPlan
	umounts []string
}

func (h *fakeHost) Spawn(plan SpawnPlan, p *Proc) error {
	if h.err != nil {
		return h.err
	}
	h.pid++
	p.Started(1000+h.pid, time.Unix(1_700_000_000, 0), nil)
	h.spawned = append(h.spawned, plan)
	return nil
}

func (h *fakeHost) Signal(p *Proc, sig string) error {
	h.signals = append(h.signals, p.Name+" "+sig)
	if sig == "TERM" || sig == "KILL" {
		p.Exit(0, sig, time.Unix(1_700_000_100, 0))
	}
	return nil
}

func (h *fakeHost) Status(service string) (Row, error) {
	if service == "postgres" {
		return Row{"name": service, "state": "ready", "since": "2026-11-23T00:00:00Z", "pid": "0"}, nil
	}
	return nil, fail.E("unknown_service")
}

func (h *fakeHost) File(op FileOp) error {
	h.files = append(h.files, op)
	return h.err
}

func (h *fakeHost) Mount(m MountPlan) error {
	h.mounts = append(h.mounts, m)
	return h.err
}

func (h *fakeHost) Umount(dir string) error {
	h.umounts = append(h.umounts, dir)
	return h.err
}

func (h *fakeHost) DialTCP(addr string) bool            { return h.ready["tcp "+addr] }
func (h *fakeHost) ProbePath(kind, root, p string) bool { return h.ready[kind+" "+p] }

func testGrant() Grant {
	g := SampleGrant("app", "app", "app")
	g.Exec = []string{"/opt/app/bin/server"}
	g.FileRead = []string{"/etc/app"}
	g.FileWrite = []string{"/run/app", "/var/log/app"}
	g.Caps = []string{"CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"}
	g.EnvNames = []string{"PORT", "DB_PASS", "LD_PRELOAD", "PATH"}
	return g
}

func newServer() (*Server, *fakeHost) {
	h := &fakeHost{ready: map[string]bool{}}
	return &Server{G: testGrant(), Table: NewTable(), Host: h, CapCeiling: []string{"net_bind_service"}}, h
}

func spawnReq(t *testing.T, name string, opts map[string]any, args ...string) Request {
	t.Helper()
	req := Request{Key: "svc.spawn", Argv: append([]string{"spawn", name, "/opt/app/bin/server"}, args...)}
	if opts == nil {
		opts = map[string]any{"user": "app", "group": "app"}
	}
	b, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = b
	return req
}

func withID(o map[string]any) map[string]any {
	o["user"], o["group"] = "app", "app"
	return o
}

func TestSpawnAccepted(t *testing.T) {
	s, h := newServer()
	resp := s.Handle(spawnReq(t, "main", withID(map[string]any{
		"env":    map[string]any{"PORT": "8080", "DB_PASS": map[string]any{"secret": "hunter2"}},
		"cwd":    "/run/app/work",
		"umask":  "027",
		"limits": map[string]any{"nofile": 1024, "core": 0},
		"stdout": "file:/var/log/app/out.log",
		"stderr": "stdout",
	}), "--port", "8080"))
	if resp.Error != "" || resp.Kind != "rows" || resp.Rows[0]["name"] != "main" || resp.Rows[0]["pid"] != "1001" {
		t.Fatalf("%+v", resp)
	}
	p := h.spawned[0]
	if strings.Join(p.Argv, " ") != "/opt/app/bin/server --port 8080" || p.User != "app" || p.Cwd != "/run/app/work" || p.CwdRoot != "/run/app" || p.Umask != 0o27 {
		t.Fatalf("%+v", p)
	}
	if len(p.Caps) != 0 || p.Limits["nofile"] != 1024 || p.Stdout != (Stream{Kind: "file", Path: "/var/log/app/out.log", Root: "/var/log/app"}) || p.Stderr.Kind != "stdout" {
		t.Fatalf("%+v", p)
	}
	secret := false
	for _, e := range p.Env {
		if e.Name == "DB_PASS" && e.Secret && e.Value == "hunter2" {
			secret = true
		}
	}
	if !secret {
		t.Fatalf("secret env %+v", p.Env)
	}
	// The name is taken while it runs.
	if r := s.Handle(spawnReq(t, "main", nil)); r.Error != "name_in_use" {
		t.Fatalf("second main: %+v", r)
	}
	s.Table.Get("main").Exit(0, "", time.Now())
	if r := s.Handle(spawnReq(t, "main", nil)); r.Error != "" {
		t.Fatalf("main after exit: %+v", r)
	}
}

func TestSpawnRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		req  func(t *testing.T) Request
		want string
	}{
		"unlisted program": {func(t *testing.T) Request {
			r := spawnReq(t, "main", nil)
			r.Argv[2] = "/bin/sh"
			return r
		}, "denied"},
		"unclean program": {func(t *testing.T) Request {
			r := spawnReq(t, "main", nil)
			r.Argv[2] = "/opt/app/bin/../bin/server"
			return r
		}, "denied"},
		"shell string": {func(t *testing.T) Request {
			r := spawnReq(t, "main", nil)
			r.Argv[2] = "/opt/app/bin/server;id"
			return r
		}, "denied"},
		"pid name":  {func(t *testing.T) Request { return spawnReq(t, "1234", nil) }, "denied"},
		"root user": {func(t *testing.T) Request { return spawnReq(t, "main", map[string]any{"user": "root", "group": "app"}) }, "denied"},
		"other group": {func(t *testing.T) Request {
			return spawnReq(t, "main", map[string]any{"user": "app", "group": "wheel"})
		}, "denied"},
		"unlisted env": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"env": map[string]any{"HOME": "/"}}))
		}, "env_refused"},
		"denylisted env": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"env": map[string]any{"LD_PRELOAD": "/x.so"}}))
		}, "env_refused"},
		"env number": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"env": map[string]any{"PORT": 1}}))
		}, "denied"},
		"cwd outside": {func(t *testing.T) Request { return spawnReq(t, "main", withID(map[string]any{"cwd": "/etc"})) }, "denied"},
		"cwd unclean": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"cwd": "/run/app/../../etc"}))
		}, "denied"},
		"cwd sibling": {func(t *testing.T) Request { return spawnReq(t, "main", withID(map[string]any{"cwd": "/run/apple"})) }, "denied"},
		"unlisted cap": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"caps": []string{"CAP_KILL"}}))
		}, "denied"},
		"cap allowed": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"caps": []string{"CAP_NET_BIND_SERVICE"}}))
		}, "caps_unsupported"},
		"env nul": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"env": map[string]any{"PORT": "80\x0080"}}))
		}, "denied"},
		"secret nul": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"env": map[string]any{"PORT": map[string]any{"secret": "a\x00b"}}}))
		}, "denied"},
		"env too big": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"env": map[string]any{"PORT": strings.Repeat("x", maxEnvBytes)}}))
		}, "denied"},
		"file is root": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"stdout": "file:/var/log/app"}))
		}, "denied"},
		"cap ceiling": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"caps": []string{"CAP_SYS_ADMIN"}}))
		}, "ceiling"},
		"limit ceiling": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"limits": map[string]any{"core": 1}}))
		}, "ceiling"},
		"limit unknown": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"limits": map[string]any{"rss": 1}}))
		}, "denied"},
		"limit negative": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"limits": map[string]any{"nofile": -1}}))
		}, "denied"},
		"file outside": {func(t *testing.T) Request {
			return spawnReq(t, "main", withID(map[string]any{"stdout": "file:/etc/app/x"}))
		}, "denied"},
		"stdout stdout": {func(t *testing.T) Request { return spawnReq(t, "main", withID(map[string]any{"stdout": "stdout"})) }, "denied"},
		"unknown opt":   {func(t *testing.T) Request { return spawnReq(t, "main", withID(map[string]any{"shell": "x"})) }, "denied"},
		"umask":         {func(t *testing.T) Request { return spawnReq(t, "main", withID(map[string]any{"umask": "0777x"})) }, "denied"},
		"nul arg":       {func(t *testing.T) Request { return spawnReq(t, "main", nil, "a\x00b") }, "denied"},
	} {
		s, h := newServer()
		if resp := s.Handle(c.req(t)); resp.Error != c.want {
			t.Errorf("%s: %+v, want %s", name, resp, c.want)
		}
		if len(h.spawned) != 0 {
			t.Errorf("%s: spawned", name)
		}
	}
	// A host failure frees the name and reports only a token.
	s, h := newServer()
	h.err = errors.New("execve: secret path /x")
	if r := s.Handle(spawnReq(t, "main", nil)); r.Error != "failed" || s.Table.Get("main") != nil {
		t.Fatalf("host failure %+v", r)
	}
}

func TestGrantKeyAndUnsupportedAndCheck(t *testing.T) {
	s, _ := newServer()
	for _, key := range []string{"file.write", "file.read", "ps", "unit.restart", ""} {
		if r := s.Handle(Request{Key: key, Argv: []string{"x"}}); r.Error != "unsupported" {
			t.Errorf("%s: %+v", key, r)
		}
	}
	s.G.Entitlements = []string{"svc.proc"}
	if r := s.Handle(spawnReq(t, "main", nil)); r.Error != "denied" {
		t.Fatalf("spawn without the key: %+v", r)
	}
	s, h := newServer()
	s.Check = true
	if r := s.Handle(spawnReq(t, "main", nil)); r.Error != "check_read_only" || len(h.spawned) != 0 {
		t.Fatalf("spawn in check: %+v", r)
	}
	if r := s.Handle(Request{Key: "svc.signal", Argv: []string{"signal", "main", "TERM"}}); r.Error != "check_read_only" {
		t.Fatalf("signal in check: %+v", r)
	}
	if r := s.Handle(Request{Key: "svc.status", Argv: []string{"service", "status", "postgres"}}); r.Error != "" {
		t.Fatalf("status in check: %+v", r)
	}
}

func TestNamedVerbs(t *testing.T) {
	s, h := newServer()
	if r := s.Handle(spawnReq(t, "main", nil)); r.Error != "" {
		t.Fatal(r)
	}
	p := s.Table.Get("main")
	p.Stdout.Write([]byte("one\ntwo\nthree\n"))
	p.Stderr.Write([]byte("oops\n"))
	r := s.Handle(Request{Key: "svc.proc", Argv: []string{"proc", "main"}})
	if r.Error != "" || r.Rows[0]["state"] != "running" || r.Rows[0]["pid"] != "1001" {
		t.Fatalf("proc %+v", r)
	}
	r = s.Handle(Request{Key: "svc.output", Argv: []string{"output", "main", "tail", "2"}})
	if r.Error != "" || len(r.Rows) != 2 || r.Rows[1]["text"] != "three" {
		t.Fatalf("output %+v", r)
	}
	r = s.Handle(Request{Key: "svc.output", Argv: []string{"output", "main", "stderr"}})
	if r.Error != "" || len(r.Rows) != 1 || r.Rows[0]["text"] != "oops" {
		t.Fatalf("stderr %+v", r)
	}
	if r := s.Handle(Request{Key: "svc.probe", Argv: []string{"probe", "notify", "main"}}); r.Exit != 1 {
		t.Fatalf("notify before ready %+v", r)
	}
	p.SetReady()
	if r := s.Handle(Request{Key: "svc.probe", Argv: []string{"probe", "notify", "main"}}); r.Exit != 0 || r.Error != "" {
		t.Fatalf("notify %+v", r)
	}
	if r := s.Handle(Request{Key: "svc.wait", Argv: []string{"wait", "main", "timeout", "20ms"}}); r.Error != "timeout" {
		t.Fatalf("wait %+v", r)
	}
	if r := s.Handle(Request{Key: "svc.signal", Argv: []string{"signal", "main", "TERM"}}); r.Error != "" || h.signals[0] != "main TERM" {
		t.Fatalf("signal %+v", r)
	}
	r = s.Handle(Request{Key: "svc.wait", Argv: []string{"wait", "main", "timeout", "1s"}})
	if r.Error != "" || r.Rows[0]["signal"] != "TERM" || r.Rows[0]["exit"] != "0" {
		t.Fatalf("wait %+v", r)
	}
	// A signal to an ended process sends nothing.
	if r := s.Handle(Request{Key: "svc.signal", Argv: []string{"signal", "main", "KILL"}}); r.Error != "" || len(h.signals) != 1 {
		t.Fatalf("signal ended %+v %v", r, h.signals)
	}
	for _, a := range [][]string{{"signal", "other", "TERM"}, {"wait", "other", "timeout", "1s"}, {"proc", "other"}, {"output", "other"}} {
		key := map[string]string{"signal": "svc.signal", "wait": "svc.wait", "proc": "svc.proc", "output": "svc.output"}[a[0]]
		if r := s.Handle(Request{Key: key, Argv: a}); r.Error != "unknown_name" {
			t.Errorf("%v: %+v", a, r)
		}
	}
	for _, a := range [][]string{{"signal", "1234", "TERM"}, {"signal", "main", "SEGV"}, {"wait", "main", "timeout", "48h"}, {"output", "main", "tail", "0"}, {"proc", "main", "x"}} {
		key := map[string]string{"signal": "svc.signal", "wait": "svc.wait", "proc": "svc.proc", "output": "svc.output"}[a[0]]
		if r := s.Handle(Request{Key: key, Argv: a}); r.Error != "denied" {
			t.Errorf("%v: %+v", a, r)
		}
	}
	if r := s.Handle(Request{Key: "svc.status", Argv: []string{"service", "status", "postgres"}}); r.Error != "" || r.Rows[0]["state"] != "ready" {
		t.Fatalf("status %+v", r)
	}
	if r := s.Handle(Request{Key: "svc.status", Argv: []string{"service", "status", "nope"}}); r.Error != "unknown_service" {
		t.Fatalf("status unknown %+v", r)
	}
}

func TestProbeRules(t *testing.T) {
	s, h := newServer()
	h.ready["tcp 127.0.0.1:80"] = true
	h.ready["unix /etc/app/sock"] = true
	probe := func(kind, target string) Response {
		return s.Handle(Request{Key: "svc.probe", Argv: []string{"probe", kind, target}})
	}
	if r := probe("tcp", "127.0.0.1:80"); r.Error != "" || r.Exit != 0 {
		t.Fatalf("loopback %+v", r)
	}
	if r := probe("tcp", "127.0.0.1:81"); r.Error != "" || r.Exit != 1 {
		t.Fatalf("not ready %+v", r)
	}
	for _, target := range []string{"10.0.0.1:80", "8.8.8.8:53", "example.com:80", "127.0.0.1:0", "[fe80::1%eth0]:80"} {
		if r := probe("tcp", target); r.Error != "denied" {
			t.Errorf("%s: %+v", target, r)
		}
	}
	s.G.AllowPrivate = true
	if r := probe("tcp", "10.0.0.1:80"); r.Error != "" {
		t.Fatalf("private with allow_private %+v", r)
	}
	if r := probe("tcp", "8.8.8.8:53"); r.Error != "denied" {
		t.Fatalf("public with allow_private %+v", r)
	}
	if r := probe("unix", "/etc/app/sock"); r.Error != "" || r.Exit != 0 {
		t.Fatalf("unix %+v", r)
	}
	for _, p := range []string{"/run/app/sock", "/etc/app/../passwd", "etc/app/sock", "/etc/apple"} {
		if r := probe("file", p); r.Error != "denied" {
			t.Errorf("%s: %+v", p, r)
		}
	}
	if r := probe("notify", "ghost"); r.Error != "unknown_name" {
		t.Fatalf("notify unknown %+v", r)
	}
}

// Serve answers a hello as an agent without mux does, keeps serving, and
// closes on an oversized frame; a secret value is never in a reply.
func TestServeWire(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	s, _ := newServer()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), b, s) }()
	send := func(body string) string {
		t.Helper()
		if err := WriteFrame(a, []byte(body)); err != nil {
			t.Fatal(err)
		}
		out, err := ReadFrame(a)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	if got := send(`{"mux":{"v":1,"max":16}}`); got != `{"error":"frame body"}` {
		t.Fatalf("hello: %s", got)
	}
	body := `{"key":"svc.spawn","argv":["spawn","main","/opt/app/bin/server"],"path":"","body":"` +
		b64(`{"user":"app","group":"app","env":{"HOME":{"secret":"hunter2"}}}`) + `"}`
	if got := send(body); got != `{"error":"env_refused"}` || strings.Contains(got, "hunter2") {
		t.Fatalf("refused secret: %s", got)
	}
	if got := send(`{"key":"file.write","argv":["\u003e","/run/app/x"],"path":"/run/app/x","body":"eA=="}`); got != `{"error":"unsupported"}` {
		t.Fatalf("plain write: %s", got)
	}
	if got := send(`{"key":"svc.proc","argv":["proc","main"],"path":"","body":""}`); got != `{"error":"unknown_name"}` {
		t.Fatalf("proc: %s", got)
	}
	a.Write([]byte{0x7f, 0xff, 0xff, 0xff})
	if err := <-done; err == nil {
		t.Fatal("oversized frame kept the session")
	}
}

func b64(s string) string {
	out, _ := json.Marshal([]byte(s))
	return strings.Trim(string(out), `"`)
}

// A wait blocked on a long-lived process ends when the peer closes the
// socket, when the session's context ends, and at the session's deadline,
// so it cannot hold stop, the cgroup kill or shutdown.
func TestWaitEndsWithTheSession(t *testing.T) {
	for _, how := range []string{"close", "cancel", "deadline"} {
		s, _ := newServer()
		if _, err := s.Table.Reserve("main"); err != nil {
			t.Fatal(err)
		}
		if how == "deadline" {
			s.Deadline = time.Now().Add(100 * time.Millisecond)
		}
		a, b := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, b, s) }()
		if err := WriteFrame(a, []byte(`{"key":"svc.wait","argv":["wait","main","timeout","24h"],"path":"","body":""}`)); err != nil {
			t.Fatal(err)
		}
		switch how {
		case "close":
			time.Sleep(50 * time.Millisecond)
			a.Close()
			b.Close()
		case "cancel":
			time.Sleep(50 * time.Millisecond)
			cancel()
			b.Close()
		case "deadline":
			a.SetReadDeadline(time.Now().Add(2 * time.Second))
			out, err := ReadFrame(a)
			if err != nil || string(out) != `{"error":"timeout"}` {
				t.Fatalf("deadline: %s %v", out, err)
			}
			a.Close()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: Serve still blocked on the wait", how)
		}
		cancel()
	}
}

func TestNameLimitAndOutputMemory(t *testing.T) {
	s, _ := newServer()
	for i := 0; i < MaxNames; i++ {
		if r := s.Handle(spawnReq(t, "p"+strconv.Itoa(i), nil)); r.Error != "" {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	if r := s.Handle(spawnReq(t, "one-more", nil)); r.Error != "too_many_names" {
		t.Fatalf("past the limit: %+v", r)
	}
	// A name already bound may be reused once its process ended.
	s.Table.Get("p0").Exit(0, "", time.Now())
	if r := s.Handle(spawnReq(t, "p0", nil)); r.Error != "" {
		t.Fatalf("reuse: %+v", r)
	}
	// Output past the service's budget drops the oldest lines; it never
	// grows past MaxOutput.
	line := strings.Repeat("y", 1000) + "\n"
	for _, p := range s.Table.All() {
		for i := 0; i < 100; i++ {
			p.Stdout.Write([]byte(line))
		}
	}
	if used := s.Table.Used(); used > MaxOutput || used < MaxOutput/2 {
		t.Fatalf("captured %d bytes", used)
	}
	// An ended process's output is freed once read.
	p := s.Table.Get("p1")
	p.Exit(0, "", time.Now())
	before := s.Table.Used()
	r := s.Handle(Request{Key: "svc.output", Argv: []string{"output", "p1"}})
	if r.Error != "" || len(r.Rows) == 0 || s.Table.Used() >= before {
		t.Fatalf("output %d rows, used %d then %d", len(r.Rows), before, s.Table.Used())
	}
	if r := s.Handle(Request{Key: "svc.output", Argv: []string{"output", "p1"}}); len(r.Rows) != 0 {
		t.Fatalf("read twice: %d rows", len(r.Rows))
	}
	// A running process's output stays.
	s.Handle(Request{Key: "svc.output", Argv: []string{"output", "p2"}})
	if r := s.Handle(Request{Key: "svc.output", Argv: []string{"output", "p2"}}); len(r.Rows) == 0 {
		t.Fatal("running output freed")
	}
	for _, a := range [][]string{{"output", "p2", "x"}, {"output", "p2", "stderr", "tail", "2", "x"}, {"output", "p2", "tail"}} {
		if r := s.Handle(Request{Key: "svc.output", Argv: a}); r.Error != "denied" {
			t.Errorf("%v: %+v", a, r)
		}
	}
}
