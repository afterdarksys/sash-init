// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/cgroup/cgtest"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// The end-to-end tests run a real sash binary (built for Linux from the sash
// repository, branch feat/init-phase1) named by SAHINIT_SASH_BIN, as root,
// with a writable cgroup2: scripts/test-sash-docker.sh builds it and runs
// them in Docker. Without it they are skipped, and say why.

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type sashEnv struct {
	t      *testing.T
	base   string
	sash   string
	self   string
	fleet  ed25519.PrivateKey
	floors *sash.FloorStore
	units  string
	root   *cgroup.Root
}

func e2eKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func copyExec(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(to, 0o755); err != nil {
		t.Fatal(err)
	}
}

func newSashEnv(t *testing.T) *sashEnv {
	t.Helper()
	bin := os.Getenv("SAHINIT_SASH_BIN")
	if bin == "" {
		t.Skip("SAHINIT_SASH_BIN is not set: scripts/test-sash-docker.sh builds sash and runs these")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to run sash as uid 65534")
	}
	cgdir := cgtest.Dir(t)
	base, err := os.MkdirTemp("/tmp", "sahsash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	e := &sashEnv{t: t, base: base, fleet: e2eKey("sahinit e2e fleet")}
	for _, d := range []string{"", "bin", "services", "grants", "units"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(base, d), 0o755)
	}
	if err := os.Mkdir(filepath.Join(base, "floors"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.units = filepath.Join(base, "units")
	e.sash = filepath.Join(base, "bin", "sash")
	copyExec(t, bin, e.sash)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	e.self = filepath.Join(base, "bin", "sahinit")
	copyExec(t, self, e.self)
	e.floors, err = sash.OpenFloorStore(filepath.Join(base, "floors"), e.fleet.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.floors.Close() })
	e.root, err = cgroup.Open(cgdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.root.Close() })
	return e
}

// add writes a service file, a grant and a unit for name.
func (e *sashEnv) add(name, script string, g sash.Grant, key ed25519.PrivateKey) {
	t := e.t
	t.Helper()
	file := filepath.Join(e.base, "services", name+".sash")
	if err := os.WriteFile(file, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := sash.SignGrant(g, key)
	if err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(e.base, "grants", name+".grant")
	if err := os.WriteFile(grant, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := json.Marshal(map[string]any{
		"name": name, "sash": map[string]any{"file": file, "grant": grant},
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": []string{"/"}},
	})
	if err := os.WriteFile(filepath.Join(e.units, name+".json"), u, 0o644); err != nil {
		t.Fatal(err)
	}
}

// load loads the catalog, describes each sash unit as supervise does, and
// returns a supervisor with the rest, and the refusals by unit.
func (e *sashEnv) load(log *syncBuf) (*Supervisor, map[string]string) {
	t := e.t
	t.Helper()
	svcs, refused, err := unit.Load(e.units)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) != 0 {
		t.Fatalf("refused at load: %v", refused)
	}
	out := map[string]string{}
	lu, lg := LookupIDs()
	for name, svc := range svcs {
		d, err := Describe(context.Background(), e.root, e.self, e.sash, svc)
		if err == nil {
			err = unit.ApplyDescribe(svc, d, lu, lg)
		}
		if err != nil {
			if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
				t.Skipf("kernel lacks sandbox: %v", err)
			}
			out[name] = fail.Token(err)
			delete(svcs, name)
		}
	}
	sup, err := New(svcs, e.self)
	if err != nil {
		t.Fatal(err)
	}
	sup.Cgroups, sup.Log = e.root, log
	sup.Sash = &SashConfig{Binary: e.sash, Fleet: e.fleet.Public().(ed25519.PublicKey), Floors: e.floors, StateDir: filepath.Join(e.base, "floors")}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := sup.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return sup, out
}

func e2eGrant(name string, exec []string, env []string) sash.Grant {
	g := sash.SampleGrant(name, "nobody", "nogroup")
	g.Exec, g.EnvNames, g.Serial = exec, env, 5
	return g
}

const appScript = `service {
  name app
  user nobody
  group nogroup
  ready notify timeout 10s
  stop signal TERM timeout 5s
}

fn start() {
  declare -s token = "s3cr3t-e2e-value"
  spawn main /bin/sh "-c" "printf x >&3; exec /usr/bin/sleep 300" opts [ {"env": {"PORT": "8080", "TOKEN": $token}, "stdout": "journal"} ]
}

fn stop() {
  signal main TERM
  try { wait main timeout 5s } catch e { signal main KILL }
}

fn check() {
  probe notify main
}
`

func refusalScript(name, spawn string) string {
	return "service {\n  name " + name + "\n  user nobody\n  group nogroup\n}\n\nfn start() {\n  " + spawn + "\n}\n"
}

func environOf(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(raw), "\x00", " ")
}

func cgroupOf(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func TestSashServiceEndToEnd(t *testing.T) {
	e := newSashEnv(t)
	e.add("app", appScript, e2eGrant("app", []string{"/bin/sh"}, []string{"PORT", "TOKEN"}), e.fleet)
	e.add("runner", "service {\n  name runner\n  user nobody\n  group nogroup\n  run /usr/bin/sleep 300\n}\n", e2eGrant("runner", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("describe refused %v", refused)
	}
	ctx := t.Context()
	if err := sup.Start(ctx, "app"); err != nil {
		t.Fatalf("start: %v (log %s) %+v", err, log.String(), rowOf(t, sup, "app"))
	}
	row := rowOf(t, sup, "app")
	if row.State != "running" || !row.Ready || row.Sash == nil || row.Sash.Serial != 5 || row.Sash.Entry != "start" || len(row.Sash.Procs) != 1 {
		t.Fatalf("row %+v %+v", row, row.Sash)
	}
	main := row.Sash.Procs[0]
	if main.Name != "main" || main.State != "running" || main.Pid <= 0 {
		t.Fatalf("main %+v", main)
	}
	if cg := cgroupOf(t, main.Pid); !strings.HasSuffix(cg, "/app.service") {
		t.Fatalf("main is in %s", cg)
	}
	env := environOf(t, main.Pid)
	if !strings.Contains(env, "TOKEN=s3cr3t-e2e-value") || !strings.Contains(env, "PORT=8080") || strings.Contains(env, "SAHINIT_SASH") {
		t.Fatalf("child env %q", env)
	}
	// The secret is in the child's environment and nowhere else.
	status, _ := json.Marshal(row)
	diag, _ := sup.Diagnostics("app")
	diagJSON, _ := json.Marshal(diag)
	for what, text := range map[string]string{"status": string(status), "diagnostics": string(diagJSON), "log": log.String()} {
		if strings.Contains(text, "s3cr3t") {
			t.Errorf("secret in %s", what)
		}
	}
	// check runs read-only and passes while main is ready.
	if err := sup.Check(ctx, "app"); err != nil {
		t.Fatalf("check: %v", err)
	}
	// The declarative run entry spawns main itself.
	if err := sup.Start(ctx, "runner"); err != nil {
		t.Fatalf("runner: %v", err)
	}
	if r := rowOf(t, sup, "runner"); r.State != "running" || r.Sash.Entry != "run" || len(r.Sash.Procs) != 1 || r.Sash.Procs[0].Name != "main" {
		t.Fatalf("runner %+v %+v", r, r.Sash)
	}
	// stop runs the stop entry, then the cgroup is killed and removed.
	if err := sup.Stop(ctx, "app"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	row = rowOf(t, sup, "app")
	if row.State != "stopped" {
		t.Fatalf("after stop %+v", row)
	}
	if !gone(main.Pid) {
		t.Fatal("main still runs")
	}
	if p := row.Sash.Procs[0]; p.State != "exited" || p.Signal != "TERM" {
		t.Fatalf("main ended %+v", p)
	}
	if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", e.root.Path("app"))); err == nil {
		t.Fatal("cgroup left")
	}
	stopped := false
	for _, en := range row.Sash.Entries {
		stopped = stopped || en.Entry == "stop" && en.Exit == 0
	}
	if !stopped {
		t.Fatalf("stop entry %+v", row.Sash.Entries)
	}
	// A runner whose process is killed from outside ends the service; the
	// policy (never) does not restart it, and the cgroup is gone.
	rr := rowOf(t, sup, "runner")
	if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", rr.Cgroup, "cgroup.kill"), []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for rowOf(t, sup, "runner").State == "running" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r := rowOf(t, sup, "runner"); r.State != "failed" || r.Restarts != 0 {
		t.Fatalf("runner after kill %+v", r)
	}
}

// sash refuses these itself and its start entry exits 2: a configuration
// error, so the unit is failed and not restarted, and the token is logged.
// The grant refusals are sahinit's, before sash runs.
func TestSashRefusalsEndToEnd(t *testing.T) {
	e := newSashEnv(t)
	other := e2eKey("not the fleet")
	cases := map[string]struct {
		script string
		g      sash.Grant
		key    ed25519.PrivateKey
		want   string
	}{
		"unlisted":  {refusalScript("unlisted", `spawn main /usr/bin/sleep 300`), e2eGrant("unlisted", []string{"/bin/sh"}, []string{}), e.fleet, "sash_config"},
		"rootspawn": {refusalScript("rootspawn", `spawn main /usr/bin/sleep 300 opts [ {"user": "root"} ]`), e2eGrant("rootspawn", []string{"/usr/bin/sleep"}, []string{}), e.fleet, "sash_config"},
		"badenv":    {refusalScript("badenv", `spawn main /usr/bin/sleep 300 opts [ {"env": {"LD_PRELOAD": "/x.so"}} ]`), e2eGrant("badenv", []string{"/usr/bin/sleep"}, []string{"LD_PRELOAD"}), e.fleet, "sash_config"},
		"badcwd":    {refusalScript("badcwd", `spawn main /usr/bin/sleep 300 opts [ {"cwd": "/etc"} ]`), e2eGrant("badcwd", []string{"/usr/bin/sleep"}, []string{}), e.fleet, "sash_config"},
		"badsig":    {refusalScript("badsig", `spawn main /usr/bin/sleep 300`), e2eGrant("badsig", []string{"/usr/bin/sleep"}, []string{}), other, "grant_bad_sig"},
		"wrongsvc":  {refusalScript("wrongsvc", `spawn main /usr/bin/sleep 300`), e2eGrant("elsewhere", []string{"/usr/bin/sleep"}, []string{}), e.fleet, "grant_service_mismatch"},
		"revoked":   {refusalScript("revoked", `spawn main /usr/bin/sleep 300`), e2eGrant("revoked", []string{"/usr/bin/sleep"}, []string{}), e.fleet, "sash_grant_revoked"},
	}
	for name, c := range cases {
		e.add(name, c.script, c.g, c.key)
	}
	e.add("misnamed", refusalScript("other", `spawn main /usr/bin/sleep 300`), e2eGrant("misnamed", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	if _, err := e.floors.Install(sash.SignFloor(sash.Floor{Version: sash.FloorVersion, Service: "revoked", MinSerial: 6, IssuedAt: 1}, e.fleet)); err != nil {
		t.Fatal(err)
	}
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 1 || refused["misnamed"] != "sash_name_mismatch" {
		t.Fatalf("describe refusals %v", refused)
	}
	for name, c := range cases {
		err := sup.Start(t.Context(), name)
		row := rowOf(t, sup, name)
		if fail.Token(err) != c.want || row.State != "failed" || row.LastError != c.want || row.Restarts != 0 {
			t.Errorf("%s: %v %+v, want %s", name, err, row, c.want)
		}
		if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", e.root.Path(name))); err == nil {
			t.Errorf("%s: cgroup left", name)
		}
	}
	if !strings.Contains(log.String(), "sash_entry_error unlisted start") {
		t.Errorf("no entry error logged: %s", log.String())
	}
}

// sahinit re-checks every spawn itself: these requests reach the verb
// server as a misbehaving sash would send them, with the real host, and are
// refused; a good one spawns into the service cgroup.
func TestSashHostRechecks(t *testing.T) {
	e := newSashEnv(t)
	e.add("app", appScript, e2eGrant("app", []string{"/bin/sh"}, []string{"PORT", "TOKEN"}), e.fleet)
	var log syncBuf
	sup, _ := e.load(&log)
	s := sup.rt["app"]
	g := e2eGrant("app", []string{"/usr/bin/sleep", "/tmp/sahinit-not-trusted"}, []string{"PORT", "LD_PRELOAD"})
	work := filepath.Join(e.base, "work")
	os.Mkdir(work, 0o755)
	os.Chown(work, 65534, 65534)
	os.Symlink("/etc", filepath.Join(work, "link"))
	// A root-only file under file_write: sahinit is root, the child is not.
	if err := os.WriteFile(filepath.Join(work, "root.log"), []byte("root only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.FileRead, g.FileWrite = []string{"/usr"}, []string{work}
	grp, err := e.root.Prepare("app", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grp.Close()
	t.Cleanup(func() { e.root.KillAll("app", time.Second) })
	srv := &sash.Server{G: g, Table: s.sashTable(), Host: &sashHost{sup: sup, s: s}, CapCeiling: nil}
	spawn := func(name, prog string, opts map[string]any) sash.Response {
		b, _ := json.Marshal(opts)
		return srv.Handle(sash.Request{Key: "svc.spawn", Argv: []string{"spawn", name, prog, "300"}, Body: b})
	}
	id := func(o map[string]any) map[string]any {
		if o == nil {
			o = map[string]any{}
		}
		if _, ok := o["user"]; !ok {
			o["user"] = "nobody"
		}
		o["group"] = "nogroup"
		return o
	}
	untrusted := "/tmp/sahinit-not-trusted"
	copyExec(t, "/usr/bin/sleep", untrusted)
	os.Chmod(untrusted, 0o777)
	t.Cleanup(func() { os.Remove(untrusted) })
	for name, c := range map[string]struct {
		prog string
		opts map[string]any
		want string
	}{
		"unlisted":         {"/bin/sh", id(nil), "denied"},
		"untrusted file":   {untrusted, id(nil), "denied"},
		"root":             {"/usr/bin/sleep", id(map[string]any{"user": "root"}), "denied"},
		"env":              {"/usr/bin/sleep", id(map[string]any{"env": map[string]any{"LD_PRELOAD": "/x"}}), "env_refused"},
		"cwd outside":      {"/usr/bin/sleep", id(map[string]any{"cwd": "/etc"}), "denied"},
		"cwd symlink":      {"/usr/bin/sleep", id(map[string]any{"cwd": work + "/link"}), "denied"},
		"stream symlink":   {"/usr/bin/sleep", id(map[string]any{"stdout": "file:" + work + "/link/x"}), "denied"},
		"stream root file": {"/usr/bin/sleep", id(map[string]any{"stdout": "file:" + work + "/root.log"}), "denied"},
	} {
		if r := spawn("p-"+strings.ReplaceAll(name, " ", "-"), c.prog, c.opts); r.Error != c.want {
			t.Errorf("%s: %+v, want %s", name, r, c.want)
		}
	}
	// A grant whose identity names another account than the unit's uid
	// and gid passes the grant check, and the host refuses it.
	srv.G.User, srv.G.Group = "daemon", "daemon"
	if r := spawn("p-daemon", "/usr/bin/sleep", map[string]any{"user": "daemon", "group": "daemon"}); r.Error != "denied" {
		t.Errorf("another account: %+v", r)
	}
	srv.G.User, srv.G.Group = "nobody", "nogroup"
	r := spawn("good", "/usr/bin/sleep", id(map[string]any{"cwd": work, "stdout": "file:" + work + "/out.log", "env": map[string]any{"PORT": "1"}}))
	if r.Error != "" {
		t.Fatalf("good spawn %+v", r)
	}
	pid, _ := strconv.Atoi(r.Rows[0]["pid"])
	if cg := cgroupOf(t, pid); !strings.HasSuffix(cg, "/app.service") {
		t.Fatalf("spawned into %s", cg)
	}
	// No limit was asked for, and the child still has no core dumps.
	if raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/limits"); err != nil || !regexp.MustCompile(`Max core file size\s+0\s+0\s`).Match(raw) {
		t.Fatalf("core limit: %s %v", raw, err)
	}
	if st, err := os.Stat(work + "/out.log"); err != nil || st.Mode().Perm() != 0o640 || st.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Fatalf("stream file %v %v", st, err)
	}
	if r := srv.Handle(sash.Request{Key: "svc.signal", Argv: []string{"signal", "good", "KILL"}}); r.Error != "" {
		t.Fatalf("signal %+v", r)
	}
	if r := srv.Handle(sash.Request{Key: "svc.wait", Argv: []string{"wait", "good", "timeout", "5s"}}); r.Error != "" || r.Rows[0]["signal"] != "KILL" {
		t.Fatalf("wait %+v", r)
	}
	waitGone(t, pid)
}

// The service block's restart policy, delay and burst apply: a start that
// exits 1 is retried until the burst is spent; a service whose processes
// die is started again.
func TestSashRestartPolicyEndToEnd(t *testing.T) {
	e := newSashEnv(t)
	e.add("flaky", "service {\n  name flaky\n  user nobody\n  group nogroup\n  restart on-failure delay 100ms burst 2 within 60s\n}\n\nfn start() {\n  exit 1\n}\n",
		e2eGrant("flaky", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	e.add("phoenix", "service {\n  name phoenix\n  user nobody\n  group nogroup\n  run /usr/bin/sleep 300\n  restart on-failure delay 100ms burst 3 within 60s\n}\n",
		e2eGrant("phoenix", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	if err := sup.Start(t.Context(), "flaky"); fail.Token(err) != "failed" {
		t.Fatalf("flaky start: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := rowOf(t, sup, "flaky")
		if r.State == "failed" && r.LastError == "restart_limit" {
			if r.Restarts != 2 {
				t.Fatalf("restarts %+v", r)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flaky %+v", r)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := sup.Start(t.Context(), "phoenix"); err != nil {
		t.Fatal(err)
	}
	first := rowOf(t, sup, "phoenix").Sash.Procs[0].Pid
	if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", rowOf(t, sup, "phoenix").Cgroup, "cgroup.kill"), []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		r := rowOf(t, sup, "phoenix")
		if r.State == "running" && r.Restarts == 1 && len(r.Sash.Procs) == 1 && r.Sash.Procs[0].Pid != first && r.Sash.Procs[0].State == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("phoenix %+v %+v", r, r.Sash)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A start blocked in a long wait (the verb server holding it) does not hold
// stop: stop ends the session and kills the cgroup at once.
func TestSashStopDuringBlockedWait(t *testing.T) {
	e := newSashEnv(t)
	e.add("hang", "service {\n  name hang\n  user nobody\n  group nogroup\n}\n\nfn start() {\n  spawn main /usr/bin/sleep 300\n  wait main timeout 24h\n}\n",
		e2eGrant("hang", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	started := make(chan error, 1)
	go func() { started <- sup.Start(context.Background(), "hang") }()
	var pid int
	deadline := time.Now().Add(10 * time.Second)
	for pid == 0 {
		if r := rowOf(t, sup, "hang"); r.Sash != nil && len(r.Sash.Procs) == 1 && r.Sash.Procs[0].Pid > 0 {
			pid = r.Sash.Procs[0].Pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("main never spawned: %+v", rowOf(t, sup, "hang"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // sash is now in wait
	begin := time.Now()
	if err := sup.Stop(t.Context(), "hang"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if took := time.Since(begin); took > 10*time.Second {
		t.Fatalf("stop took %v", took)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("start still blocked")
	}
	waitGone(t, pid)
	if r := rowOf(t, sup, "hang"); r.State != "stopped" {
		t.Fatalf("after stop %+v", r)
	}
	if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", e.root.Path("hang"))); err == nil {
		t.Fatal("cgroup left")
	}
}

// Describe reads at most 1 MiB: a valid document followed by more output
// than that is sash_describe, though the first MiB alone would parse. A
// fake sash stands in, so this runs without SAHINIT_SASH_BIN.
func TestDescribeOutputCap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to run describe as uid 65534")
	}
	r, err := cgroup.Open(cgtest.Dir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	base, err := os.MkdirTemp("/tmp", "sahdesc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	os.Chmod(base, 0o755)
	self := filepath.Join(base, "sahinit")
	exe, _ := os.Executable()
	copyExec(t, exe, self)
	doc := `{"v":"sash-describe/1","service":{"name":"app","description":"","requires":[],"after":[],"wants":[],"user":"nobody","group":"nogroup","run":[],"ready":null,"stop":null,"restart":null},"entries":["start"],"needs":{},"complete":true}`
	uid := uint32(65534)
	svc := &unit.Service{Name: "app", Sandbox: &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}, Execution: unit.Execution{UID: &uid, GID: &uid},
		Sash: &unit.Sash{File: filepath.Join(base, "app.sash")}}
	for _, c := range []struct {
		pad  int
		want string
	}{{0, ""}, {sash.MaxDescribe, "sash_describe"}} {
		fake := filepath.Join(base, "sash"+strconv.Itoa(c.pad))
		script := "#!/bin/sh\nprintf '%s' '" + doc + "'\n"
		if c.pad > 0 {
			script += "head -c " + strconv.Itoa(c.pad) + " /dev/zero | tr '\\000' ' '\n"
		}
		if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		d, err := Describe(context.Background(), r, self, fake, svc)
		if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
			t.Skipf("kernel lacks sandbox: %v", err)
		}
		if fail.Token(err) != c.want || (c.want == "" && (d == nil || d.Name != "app")) {
			t.Errorf("pad %d: %v %+v, want %q", c.pad, err, d, c.want)
		}
	}
}

// Stop interrupts a start waiting on readiness (a tcp port nobody opens)
// at once, and kills the cgroup.
func TestSashStopDuringReadyWait(t *testing.T) {
	e := newSashEnv(t)
	e.add("never", "service {\n  name never\n  user nobody\n  group nogroup\n  ready tcp 127.0.0.1:1 timeout 60s\n}\n\nfn start() {\n  spawn main /usr/bin/sleep 300\n}\n",
		e2eGrant("never", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	started := make(chan error, 1)
	go func() { started <- sup.Start(context.Background(), "never") }()
	pid := waitMain(t, sup, "never")
	time.Sleep(300 * time.Millisecond) // the start session ended; readiness is polled
	begin := time.Now()
	if err := sup.Stop(t.Context(), "never"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if took := time.Since(begin); took > 3*time.Second {
		t.Fatalf("stop took %v", took)
	}
	<-started
	waitGone(t, pid)
	if r := rowOf(t, sup, "never"); r.State != "stopped" {
		t.Fatalf("after stop %+v", r)
	}
	if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", e.root.Path("never"))); err == nil {
		t.Fatal("cgroup left")
	}
}

// Stop interrupts a reload session that holds the service (a long wait):
// the reload's sash is killed, the stop entry then runs, and the cgroup is
// killed.
func TestSashStopDuringReload(t *testing.T) {
	e := newSashEnv(t)
	e.add("slow", "service {\n  name slow\n  user nobody\n  group nogroup\n}\n\nfn start() {\n  spawn main /usr/bin/sleep 300\n}\n\nfn reload() {\n  wait main timeout 1h\n}\n\nfn stop() {\n  signal main TERM\n}\n",
		e2eGrant("slow", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	if err := sup.Start(t.Context(), "slow"); err != nil {
		t.Fatal(err)
	}
	pid := waitMain(t, sup, "slow")
	reloaded := make(chan error, 1)
	go func() { reloaded <- sup.Reload(context.Background(), "slow") }()
	time.Sleep(500 * time.Millisecond) // sash is in wait
	if gone(pid) {
		t.Fatal("main ended before stop")
	}
	begin := time.Now()
	if err := sup.Stop(t.Context(), "slow"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if took := time.Since(begin); took > 5*time.Second {
		t.Fatalf("stop took %v", took)
	}
	if err := <-reloaded; err == nil {
		t.Fatal("interrupted reload succeeded")
	}
	waitGone(t, pid)
	r := rowOf(t, sup, "slow")
	if r.State != "stopped" || r.Sash.Procs[0].Signal != "TERM" {
		t.Fatalf("after stop %+v %+v", r, r.Sash.Procs)
	}
}

func waitMain(t *testing.T, sup *Supervisor, name string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if r := rowOf(t, sup, name); r.Sash != nil && len(r.Sash.Procs) == 1 && r.Sash.Procs[0].Pid > 0 {
			return r.Sash.Procs[0].Pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("main never spawned: %+v", rowOf(t, sup, name))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A sash entry's first stderr word is the service's own: it is kept as the
// entry's token and the sash_start event's code, and never becomes
// last_error or explain's reason, which stay sahinit's codes. Here the
// script runs a name spelled like a catalog code.
func TestSashServiceWordIsNotACode(t *testing.T) {
	e := newSashEnv(t)
	e.add("worder", refusalScript("worder", "root_required"), e2eGrant("worder", []string{"/usr/bin/sleep"}, []string{}), e.fleet)
	var log syncBuf
	sup, refused := e.load(&log)
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	err := sup.Start(t.Context(), "worder")
	row := rowOf(t, sup, "worder")
	ex, xerr := sup.Explain("worder")
	d, derr := sup.Diagnostics("worder")
	if xerr != nil || derr != nil || row.Sash == nil || len(row.Sash.Entries) != 1 {
		t.Fatalf("%v %v %+v", xerr, derr, row)
	}
	tok := row.Sash.Entries[0].Token
	t.Logf("start: err %v, last_error %q, reason %q, entry token %q, exit %d", err, row.LastError, ex.Reason, tok, row.Sash.Entries[0].Exit)
	if _, ok := fail.Lookup(row.LastError); !ok || row.LastError != fail.Token(err) || ex.Reason != row.LastError {
		t.Fatalf("last_error %q reason %q err %v: not sahinit's code", row.LastError, ex.Reason, err)
	}
	if tok == "" || tok == row.LastError {
		t.Fatalf("the service's word %q is not kept apart from last_error %q", tok, row.LastError)
	}
	found := false
	for _, ev := range d.Events {
		if ev.Kind == "sash_start" && ev.Code == tok {
			found = true
		}
	}
	if !found {
		t.Fatalf("no sash_start event carrying the service's word: %+v", d.Events)
	}
}
