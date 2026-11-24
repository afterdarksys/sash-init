package supervise

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// grantSup is a supervisor with one sash unit, app, whose grant file holds
// doc, and a floor store; nothing is started.
func grantSup(t *testing.T, doc []byte) (*Supervisor, *runtime, *sash.FloorStore, ed25519.PrivateKey) {
	t.Helper()
	fleet := testKey("fleet")
	dir := t.TempDir()
	file, grant := filepath.Join(dir, "app.sash"), filepath.Join(dir, "app.grant")
	if err := os.WriteFile(file, []byte("service {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grant, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	floors := filepath.Join(dir, "floors")
	if err := os.Mkdir(floors, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := sash.OpenFloorStore(floors, fleet.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	uid, gid := uint32(990), uint32(990)
	svc := &unit.Service{Name: "app", Type: "simple", Restart: "no", Timeout: unit.DefaultTimeout, Sandbox: &unit.Sandbox{NoNewPrivs: true},
		Execution: unit.Execution{UID: &uid, GID: &gid},
		Sash:      &unit.Sash{File: file, Grant: grant, Desc: &sash.Description{Name: "app", User: "app", Group: "app", Entries: []string{"start"}}}}
	sup := mustSup(t, map[string]*unit.Service{"app": svc})
	sup.Sash = &SashConfig{Binary: "/bin/sh", Fleet: fleet.Public().(ed25519.PublicKey), Floors: store, Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	return sup, sup.rt["app"], store, fleet
}

func signed(t *testing.T, g sash.Grant, k ed25519.PrivateKey) []byte {
	t.Helper()
	doc, err := sash.SignGrant(g, k)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// Before every session sahinit verifies the grant file itself: the fleet
// key, this service, the identity describe gave, exp, and the floor.
func TestLoadGrantBindings(t *testing.T) {
	good := sash.SampleGrant("app", "app", "app")
	good.Serial = 5
	sup, s, store, fleet := grantSup(t, signed(t, good, testKey("fleet")))
	g, doc, err := sup.loadGrant(s.svc)
	if err != nil || g.Serial != 5 || len(doc) == 0 {
		t.Fatalf("%+v %v", g, err)
	}
	for name, c := range map[string]struct {
		edit func(*sash.Grant)
		key  ed25519.PrivateKey
		want string
	}{
		"other key": {nil, testKey("other"), "grant_bad_sig"},
		"service": {func(g *sash.Grant) {
			g.Service, g.Actor = "web", "service:web"
		}, fleet, "grant_service_mismatch"},
		"user":    {func(g *sash.Grant) { g.User = "www" }, fleet, "grant_identity_mismatch"},
		"group":   {func(g *sash.Grant) { g.Group = "www" }, fleet, "grant_identity_mismatch"},
		"expired": {func(g *sash.Grant) { g.Exp = 1_600_000_000 }, fleet, "grant_expired"},
	} {
		g := good
		if c.edit != nil {
			c.edit(&g)
		}
		if err := os.WriteFile(s.svc.Sash.Grant, signed(t, g, c.key), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := sup.loadGrant(s.svc); fail.Token(err) != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
	if err := os.WriteFile(s.svc.Sash.Grant, signed(t, good, fleet), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Install(sash.SignFloor(sash.Floor{Version: sash.FloorVersion, Service: "app", MinSerial: 6, IssuedAt: 1}, fleet)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sup.loadGrant(s.svc); fail.Token(err) != "sash_grant_revoked" {
		t.Fatalf("below floor: %v", err)
	}
	// A grant file that became readable by others is refused before it is
	// read.
	if err := os.Chmod(s.svc.Sash.Grant, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sup.loadGrant(s.svc); fail.Token(err) != "sash_grant_perm" {
		t.Fatalf("grant mode: %v", err)
	}
	// No sash configuration, no start.
	sup.Sash = nil
	if _, _, err := sup.loadGrant(s.svc); fail.Token(err) != "sash_unavailable" {
		t.Fatalf("no config: %v", err)
	}
}

// A start whose grant fails is failed, not restarted, even with restart
// always; nothing is launched.
func TestSashGrantFailureIsNotRestarted(t *testing.T) {
	g := sash.SampleGrant("app", "app", "app")
	sup, s, _, _ := grantSup(t, signed(t, g, testKey("other")))
	s.svc.Restart = "always"
	err := sup.Start(t.Context(), "app")
	row := rowOf(t, sup, "app")
	if fail.Token(err) != "grant_bad_sig" || row.State != "failed" || row.LastError != "grant_bad_sig" || row.Restarts != 0 {
		t.Fatalf("%v %+v", err, row)
	}
	time.Sleep(50 * time.Millisecond)
	if row := rowOf(t, sup, "app"); row.State != "failed" {
		t.Fatalf("restarted: %+v", row)
	}
}

// svc.status reads any service's row: ready when running and ready; the
// status row of a sash unit shows the name table and serial, never the
// grant body or an env value.
func TestSashStatusRows(t *testing.T) {
	g := sash.SampleGrant("app", "app", "app")
	sup, s, _, _ := grantSup(t, signed(t, g, testKey("fleet")))
	s.mu.Lock()
	s.state, s.ready, s.pid = "running", true, 0
	s.eventLocked("ready", "", nil)
	s.sash = &sashState{table: sash.NewTable(), serial: 9, entries: map[string]EntryResult{}}
	s.mu.Unlock()
	p, _ := s.sash.table.Reserve("main")
	p.Started(4242, time.Unix(1_700_000_000, 0), nil)
	s.recordEntry("start", 0, "")
	row, err := sup.statusRow("app")
	if err != nil || row["state"] != "ready" || row["name"] != "app" || row["since"] == "" {
		t.Fatalf("%v %v", row, err)
	}
	if _, err := sup.statusRow("nope"); fail.Token(err) != "unknown_service" {
		t.Fatalf("unknown: %v", err)
	}
	r := rowOf(t, sup, "app")
	if r.Sash == nil || r.Sash.Serial != 9 || r.Sash.Entry != "start" || len(r.Sash.Procs) != 1 || r.Sash.Procs[0].Pid != 4242 || len(r.Sash.Entries) != 1 {
		t.Fatalf("%+v", r.Sash)
	}
	raw, _ := json.Marshal(r)
	for _, bad := range []string{`"sig"`, "lease_id", "entitlements", "env"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("status holds %s: %s", bad, raw)
		}
	}
	p.Exit(0, "", time.Now())
}

func TestSashEntryRefusals(t *testing.T) {
	g := sash.SampleGrant("app", "app", "app")
	sup, s, _, _ := grantSup(t, signed(t, g, testKey("fleet")))
	if err := sup.Reload(t.Context(), "app"); fail.Token(err) != "no_entry" {
		t.Fatalf("reload without the entry: %v", err)
	}
	s.svc.Sash.Desc.Entries = []string{"start", "check"}
	if err := sup.Check(t.Context(), "app"); fail.Token(err) != "not_running" {
		t.Fatalf("check while stopped: %v", err)
	}
	if err := sup.Check(t.Context(), "nope"); fail.Token(err) != "not_found" {
		t.Fatalf("unknown: %v", err)
	}
}

// A service's journal lines reach sahinit's log at most at the bucket's
// rate; the rest are dropped and counted.
func TestJournalRateLimit(t *testing.T) {
	g := sash.SampleGrant("app", "app", "app")
	sup, s, _, _ := grantSup(t, signed(t, g, testKey("fleet")))
	var log syncLog
	sup.Log = &log
	now := time.Unix(1_700_000_000, 0)
	s.journal = newLineBucket(func() time.Time { return now })
	for i := 0; i < 1000; i++ {
		sup.journalLine(s, "main", "stdout", "line\x1b")
	}
	if n := strings.Count(log.String(), "sash_output app main stdout: line?\n"); n != journalBurst {
		t.Fatalf("%d lines logged, want %d", n, journalBurst)
	}
	now = now.Add(time.Second)
	sup.journalLine(s, "main", "stdout", "again")
	if !strings.Contains(log.String(), "sash_output_dropped app 800\n") || !strings.HasSuffix(log.String(), "sash_output app main stdout: again\n") {
		t.Fatalf("log tail %q", log.String()[len(log.String())-120:])
	}
}

type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
