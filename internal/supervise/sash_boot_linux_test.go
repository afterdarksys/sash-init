// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/cgroup/cgtest"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// fakeBootSash is a boot-ops unit's supervisor with a fake sash binary
// that runs script, and a real cgroup root: the paths below run a real
// session, as root. The fake talks to the verb server on fd 6 (the fourth
// passed fd, after the grant, the fleet key and the emergency key) in the
// wire's frames: four length bytes, then one JSON object.
func fakeBootSash(t *testing.T, script string) (*Supervisor, *runtime) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to run sash as uid 65534")
	}
	root, err := cgroup.Open(cgtest.Dir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	base, err := os.MkdirTemp("/tmp", "sahboot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	os.Chmod(base, 0o755)
	self, fake := filepath.Join(base, "sahinit"), filepath.Join(base, "sash")
	exe, _ := os.Executable()
	copyExec(t, exe, self)
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	file, grant := filepath.Join(base, "app.sash"), filepath.Join(base, "app.grant")
	if err := os.WriteFile(file, []byte("service {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fleet := testKey("fleet")
	g := sash.SampleBootGrant("app", "nobody", "nogroup")
	g.Host, g.Exec, g.Serial = "web1", []string{"/bin/sleep"}, 5
	if err := os.WriteFile(grant, signed(t, g, fleet), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "floors"), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := sash.OpenFloorStore(filepath.Join(base, "floors"), fleet.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	uid := uint32(65534)
	svc := &unit.Service{Name: "app", Type: "simple", Restart: "no", Timeout: unit.DefaultTimeout,
		Sandbox:   &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}},
		Execution: unit.Execution{UID: &uid, GID: &uid},
		Sash: &unit.Sash{File: file, Grant: grant, BootOps: true,
			Desc: &sash.Description{Name: "app", User: "nobody", Group: "nogroup", Entries: []string{"start", "stop", "reload", "check"}}}}
	sup, err := New(map[string]*unit.Service{"app": svc}, self)
	if err != nil {
		t.Fatal(err)
	}
	sup.Cgroups = root
	sup.Sash = &SashConfig{Binary: fake, Fleet: fleet.Public().(ed25519.PublicKey), Floors: store, HostID: "web1",
		StateDir: filepath.Join(base, "floors"), Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	t.Cleanup(func() {
		sup.Shutdown(t.Context())
	})
	return sup, sup.rt["app"]
}

// sendFrame is the fake's shell function: one request of the given JSON
// object as a frame on fd 6.
const sendFrame = `send() { n=${#1}; printf "\\000\\000\\000\\$(printf '%03o' $n)%s" "$1" >&6; }
`

// A boot verb is served in a start session only: a stop, reload or check
// session that sends one is refused boot_entry, through the real session()
// that builds the verb server from the entry it runs.
func TestSessionRefusesBootVerbsOutsideStart(t *testing.T) {
	sup, s := fakeBootSash(t, "#!/bin/sh\n"+sendFrame+
		`send '{"key":"boot.start","argv":["x"],"path":"","body":""}'
dd bs=65536 count=1 <&6 2>&- | tr -d '\000-\037\177-\377' | sed -n 's/.*"error":"\([a-z_]*\)".*/\1/p' >&2
`)
	g, doc, err := sup.loadGrant(s.svc)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"start", "stop", "reload", "check"} {
		grp, err := sup.Cgroups.Prepare("app", s.svc.Limits, timeoutOf(s.svc))
		if err != nil {
			t.Fatal(err)
		}
		code, tok := sup.session(t.Context(), s, entry, entry == "check", 20*time.Second, g, doc, grp)
		grp.Close()
		if tok == "" || code != 0 {
			t.Fatalf("%s: fake did not get an answer: %d %q", entry, code, tok)
		}
		if (tok == "boot_entry") == (entry == "start") {
			t.Errorf("%s session answered %q", entry, tok)
		}
	}
}

// A boot-ops unit's start settles through sashStarted: a start that exits
// 0 with a process it spawned still running fails boot_ops_lingering with
// the unit failed; one that leaves nothing running ends exited and ready.
func TestBootOpsStartSettles(t *testing.T) {
	for _, lingering := range []bool{true, false} {
		script := "#!/bin/sh\n"
		if lingering {
			script += sendFrame + `send '{"key":"svc.spawn","argv":["spawn","w","/bin/sleep","300"],"path":"","body":""}'
dd bs=65536 count=1 <&6 >&- 2>&-
exit 0
`
		}
		sup, _ := fakeBootSash(t, script)
		err := sup.Start(t.Context(), "app")
		row := rowOf(t, sup, "app")
		if lingering {
			if fail.Token(err) != "boot_ops_lingering" || row.State != "failed" || row.LastError != "boot_ops_lingering" {
				t.Fatalf("lingering: %v %+v", err, row)
			}
			continue
		}
		if err != nil || row.State != "exited" || !row.Ready {
			t.Fatalf("clean: %v %+v", err, row)
		}
	}
}
