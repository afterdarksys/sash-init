// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
)

const refusedPeer = `{"ok":false,"error":"peer_supervised"}`

// clientOut returns a response file prefix for socketClient and removes
// whatever the clients write under it.
func clientOut(t *testing.T) string {
	t.Helper()
	out := tmpPath("sahc")
	t.Cleanup(func() {
		files, _ := filepath.Glob(out + "-*")
		for _, f := range files {
			removeFile(t, f)
		}
	})
	return out
}

// waitResponses waits until n clients have answered and returns their
// responses, one per process group.
func waitResponses(t *testing.T, out string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := filepath.Glob(out + "-*")
		var got []string
		for _, f := range files {
			if filepath.Ext(f) == ".tmp" {
				continue
			}
			raw, err := os.ReadFile(f)
			if err == nil {
				got = append(got, string(raw))
			}
		}
		if len(got) >= n {
			sort.Strings(got)
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d clients answered", n)
	return nil
}

// A service, or a child in its process group, is refused on the control
// socket even though it runs as an allowed uid.
func TestSocketRefusesSupervisedPeer(t *testing.T) {
	bin := os.Args[0]
	for _, tc := range []struct {
		name string
		exec []string
	}{
		{"leader", []string{bin}},
		{"group", []string{"/bin/sh", "-c", bin + "; exit 0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := clientOut(t)
			svc := newSvc("client", "simple", "exec", "no", false, 5*time.Second, tc.exec)
			idle := newSvc("idle", "simple", "exec", "no", false, 5*time.Second, []string{"/bin/sleep", "30"})
			sup := mustSup(t, map[string]*unit.Service{"client": svc, "idle": idle})
			path := listenServe(t, sup)
			// The test process is not supervised and is answered.
			if _, raw := rpc(t, path, `{"op":"status","name":"idle"}`); string(raw) == refusedPeer {
				t.Fatalf("%s", raw)
			}
			svc.Execution.Environment = []string{"SAHT_CLIENT_SOCK=" + path, "SAHT_CLIENT_OUT=" + out}
			if err := sup.Start(t.Context(), "client"); err != nil {
				t.Fatal(err)
			}
			if got := waitResponses(t, out, 1); got[0] != refusedPeer {
				t.Fatalf("response %q", got)
			}
		})
	}
}

// The reviewer's reproduction: the leader exits at once and a child left in
// its group calls the socket afterwards.
func TestSocketRefusesOrphanAfterLeaderExit(t *testing.T) {
	out := clientOut(t)
	svc := newSvc("client", "simple", "exec", "no", false, 5*time.Second, []string{"/bin/sh", "-c", "(exec >/dev/null 2>&1; sleep 1; exec " + os.Args[0] + ") & exit 0"})
	sup := mustSup(t, map[string]*unit.Service{"client": svc})
	path := listenServe(t, sup)
	svc.Execution.Environment = []string{"SAHT_CLIENT_SOCK=" + path, "SAHT_CLIENT_OUT=" + out}
	if err := sup.Start(t.Context(), "client"); err != nil {
		t.Fatal(err)
	}
	// The child drops the output pipes, so the leader is collected at once.
	deadline := time.Now().Add(900 * time.Millisecond)
	for rowOf(t, sup, "client").Pid != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if row := rowOf(t, sup, "client"); row.Pid != 0 {
		t.Fatalf("leader still running: %+v", row)
	}
	if got := waitResponses(t, out, 1); got[0] != refusedPeer {
		t.Fatalf("response %q", got)
	}
}

// A child left by an earlier start is still refused after the service has
// started again and leads a new group.
func TestSocketRefusesOrphanOfEarlierStart(t *testing.T) {
	out := clientOut(t)
	svc := newSvc("client", "simple", "exec", "always", false, 5*time.Second, []string{"/bin/sh", "-c", "(exec >/dev/null 2>&1; sleep 1; exec " + os.Args[0] + ") & exit 0"})
	sup := mustSup(t, map[string]*unit.Service{"client": svc})
	sup.RestartBurst = 1
	path := listenServe(t, sup)
	svc.Execution.Environment = []string{"SAHT_CLIENT_SOCK=" + path, "SAHT_CLIENT_OUT=" + out}
	if err := sup.Start(t.Context(), "client"); err != nil {
		t.Fatal(err)
	}
	got := waitResponses(t, out, 2)
	for _, r := range got {
		if r != refusedPeer {
			t.Fatalf("responses %q", got)
		}
	}
}

func TestSupervisedPeerUnknownPid(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"idle": newSvc("idle", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})})
	if !sup.supervisedPeer(0) || !sup.supervisedPeer(-1) {
		t.Fatal("unknown pid accepted")
	}
	if sup.supervisedPeer(os.Getpid()) {
		t.Fatal("test process refused")
	}
}
