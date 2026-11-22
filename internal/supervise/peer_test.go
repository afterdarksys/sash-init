package supervise

import (
	"os"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
)

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
			out := marker(t)
			t.Cleanup(func() { removeFile(t, out+".tmp") })
			svc := newSvc("client", "simple", "exec", "no", false, 5*time.Second, tc.exec)
			idle := newSvc("idle", "simple", "exec", "no", false, 5*time.Second, []string{"/bin/sleep", "30"})
			sup := mustSup(t, map[string]*unit.Service{"client": svc, "idle": idle})
			path := listenServe(t, sup)
			// The test process is not supervised and is answered.
			if _, raw := rpc(t, path, `{"op":"status","name":"idle"}`); string(raw) == `{"ok":false,"error":"peer_supervised"}` {
				t.Fatalf("%s", raw)
			}
			svc.Execution.Environment = []string{"SAHT_CLIENT_SOCK=" + path, "SAHT_CLIENT_OUT=" + out}
			if err := sup.Start(t.Context(), "client"); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			var raw []byte
			for time.Now().Before(deadline) {
				var err error
				if raw, err = os.ReadFile(out); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if string(raw) != `{"ok":false,"error":"peer_supervised"}` {
				t.Fatalf("response %q", raw)
			}
		})
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
