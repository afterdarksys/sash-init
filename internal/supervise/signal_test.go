package supervise

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
)

// A pid that is not the service's last started process (a reused pid, or a
// pid read before a restart) is never signalled.
func TestSignalOnlyOwnGroup(t *testing.T) {
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	if err := sup.Start(t.Context(), "agent"); err != nil {
		t.Fatal(err)
	}
	foreign := exec.Command("/bin/sleep", "30")
	foreign.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		foreign.Process.Kill()
		foreign.Wait()
	})
	s := sup.rt["agent"]
	if err := s.signalGroup(foreign.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if !s.groupGone(foreign.Process.Pid) {
		t.Fatal("foreign group reported as ours")
	}
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(foreign.Process.Pid, 0); err != nil {
		t.Fatalf("foreign process signalled: %v", err)
	}
	pid := rowOf(t, sup, "agent").Pid
	if err := sup.Stop(t.Context(), "agent"); err != nil {
		t.Fatal(err)
	}
	// After the leader is reaped and its group is empty, signalling the old
	// pid is a no-op, not an error.
	if err := s.signalGroup(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if !s.groupGone(pid) {
		t.Fatal("stopped group reported alive")
	}
}
