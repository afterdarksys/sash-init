// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

func pidfdPid(t *testing.T, fd int) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return -2
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	return -2
}

// Each started process is held by a pidfd, replaced at the next start.
func TestPidfdHeldPerStart(t *testing.T) {
	if fd, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
		t.Skip("kernel lacks pidfd_open")
	} else {
		unix.Close(fd)
	}
	agent := newSvc("agent", "simple", "exec", "no", false, 2*time.Second, []string{"/bin/sleep", "30"})
	sup := mustSup(t, map[string]*unit.Service{"agent": agent})
	s := sup.rt["agent"]
	if err := sup.Start(t.Context(), "agent"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	first, group, pid := s.pidfd, s.group, s.pid
	s.mu.Unlock()
	if first < 0 || group != pid || pidfdPid(t, first) != pid {
		t.Fatalf("pidfd %d group %d pid %d", first, group, pid)
	}
	if err := sup.Restart(t.Context(), "agent"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	second, pid2 := s.pidfd, s.pid
	s.mu.Unlock()
	if second < 0 || pidfdPid(t, second) != pid2 || pid2 == pid {
		t.Fatalf("pidfd %d pid %d", second, pid2)
	}
	if first != second && pidfdPid(t, first) == pid {
		t.Fatal("old pidfd still open")
	}
	// Linux 6.9+ signals the group through the pidfd; older kernels say EINVAL.
	if err := pidfdSignalGroup(second, 0); err != nil && err != syscall.EINVAL {
		t.Fatal(err)
	}
}
