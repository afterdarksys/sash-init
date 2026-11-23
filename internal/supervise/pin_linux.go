//go:build linux

package supervise

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// peerPin holds the control-socket peer from the moment it is accepted, so
// the pid checked after its request is read is known to be the same process.
type peerPin struct {
	fd    int    // pidfd for the peer, or -1
	pid   int    // the peer's pid
	start string // start time from /proc/PID/stat, when there is no pidfd
}

// pinPeer pins the peer right after accept: through SO_PEERPIDFD (Linux
// 6.5), which names the process that connected; else pidfd_open on the
// SO_PEERCRED pid; else (before Linux 5.3) the pid's start time.
//
// Threats: without SO_PEERPIDFD a peer that exits between connect and
// accept, and whose pid is reused in that window, is pinned as the new
// process. Without any pidfd the start time has clock-tick resolution.
func pinPeer(conn *net.UnixConn, pid int) peerPin {
	p := peerPin{fd: -1, pid: pid}
	if soPeerPidfd != 0 {
		if raw, err := conn.SyscallConn(); err == nil {
			raw.Control(func(s uintptr) {
				if fd, err := unix.GetsockoptInt(int(s), unix.SOL_SOCKET, soPeerPidfd); err == nil && fd >= 0 {
					p.fd = fd
				}
			})
		}
		if p.fd >= 0 {
			p.pid = fdinfoPid(p.fd)
			return p
		}
	}
	if pid <= 0 {
		return p
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		p.fd = fd
		return p
	}
	if errors.Is(err, unix.ENOSYS) {
		p.start = startTime(pid)
	}
	return p
}

// same reports whether the pinned process still exists, so a pid read since
// the pin named it and not a reuse. A pin that could not be taken is never
// the same.
func (p peerPin) same() bool {
	if p.pid <= 0 {
		return false
	}
	if p.fd >= 0 {
		err := unix.PidfdSendSignal(p.fd, 0, nil, 0)
		return err == nil || errors.Is(err, unix.EPERM)
	}
	return p.start != "" && startTime(p.pid) == p.start
}

func (p peerPin) close() {
	if p.fd >= 0 {
		unix.Close(p.fd)
	}
}

// fdinfoPid reads the pid a pidfd names (-1 once it has exited).
func fdinfoPid(fd int) int {
	raw, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return -1
			}
			return n
		}
	}
	return -1
}

// startTime is field 22 of /proc/PID/stat, or "" when unreadable.
func startTime(pid int) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
