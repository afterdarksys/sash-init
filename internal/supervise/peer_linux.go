//go:build linux

package supervise

import (
	"net"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// peerCred returns the peer's uid and pid from SO_PEERCRED. A pid of 0 (a
// peer in another pid namespace) is returned as is; the caller refuses it.
func peerCred(conn *net.UnixConn) (uint32, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fail.E("uid_denied")
	}
	var uid uint32
	var pid int
	var got bool
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = cred.Uid
		pid = int(cred.Pid)
		got = true
	}); err != nil {
		return 0, 0, fail.E("uid_denied")
	}
	if credErr != nil || !got {
		return 0, 0, fail.E("uid_denied")
	}
	return uid, pid, nil
}
