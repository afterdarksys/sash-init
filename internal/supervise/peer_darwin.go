// SPDX-License-Identifier: GPL-3.0-or-later

//go:build darwin

package supervise

import (
	"net"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// peerCred returns the peer's uid (LOCAL_PEERCRED) and pid (LOCAL_PEERPID).
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
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		p, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if err != nil {
			credErr = err
			return
		}
		uid = cred.Uid
		pid = p
		got = true
	}); err != nil {
		return 0, 0, fail.E("uid_denied")
	}
	if credErr != nil || !got {
		return 0, 0, fail.E("uid_denied")
	}
	return uid, pid, nil
}
