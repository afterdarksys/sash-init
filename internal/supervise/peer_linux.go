//go:build linux

package supervise

import (
	"net"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fail.E("uid_denied")
	}
	var uid uint32
	var got bool
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = cred.Uid
		got = true
	}); err != nil {
		return 0, fail.E("uid_denied")
	}
	if credErr != nil || !got {
		return 0, fail.E("uid_denied")
	}
	return uid, nil
}
