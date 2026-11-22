//go:build !linux && !darwin

package supervise

import (
	"net"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func peerCred(*net.UnixConn) (uint32, int, error) {
	return 0, 0, fail.E("uid_denied")
}
