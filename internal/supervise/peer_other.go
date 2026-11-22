//go:build !linux && !darwin

package supervise

import (
	"net"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func peerUID(*net.UnixConn) (uint32, error) {
	return 0, fail.E("uid_denied")
}
