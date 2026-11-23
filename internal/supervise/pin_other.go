//go:build !linux

package supervise

import "net"

// peerPin is the peer's pid only: there is no pidfd here, and no cgroup to
// judge it by, so the pid-reuse race stays (see supervisedPeer).
type peerPin struct{ pid int }

func pinPeer(_ *net.UnixConn, pid int) peerPin { return peerPin{pid: pid} }

func (p peerPin) same() bool { return p.pid > 0 }

func (peerPin) close() {}
