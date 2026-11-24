//go:build !linux

package supervise

import (
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
)

// sashHost is the sash verb host. Off Linux there is no sandbox to spawn
// into, so spawn and the path probes refuse; sash units do not start.
type sashHost struct {
	sup *Supervisor
	s   *runtime
}

func socketPair() (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fail.E("failed")
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	return os.NewFile(uintptr(fds[0]), "verb"), os.NewFile(uintptr(fds[1]), "verb-sash"), nil
}

func (h *sashHost) Status(service string) (sash.Row, error) { return h.sup.statusRow(service) }

func (h *sashHost) DialTCP(addr string) bool {
	if strings.HasPrefix(addr, "localhost:") {
		addr = "127.0.0.1:" + strings.TrimPrefix(addr, "localhost:")
	}
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (h *sashHost) ProbePath(string, string, string) bool { return false }

func (h *sashHost) Signal(*sash.Proc, string) error { return fail.E("failed") }

func (h *sashHost) Spawn(sash.SpawnPlan, *sash.Proc) error { return fail.E("failed") }

func (h *sashHost) File(sash.FileOp) error { return fail.E("failed") }

func (h *sashHost) Mount(sash.MountPlan) error { return fail.E("failed") }

func (h *sashHost) Umount(string) error { return fail.E("failed") }

func (h *sashHost) unmountAll(*sash.Table) {}
