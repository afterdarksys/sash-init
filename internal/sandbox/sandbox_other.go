//go:build !linux

package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func launchHelper(context.Context, string, []string, *os.File, *unit.Sandbox, bool, time.Duration, Options, bool) (*exec.Cmd, string, *os.File, error) {
	return nil, "", nil, fail.E("sandbox_unsupported")
}

// openExec returns no fd: off Linux the checked, resolved path is run.
func openExec(string) (*os.File, error) {
	return nil, nil
}

// directTarget runs the resolved path.
func directTarget(target string, _ *os.File, _ bool, notifyW *os.File) (string, []*os.File, *os.File, error) {
	if notifyW != nil {
		return target, []*os.File{notifyW}, nil, nil
	}
	return target, nil, nil, nil
}

// readHead reads the start of the file at p. A file the supervisor cannot
// read is not a script anyone could run, so it has no head.
func readHead(_ *os.File, p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, nil
		}
		return nil, fail.E("exec_not_file")
	}
	defer f.Close()
	buf := make([]byte, headLen)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fail.E("exec_not_file")
	}
	return buf[:n], nil
}

// ApplyCLI is the re-exec entry. This platform has no sandbox mechanism.
func ApplyCLI([]string) int {
	return 2
}
