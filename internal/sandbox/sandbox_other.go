//go:build !linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func launchSandboxed(context.Context, string, []string, *os.File, *unit.Sandbox, bool, time.Duration, Options) (*exec.Cmd, string, *os.File, error) {
	return nil, "", nil, fail.E("sandbox_unsupported")
}

// execPathFD is unused here: there is no exec fd off Linux.
const execPathFD = ""

// openExec returns no fd: off Linux the checked, resolved path is run.
func openExec(string) (*os.File, error) {
	return nil, nil
}

// ApplyCLI is the re-exec entry. This platform has no sandbox mechanism.
func ApplyCLI([]string) int {
	return 2
}
