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

func launchSandboxed(context.Context, string, []string, *unit.Sandbox, bool, time.Duration) (*exec.Cmd, string, *os.File, error) {
	return nil, "", nil, fail.E("sandbox_unsupported")
}

// ApplyCLI is the re-exec entry. This platform has no sandbox mechanism.
func ApplyCLI([]string) int {
	return 2
}
