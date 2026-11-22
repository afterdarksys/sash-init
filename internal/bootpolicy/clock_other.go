//go:build !linux

package bootpolicy

import (
	"github.com/afterdarksys/sahinit/internal/fail"
	"time"
)

func bootElapsed() (time.Duration, error) { return 0, fail.E("policy_clock_uncertain") }
