// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package bootpolicy

import (
	"golang.org/x/sys/unix"
	"time"
)

func bootElapsed() (time.Duration, error) {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t); err != nil {
		return 0, err
	}
	return time.Duration(t.Nano()), nil
}
