// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package hostinit

import "fmt"

func Run([]string) error { return fmt.Errorf("init requires Linux PID 1") }
