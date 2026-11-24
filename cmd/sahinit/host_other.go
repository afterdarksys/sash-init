// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package main

import (
	"fmt"
	"io"
)

func runHost(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "host helpers require Linux")
	return 1
}
