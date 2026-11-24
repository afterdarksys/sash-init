// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

// Package cgtest prepares delegated cgroups for tests; cgroups are Linux
// only, so here every cgroup test is skipped.
package cgtest

import "testing"

// Base is always "" here.
func Base() (string, string) { return "", "cgroups are Linux only" }

// Dir skips the test.
func Dir(t *testing.T) string {
	t.Helper()
	t.Skip("cgroup tests skipped: cgroups are Linux only")
	return ""
}
