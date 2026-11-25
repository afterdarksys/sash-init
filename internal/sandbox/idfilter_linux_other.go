// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && !amd64 && !arm64

package sandbox

// nativeFilter is empty: the id filter is written for little-endian amd64
// and arm64 only, so setuid and setgid are seccomp_unavailable elsewhere.
var nativeFilter = filterArch{}
