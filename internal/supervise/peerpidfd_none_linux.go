// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && !(amd64 || arm64)

package supervise

// soPeerPidfd is not used where its number differs; pidfd_open is.
const soPeerPidfd = 0
