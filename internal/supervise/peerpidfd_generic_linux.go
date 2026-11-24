// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && (amd64 || arm64)

package supervise

// soPeerPidfd is SO_PEERPIDFD (Linux 6.5) in the generic socket option
// numbering that amd64 and arm64 use; x/sys has no constant for it.
const soPeerPidfd = 77
