// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux && amd64

package sandbox

import "golang.org/x/sys/unix"

var nativeFilter = filterArch{
	audit: unix.AUDIT_ARCH_X86_64, x32: true,
	setuid: unix.SYS_SETUID, setreuid: unix.SYS_SETREUID, setresuid: unix.SYS_SETRESUID, setfsuid: unix.SYS_SETFSUID,
	setgid: unix.SYS_SETGID, setregid: unix.SYS_SETREGID, setresgid: unix.SYS_SETRESGID, setfsgid: unix.SYS_SETFSGID,
	setgroups: unix.SYS_SETGROUPS, unshare: unix.SYS_UNSHARE, clone: unix.SYS_CLONE, clone3: unix.SYS_CLONE3,
	setns: unix.SYS_SETNS,
}
