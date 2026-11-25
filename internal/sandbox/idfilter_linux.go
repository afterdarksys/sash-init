// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"runtime"
	"unsafe"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// The id filter: a seccomp program the helper installs, after
// no_new_privs, for a unit that holds setuid or setgid
// (docs/design/unit-caps-1.md).
//
// Threats: CAP_SETUID and CAP_SETGID alone let a service become uid or gid
// 0, the supervisor, or any account whose Unix sockets, files and processes
// it then reaches (D-Bus as root, docker.sock as gid docker), and map any id
// into a new user namespace. The filter bounds every uid and gid change to
// the unit's own ids and its listed targets, allows setgroups only to clear
// the list, refuses CLONE_NEWUSER and hides clone3 (whose flags it cannot
// read). A foreign architecture, and x32 on x86-64, kills the process, so no
// other syscall table reaches the unfiltered numbers. It does not stop a
// forged SCM_CREDENTIALS uid or gid, which the kernel allows any CAP_SETUID
// or CAP_SETGID holder and a filter cannot see.

// filterArch describes the syscall table the id filter checks. It is set
// per architecture; audit 0 means the filter is not available.
type filterArch struct {
	audit uint32
	x32   bool // reject nr with __X32_SYSCALL_BIT (x86-64)
	// Syscall numbers.
	setuid, setreuid, setresuid, setfsuid uint32
	setgid, setregid, setresgid, setfsgid uint32
	setgroups, unshare, clone, clone3     uint32
}

// seccomp_data offsets: nr, arch, then args at 16 + 8*i. The low 32 bits of
// an argument are at its offset on a little-endian machine (amd64, arm64),
// and they are all the kernel reads of a uid_t, gid_t or int.
const (
	offNR    = 0
	offArch  = 4
	offArg0  = 16
	x32Bit   = 0x40000000
	allOnes  = 0xffffffff
	retAllow = unix.SECCOMP_RET_ALLOW
	retKill  = unix.SECCOMP_RET_KILL_PROCESS
	retEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retNoSys = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
)

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

const (
	ldAbs = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	jeq   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	jset  = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	ret   = unix.BPF_RET | unix.BPF_K
)

// idBlock returns the instructions for one id syscall, entered with the
// syscall number in A: when nr is not the call, it falls through to the
// next block with A unchanged; otherwise each of its nargs arguments must
// be one of allowed, or the call fails with EPERM.
func idBlock(nr uint32, nargs int, allowed []uint32) ([]unix.SockFilter, error) {
	var body []unix.SockFilter
	for i := 0; i < nargs; i++ {
		body = append(body, stmt(ldAbs, uint32(offArg0+8*i)))
		for j, id := range allowed {
			// On a match, skip the rest of the list and the EPERM return.
			skip := len(allowed) - j
			if skip > 255 {
				return nil, fail.E("failed")
			}
			body = append(body, jump(jeq, id, uint8(skip), 0))
		}
		body = append(body, stmt(ret, retEPERM))
	}
	body = append(body, stmt(ret, retAllow))
	if len(body) > 255 {
		return nil, fail.E("failed")
	}
	return append([]unix.SockFilter{jump(jeq, nr, 0, uint8(len(body)))}, body...), nil
}

// flagBlock refuses nr when its first argument has any bit of mask, and
// allows it otherwise.
func flagBlock(nr, mask uint32) []unix.SockFilter {
	return []unix.SockFilter{
		jump(jeq, nr, 0, 4),
		stmt(ldAbs, offArg0),
		jump(jset, mask, 0, 1),
		stmt(ret, retEPERM),
		stmt(ret, retAllow),
	}
}

// buildIDFilter returns the id filter for a. uids and gids are the ids the
// process may take: its own and its listed targets. Either list may be nil,
// which allows no change of that kind of id at all (only the all-ones
// "unchanged" value).
func buildIDFilter(a filterArch, uids, gids []uint32) ([]unix.SockFilter, error) {
	if a.audit == 0 {
		return nil, fail.E("seccomp_unavailable")
	}
	if len(uids) > unit.MaxIDs+1 || len(gids) > unit.MaxIDs+1 {
		return nil, fail.E("sandbox_ids")
	}
	prog := []unix.SockFilter{
		stmt(ldAbs, offArch),
		jump(jeq, a.audit, 1, 0),
		stmt(ret, retKill),
		stmt(ldAbs, offNR),
	}
	if a.x32 {
		prog = append(prog, jump(jset, x32Bit, 0, 1), stmt(ret, retKill))
	}
	allowU := append(append([]uint32{}, uids...), allOnes)
	allowG := append(append([]uint32{}, gids...), allOnes)
	for _, c := range []struct {
		nr    uint32
		nargs int
		ids   []uint32
	}{
		{a.setuid, 1, allowU}, {a.setreuid, 2, allowU}, {a.setresuid, 3, allowU}, {a.setfsuid, 1, allowU},
		{a.setgid, 1, allowG}, {a.setregid, 2, allowG}, {a.setresgid, 3, allowG}, {a.setfsgid, 1, allowG},
		// setgroups(size, list): only size 0, which clears the list.
		{a.setgroups, 1, []uint32{0}},
	} {
		b, err := idBlock(c.nr, c.nargs, c.ids)
		if err != nil {
			return nil, err
		}
		prog = append(prog, b...)
	}
	prog = append(prog, flagBlock(a.unshare, unix.CLONE_NEWUSER)...)
	prog = append(prog, flagBlock(a.clone, unix.CLONE_NEWUSER)...)
	prog = append(prog, jump(jeq, a.clone3, 0, 1), stmt(ret, retNoSys))
	prog = append(prog, stmt(ret, retAllow))
	if len(prog) > unix.BPF_MAXINSNS {
		return nil, fail.E("failed")
	}
	return prog, nil
}

// needsIDFilter reports whether the sandbox holds setuid or setgid.
func needsIDFilter(sb *unit.Sandbox) bool {
	return sb.HasCap("setuid") || sb.HasCap("setgid")
}

// installIDFilter installs the id filter on the calling thread, which must
// have no_new_privs set. The process's own uid or gid is allowed with the
// targets; a kind of id whose cap the unit lacks gets only its own id.
func installIDFilter(sb *unit.Sandbox) error {
	uids := append([]uint32{uint32(unix.Getuid())}, sb.SetuidTo...)
	gids := append([]uint32{uint32(unix.Getgid())}, sb.SetgidTo...)
	prog, err := buildIDFilter(nativeFilter, uids, gids)
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	runtime.KeepAlive(&fprog)
	if errno != 0 {
		return fail.E("seccomp_unavailable")
	}
	return nil
}
