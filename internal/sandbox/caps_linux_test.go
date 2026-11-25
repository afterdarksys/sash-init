// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// The probe runs as the service. It prints key=value lines; a refused call
// prints its errno name.

func errName(err error) string {
	if err == nil {
		return "ok"
	}
	var e syscall.Errno
	if errors.As(err, &e) {
		switch e {
		case unix.EPERM:
			return "EPERM"
		case unix.EACCES:
			return "EACCES"
		case unix.ENOSYS:
			return "ENOSYS"
		case unix.EINVAL:
			return "EINVAL"
		}
		return "errno" + strconv.Itoa(int(e))
	}
	return "err"
}

func sys3(nr, a, b, c uintptr) error {
	_, _, errno := unix.RawSyscall(nr, a, b, c)
	if errno != 0 {
		return errno
	}
	return nil
}

// statusLines prints the capability lines of the calling thread.
func statusLines(prefix string) {
	raw, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		fmt.Printf("%sstatus=%s\n", prefix, errName(err))
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch k {
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp":
			fmt.Printf("%s%s=%s\n", prefix, k, strings.TrimSpace(v))
		}
	}
}

func bindTCP(port string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	p, _ := strconv.Atoi(port)
	return unix.Bind(fd, &unix.SockaddrInet4{Port: p, Addr: [4]byte{127, 0, 0, 1}})
}

func dropAll() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	return setCaps(0)
}

// clearInherited clears the ambient and inheritable sets, keeping the
// permitted and effective sets: what a service does so its children get no
// capability.
func clearInherited() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	st, err := readCaps()
	if err != nil {
		return err
	}
	var data [2]unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data[0] = unix.CapUserData{Effective: uint32(st.eff), Permitted: uint32(st.prm)}
	data[1] = unix.CapUserData{Effective: uint32(st.eff >> 32), Permitted: uint32(st.prm >> 32)}
	return unix.Capset(&hdr, &data[0])
}

func probeChild(prefix string) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{"SAHT_CAPS_PROBE=status", "SAHT_PREFIX=" + prefix}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("%srun=%s\n", prefix, errName(err))
	}
}

func capsProbe(mode string) int {
	runtime.LockOSThread()
	switch mode {
	case "status":
		statusLines(os.Getenv("SAHT_PREFIX"))
	case "landlock":
		statusLines("")
		_, err := os.ReadFile("/etc/hostname")
		fmt.Printf("outside=%s\n", errName(err))
		fmt.Printf("bind=%s\n", errName(bindTCP(os.Getenv("SAHT_PORT"))))
	case "x32":
		// An x32 syscall number on x86-64: the id filter kills the process.
		unix.RawSyscall(unix.SYS_GETPID|x32Bit, 0, 0, 0)
		fmt.Printf("survived\n")
	case "netbind":
		statusLines("")
		fmt.Printf("bind=%s\n", errName(bindTCP(os.Getenv("SAHT_PORT"))))
		fmt.Printf("setresuid=%s\n", errName(sys3(unix.SYS_SETRESUID, 65533, 65533, 65533)))
		fmt.Printf("chown=%s\n", errName(unix.Fchownat(unix.AT_FDCWD, "/proc/self/fd/0", 0, 0, 0)))
		fmt.Printf("drop=%s\n", errName(dropAll()))
		fmt.Printf("bind_after_drop=%s\n", errName(bindTCP(os.Getenv("SAHT_PORT2"))))
	case "setuid":
		statusLines("")
		target := uintptr(65533)
		none := ^uintptr(0)
		zero := uintptr(0)
		fmt.Printf("uid0=%s\n", errName(sys3(unix.SYS_SETRESUID, zero, zero, zero)))
		fmt.Printf("euid0=%s\n", errName(sys3(unix.SYS_SETRESUID, none, zero, none)))
		fmt.Printf("setuid0=%s\n", errName(sys3(unix.SYS_SETUID, zero, 0, 0)))
		fmt.Printf("setreuid0=%s\n", errName(sys3(unix.SYS_SETREUID, none, zero, 0)))
		// setfsuid returns the old fsuid, or -EPERM from the filter.
		r1, _, _ := unix.RawSyscall(unix.SYS_SETFSUID, zero, 0, 0)
		fmt.Printf("setfsuid0=%d\n", int32(r1))
		fmt.Printf("gid0=%s\n", errName(sys3(unix.SYS_SETRESGID, zero, zero, zero)))
		fmt.Printf("setgid0=%s\n", errName(sys3(unix.SYS_SETGID, zero, 0, 0)))
		fmt.Printf("unlisted=%s\n", errName(sys3(unix.SYS_SETRESUID, 12345, 12345, 12345)))
		fmt.Printf("unlisted_gid=%s\n", errName(sys3(unix.SYS_SETRESGID, 12345, 12345, 12345)))
		// The upper 32 bits are not part of a uid_t: 1<<32 is uid 0.
		fmt.Printf("uid0_high=%s\n", errName(sys3(unix.SYS_SETRESUID, 1<<32, 1<<32, 1<<32)))
		groups := []uint32{0}
		fmt.Printf("setgroups=%s\n", errName(sys3(unix.SYS_SETGROUPS, 1, uintptr(unsafe.Pointer(&groups[0])), 0)))
		fmt.Printf("newuser=%s\n", errName(sys3(unix.SYS_UNSHARE, unix.CLONE_NEWUSER, 0, 0)))
		// Flags the kernel itself rejects (EINVAL), so nothing forks even if
		// the filter let the call through.
		fmt.Printf("clone_newuser=%s\n", errName(sys3(unix.SYS_CLONE, unix.CLONE_NEWUSER|unix.CLONE_FS, 0, 0)))
		fmt.Printf("clone3=%s\n", errName(sys3(unix.SYS_CLONE3, 0, 0, 0)))
		// Joining an existing user namespace: EBADF from the kernel if the
		// filter let it through.
		fmt.Printf("setns_user=%s\n", errName(sys3(unix.SYS_SETNS, none, unix.CLONE_NEWUSER, 0)))
		// Every argument is checked, not only the first ones.
		fmt.Printf("resuid_saved0=%s\n", errName(sys3(unix.SYS_SETRESUID, target, target, zero)))
		fmt.Printf("resgid_saved0=%s\n", errName(sys3(unix.SYS_SETRESGID, target, target, zero)))
		fmt.Printf("regid0=%s\n", errName(sys3(unix.SYS_SETREGID, none, zero, 0)))
		// setfsgid reports no error: the fsgid must simply stay.
		unix.RawSyscall(unix.SYS_SETFSGID, zero, 0, 0)
		r1, _, _ = unix.RawSyscall(unix.SYS_SETFSGID, none, 0, 0)
		fmt.Printf("fsgid_after=%d\n", int32(r1))
		fmt.Printf("setgroups_clear=%s\n", errName(sys3(unix.SYS_SETGROUPS, 0, 0, 0)))
		// -1 leaves an id unchanged and is always allowed.
		fmt.Printf("euid_only=%s\n", errName(sys3(unix.SYS_SETRESUID, none, target, none)))
		fmt.Printf("gid_target=%s\n", errName(sys3(unix.SYS_SETRESGID, target, target, target)))
		fmt.Printf("uid_target=%s\n", errName(sys3(unix.SYS_SETRESUID, target, target, target)))
		// The unit's own uid stays allowed after switching away from it.
		fmt.Printf("own_back=%s\n", errName(sys3(unix.SYS_SETRESUID, 65534, 65534, 65534)))
		fmt.Printf("uid_target2=%s\n", errName(sys3(unix.SYS_SETRESUID, target, target, target)))
		statusLines("after_")
		probeChild("child_kept_")
		fmt.Printf("clear=%s\n", errName(clearInherited()))
		probeChild("child_cleared_")
		fmt.Printf("drop=%s\n", errName(dropAll()))
		statusLines("dropped_")
		fmt.Printf("back=%s\n", errName(sys3(unix.SYS_SETRESUID, 65534, 65534, 65534)))
	}
	return 0
}

// sinetdStandIn stands in for /usr/local/sbin/sinetd under the shipped unit:
// it reports its capability state through capget and prctl (its Landlock
// domain has no /proc), binds a low port and signals readiness on fd 3.
func sinetdStandIn() int {
	runtime.LockOSThread()
	st, err := readCaps()
	if err != nil {
		fmt.Printf("caps=%s\n", errName(err))
		return 1
	}
	nnp, _ := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	sec, _ := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	fmt.Printf("eff=%#x prm=%#x inh=%#x amb=%#x bnd=%#x nnp=%d seccomp=%d uid=%d\n", st.eff, st.prm, st.inh, st.amb, st.bnd, nnp, sec, unix.Getuid())
	bound := "none"
	for p := 700; p < 800; p++ {
		if bindTCP(strconv.Itoa(p)) == nil {
			bound = "low"
			break
		}
	}
	fmt.Printf("bind=%s\n", bound)
	_, err = os.ReadFile("/etc/hostname")
	fmt.Printf("outside=%s\n", errName(err))
	if _, err := unix.Write(3, []byte{'\n'}); err != nil {
		return 1
	}
	return 0
}

func parseProbe(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

// capsSetup skips unless the test runs as root (the supervisor must be root
// to give caps) on a kernel with Landlock.
func capsSetup(t *testing.T) (string, unit.Execution) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if landlockABI() < 1 {
		t.Skip("no Landlock")
	}
	return helperSelf(t)
}

// privilegedPorts makes ports below 1024 need CAP_NET_BIND_SERVICE in this
// network namespace for the test (Docker lowers the start to 0), and puts
// the old value back after.
func privilegedPorts(t *testing.T) {
	t.Helper()
	const knob = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
	old, err := os.ReadFile(knob)
	if err != nil {
		t.Skipf("no %s: %v", knob, err)
	}
	if strings.TrimSpace(string(old)) == "1024" {
		return
	}
	if err := os.WriteFile(knob, []byte("1024\n"), 0o644); err != nil {
		t.Skipf("cannot set %s: %v", knob, err)
	}
	t.Cleanup(func() { os.WriteFile(knob, old, 0o644) })
}

// freeLowPort returns a port below 1024 nobody holds on 127.0.0.1.
func freeLowPort(t *testing.T, skip int) string {
	t.Helper()
	for p := 900 + skip*20; p < 1000+skip*20 && p < 1024; p++ {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			l.Close()
			return strconv.Itoa(p)
		}
	}
	t.Fatal("no free low port")
	return ""
}

func runCaps(t *testing.T, self string, ident unit.Execution, sb *unit.Sandbox, env ...string) (map[string]string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	ident.Environment = env
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, claim, _, err := Launch(ctx, self, []string{self}, sb, false, 5*time.Second, Options{Execution: ident, Stdout: &out, Stderr: &errb})
	if err != nil {
		return nil, "", err
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v: %s %s", err, out.String(), errb.String())
	}
	return parseProbe(out.String()), claim, nil
}

func wantKeys(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

// ownStatus is a field of the test process's own status, which a service
// without caps inherits: its bounding set, and the seccomp mode a container
// runtime may have set.
func ownStatus(t *testing.T, key string) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(l, key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatal("no " + key)
	return ""
}

const zeroCaps = "0000000000000000"

// A unit without caps is exactly as before: nothing in any set, the
// bounding set inherited unchanged, no_new_privs, no seccomp.
func TestCapsNoneUnchanged(t *testing.T) {
	self, ident := capsSetup(t)
	for _, caps := range [][]string{nil, {}} {
		sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: caps}
		got, claim, err := runCaps(t, self, ident, sb, "SAHT_CAPS_PROBE=status")
		if err != nil {
			t.Fatal(err)
		}
		wantKeys(t, got, map[string]string{"CapInh": zeroCaps, "CapPrm": zeroCaps, "CapEff": zeroCaps, "CapAmb": zeroCaps, "CapBnd": ownStatus(t, "CapBnd"), "NoNewPrivs": "1", "Seccomp": ownStatus(t, "Seccomp")})
		if claim != SandboxClaim(min(landlockABI(), MaxLandlockABI)) {
			t.Fatalf("claim %q", claim)
		}
	}
}

// net_bind_service as uid 65534: exactly that bit in all five sets; a low
// port binds; nothing else privileged works; after dropping it, binding
// fails.
func TestCapsNetBindService(t *testing.T) {
	self, ident := capsSetup(t)
	privilegedPorts(t)
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"net_bind_service"}}
	got, claim, err := runCaps(t, self, ident, sb, "SAHT_CAPS_PROBE=netbind", "SAHT_PORT="+freeLowPort(t, 0), "SAHT_PORT2="+freeLowPort(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	const bit = "0000000000000400"
	wantKeys(t, got, map[string]string{
		"CapInh": bit, "CapPrm": bit, "CapEff": bit, "CapAmb": bit, "CapBnd": bit, "NoNewPrivs": "1", "Seccomp": ownStatus(t, "Seccomp"),
		"bind": "ok", "setresuid": "EPERM", "chown": "EPERM", "drop": "ok", "bind_after_drop": "EACCES",
	})
	if claim != SandboxClaim(min(landlockABI(), MaxLandlockABI)) {
		t.Fatalf("claim %q", claim)
	}
}

// setuid and setgid with target lists: exactly those bits, the id filter on,
// every way to uid or gid 0, an unlisted id, supplementary groups or a new
// user namespace refused; the listed target works and keeps the caps (the
// kernel rule for a change between non-zero uids), a child keeps them until
// the service clears its ambient and inheritable sets, and after a drop
// nothing is left.
func TestCapsSetuidSetgid(t *testing.T) {
	self, ident := capsSetup(t)
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setuid", "setgid"}, SetuidTo: []uint32{65533}, SetgidTo: []uint32{65533}}
	got, claim, err := runCaps(t, self, ident, sb, "SAHT_CAPS_PROBE=setuid")
	if err != nil {
		t.Fatal(err)
	}
	const bits = "00000000000000c0"
	wantKeys(t, got, map[string]string{
		"CapInh": bits, "CapPrm": bits, "CapEff": bits, "CapAmb": bits, "CapBnd": bits, "NoNewPrivs": "1", "Seccomp": "2",
		"uid0": "EPERM", "euid0": "EPERM", "setuid0": "EPERM", "setreuid0": "EPERM", "setfsuid0": "-1",
		"gid0": "EPERM", "setgid0": "EPERM", "unlisted": "EPERM", "unlisted_gid": "EPERM", "uid0_high": "EPERM",
		"setgroups": "EPERM", "newuser": "EPERM", "clone_newuser": "EPERM", "clone3": "ENOSYS",
		"setns_user": "EPERM", "resuid_saved0": "EPERM", "resgid_saved0": "EPERM", "regid0": "EPERM", "fsgid_after": "65534",
		"setgroups_clear": "ok", "euid_only": "ok", "gid_target": "ok", "uid_target": "ok", "own_back": "ok", "uid_target2": "ok",
		"after_CapPrm": bits, "after_CapEff": bits, "after_CapAmb": bits,
		"child_kept_CapPrm": bits, "child_kept_CapAmb": bits, "child_kept_Seccomp": "2",
		"clear":                "ok",
		"child_cleared_CapPrm": zeroCaps, "child_cleared_CapEff": zeroCaps, "child_cleared_CapAmb": zeroCaps, "child_cleared_CapInh": zeroCaps, "child_cleared_Seccomp": "2", "child_cleared_NoNewPrivs": "1",
		"drop": "ok", "dropped_CapPrm": zeroCaps, "dropped_CapEff": zeroCaps, "dropped_CapAmb": zeroCaps, "dropped_CapInh": zeroCaps,
		"back": "EPERM",
	})
	if claim != SandboxClaim(min(landlockABI(), MaxLandlockABI))+idFilterClaim {
		t.Fatalf("claim %q", claim)
	}
}

// Landlock still holds with caps granted.
func TestCapsLandlockHolds(t *testing.T) {
	self, ident := capsSetup(t)
	privilegedPorts(t)
	dir, err := os.MkdirTemp("/tmp", "sahcaps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "probe")
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probe, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sb := range []*unit.Sandbox{
		{NoNewPrivs: true, ReadOnly: []string{dir, "/usr", "/proc"}, Caps: []string{"net_bind_service"}},
		{NoNewPrivs: true, ReadOnly: []string{dir, "/usr", "/proc"}, Caps: []string{"net_bind_service", "setuid"}, SetuidTo: []uint32{65533}},
	} {
		var out, errb bytes.Buffer
		ident := ident
		ident.Environment = []string{"SAHT_CAPS_PROBE=landlock", "SAHT_PORT=" + freeLowPort(t, 2)}
		cmd, _, _, err := Launch(context.Background(), self, []string{probe}, sb, false, 5*time.Second, Options{Execution: ident, Stdout: &out, Stderr: &errb})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%v: %s %s", err, out.String(), errb.String())
		}
		got := parseProbe(out.String())
		wantKeys(t, got, map[string]string{"outside": "EACCES", "bind": "ok", "NoNewPrivs": "1"})
	}
}

// The helper checks the state it was started with: one cap too many, no
// CAP_SETPCAP, or nothing at all is sandbox_cap, and the target never runs.
func TestCapsHelperEntryCheck(t *testing.T) {
	self, ident := capsSetup(t)
	saved := ambientCaps
	t.Cleanup(func() { ambientCaps = saved })
	for name, fn := range map[string]func([]string) ([]uintptr, error){
		"extra": func(n []string) ([]uintptr, error) {
			a, err := saved(n)
			return append(a, unix.CAP_KILL), err
		},
		"no_setpcap": func([]string) ([]uintptr, error) { return []uintptr{unix.CAP_NET_BIND_SERVICE}, nil },
		"none":       func([]string) ([]uintptr, error) { return nil, nil },
	} {
		ambientCaps = fn
		sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"net_bind_service"}}
		got, claim, err := runCaps(t, self, ident, sb, "SAHT_CAPS_PROBE=status")
		if fail.Token(err) != "sandbox_cap" || got != nil || claim != "" {
			t.Errorf("%s: %v %v %q", name, err, got, claim)
		}
	}
}

// The parent refuses a claim that does not match the id filter the unit
// needs, either way.
func TestCapsClaimMatchesFilter(t *testing.T) {
	plain := &unit.Sandbox{Caps: []string{"net_bind_service"}}
	ids := &unit.Sandbox{Caps: []string{"setgid"}, SetgidTo: []uint32{7}}
	c := SandboxClaim(3)
	for _, tc := range []struct {
		sb    *unit.Sandbox
		claim string
		ok    bool
	}{
		{plain, c, true}, {plain, c + idFilterClaim, false}, {ids, c + idFilterClaim, true}, {ids, c, false},
	} {
		if err := checkClaim(tc.claim, tc.sb); (err == nil) != tc.ok {
			t.Errorf("%v %q: %v", tc.sb.Caps, tc.claim, err)
		}
	}
	if !IsSandboxClaim(c+idFilterClaim) || IsSandboxClaim(claimNone+idFilterClaim) || IsSandboxClaim(c+idFilterClaim+idFilterClaim) {
		t.Fatal("IsSandboxClaim")
	}
}

// A supervisor that is not root has no capability to give.
func TestCapsNeedRootSupervisor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	uid, gid := uint32(os.Getuid()+1), uint32(os.Getgid()+1)
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"net_bind_service"}}
	_, _, _, err := Launch(context.Background(), "/unused", []string{"/bin/true"}, sb, false, time.Second, Options{Execution: unit.Execution{UID: &uid, GID: &gid}})
	if fail.Token(err) != "sandbox_cap" {
		t.Fatal(err)
	}
}

// The id filter program: every jump stays inside it, and the largest
// allowed lists still fit 8-bit jumps.
func TestIDFilterShape(t *testing.T) {
	if _, err := buildIDFilter(filterArch{}, nil, nil); fail.Token(err) != "seccomp_unavailable" {
		t.Fatal(err)
	}
	big := make([]uint32, unit.MaxIDs+1)
	for i := range big {
		big[i] = uint32(1000 + i)
	}
	if _, err := buildIDFilter(nativeFilter, append(big, 1), nil); fail.Token(err) != "sandbox_ids" && nativeFilter.audit != 0 {
		t.Fatal(err)
	}
	if nativeFilter.audit == 0 {
		t.Skip("no id filter on this architecture")
	}
	for _, lists := range [][2][]uint32{{nil, nil}, {{5}, {6}}, {big, big}} {
		prog, err := buildIDFilter(nativeFilter, lists[0], lists[1])
		if err != nil {
			t.Fatal(err)
		}
		// The arch check comes first and kills on a mismatch.
		if prog[0] != stmt(ldAbs, offArch) || prog[1] != jump(jeq, nativeFilter.audit, 1, 0) || prog[2] != stmt(ret, retKill) || prog[len(prog)-1] != stmt(ret, retAllow) {
			t.Fatal("frame")
		}
		for i, in := range prog {
			if in.Code&0x07 == unix.BPF_JMP && (i+1+int(in.Jt) >= len(prog) || i+1+int(in.Jf) >= len(prog)) {
				t.Fatalf("jump out of program at %d", i)
			}
		}
	}
}

// The sinetd unit as shipped (internal/unit/testdata/sinetd.json, copied from
// the sahinetd repository), with only exec[0] pointed at a stand-in binary,
// loads and starts as uid 65532 holding net_bind_service; with the three
// caps and target lists it starts with the id filter.
func TestCapsSinetdUnit(t *testing.T) {
	self, _ := capsSetup(t)
	privilegedPorts(t)
	raw, err := os.ReadFile("../unit/testdata/sinetd.json")
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.MkdirTemp("/usr/local", "sahinit-sinetd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(bin) })
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	standIn := filepath.Join(bin, "sinetd")
	if err := os.WriteFile(standIn, body, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"/etc/sinetd", "/run/sinetd"} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(d) })
		}
	}
	shipped := strings.Replace(string(raw), `"/usr/local/sbin/sinetd"`, strconv.Quote(standIn), 1)
	three := strings.Replace(shipped, `"caps": ["net_bind_service"]`, `"caps": ["net_bind_service", "setuid", "setgid"], "setuid_to": [70001], "setgid_to": [70001]`, 1)
	if shipped == string(raw) || three == shipped {
		t.Fatal("fixture edit did not apply")
	}
	abi := min(landlockABI(), MaxLandlockABI)
	for _, tc := range []struct {
		unit, caps, seccomp, claim string
	}{
		{shipped, "0x400", ownStatus(t, "Seccomp"), SandboxClaim(abi)},
		{three, "0x4c0", "2", SandboxClaim(abi) + idFilterClaim},
	} {
		svc, err := unit.Parse([]byte(tc.unit), "sinetd")
		if err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		cmd, claim, ready, err := Launch(context.Background(), self, svc.Exec, svc.Sandbox, svc.Ready == "notify", 5*time.Second, Options{Execution: svc.Execution, Stdout: &out, Stderr: &errb})
		if err != nil {
			t.Fatal(err)
		}
		ready.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b [1]byte
		if _, err := ready.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		ready.Close()
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%v: %s %s", err, out.String(), errb.String())
		}
		want := fmt.Sprintf("eff=%[1]s prm=%[1]s inh=%[1]s amb=%[1]s bnd=%[1]s nnp=1 seccomp=%s uid=65532\nbind=low\noutside=EACCES\n", tc.caps, tc.seccomp)
		if out.String() != want || claim != tc.claim {
			t.Fatalf("got %q claim %q, want %q %q", out.String(), claim, want, tc.claim)
		}
	}
}

// On x86-64 an x32 syscall number kills a process under the id filter, so
// the x32 table cannot reach the unfiltered numbers.
func TestCapsIDFilterKillsX32(t *testing.T) {
	self, ident := capsSetup(t)
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 is x86-64 only")
	}
	var out bytes.Buffer
	ident.Environment = []string{"SAHT_CAPS_PROBE=x32"}
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setgid"}, SetgidTo: []uint32{65533}}
	cmd, _, _, err := Launch(context.Background(), self, []string{self}, sb, false, 5*time.Second, Options{Execution: ident, Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGSYS || out.Len() != 0 {
		t.Fatalf("err %v out %q", err, out.String())
	}
}

// The supervisor's own ids are refused at start: as a target, as the unit's
// gid, or among its groups. As root the supervisor's gid is 0; as another
// user the helper never runs (the root check follows), so this check alone
// decides.
func TestCapsSupervisorIDsAtStart(t *testing.T) {
	uid := uint32(os.Geteuid() + 1)
	euid, egid := uint32(os.Geteuid()), uint32(os.Getegid())
	other := uint32(65533)
	for _, tc := range []struct {
		sb  *unit.Sandbox
		gid uint32
	}{
		{&unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setuid"}, SetuidTo: []uint32{euid}}, other},
		{&unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setgid"}, SetgidTo: []uint32{egid}}, other},
		{&unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"net_bind_service"}}, egid},
	} {
		gid := tc.gid
		_, _, _, err := Launch(context.Background(), "/unused", []string{"/bin/true"}, tc.sb, false, time.Second, Options{Execution: unit.Execution{UID: &uid, GID: &gid}})
		if fail.Token(err) != "sandbox_ids" {
			t.Errorf("%v gid %d: %v", tc.sb.Caps, gid, err)
		}
	}
}

// fakeHelper stands in for the helper and claims the id filter or not,
// whatever it applied (it applies nothing and runs nothing).
func fakeHelper(claim string) int {
	var buf [4096]byte
	for {
		n, err := unix.Read(fdSpec, buf[:])
		if n <= 0 || err != nil {
			break
		}
	}
	writeFD(fdStatus, okLine(min(landlockABI(), MaxLandlockABI), claim == "filter"))
	return 0
}

// A helper whose claim does not match the id filter the unit needs is
// refused, either way.
func TestCapsLyingHelperClaim(t *testing.T) {
	self, ident := capsSetup(t)
	for _, tc := range []struct {
		claim string
		sb    *unit.Sandbox
	}{
		{"filter", &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"net_bind_service"}}},
		{"plain", &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setgid"}, SetgidTo: []uint32{65533}}},
	} {
		got, claim, err := runCaps(t, self, ident, tc.sb, "SAHT_FAKE_CLAIM="+tc.claim)
		if fail.Token(err) != "sandbox_cap" || got != nil || claim != "" {
			t.Errorf("%s: %v %v %q", tc.claim, err, got, claim)
		}
	}
}
