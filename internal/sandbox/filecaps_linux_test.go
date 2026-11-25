// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// fileCapsProbe runs as a capped service: it clears its ambient and
// inheritable sets, then execs SAHT_FCAP (a binary with file capabilities)
// directly and through a plain trampoline (this binary).
func fileCapsProbe() {
	fmt.Printf("clear=%s\n", errName(clearInherited()))
	statusLines("svc_")
	fcap := os.Getenv("SAHT_FCAP")
	for _, tc := range []struct {
		prefix, path string
		env          []string
	}{
		{"direct_", fcap, []string{"SAHT_CAPS_PROBE=status", "SAHT_PREFIX=direct_"}},
		{"tramp_", os.Args[0], []string{"SAHT_CAPS_PROBE=tramp", "SAHT_FCAP=" + fcap}},
	} {
		cmd := exec.Command(tc.path)
		cmd.Env = tc.env
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("%srun=%s\n", tc.prefix, errName(err))
		}
	}
}

// trampoline holds nothing (no file capabilities, ambient and inheritable
// cleared by its parent) and execs SAHT_FCAP.
func trampoline() {
	statusLines("tramp_self_")
	fcap := os.Getenv("SAHT_FCAP")
	fmt.Printf("tramp_exec=%s\n", errName(unix.Exec(fcap, []string{fcap}, []string{"SAHT_CAPS_PROBE=status", "SAHT_PREFIX=tramp_"})))
}

// Clearing the ambient and inheritable sets is not enough: a binary with
// file capabilities exec'd while the permitted set is held gets those it
// names (no_new_privs limits them to the permitted set, not to nothing);
// exec'd through a plain trampoline it gets nothing; one naming a cap
// outside the unit's bounding set does not run at all.
func TestCapsFileCapsChild(t *testing.T) {
	self, ident := capsSetup(t)
	dir, err := os.MkdirTemp("/tmp", "sahfcap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	fcap := filepath.Join(dir, "fcap")
	if err := os.WriteFile(fcap, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	// struct vfs_cap_data, revision 2 with the effective flag, permitted
	// CAP_SETUID: what setcap cap_setuid=ep writes.
	xattr := make([]byte, 20)
	binary.LittleEndian.PutUint32(xattr[0:], 0x02000000|0x1)
	binary.LittleEndian.PutUint32(xattr[4:], 1<<unix.CAP_SETUID)
	if err := unix.Setxattr(fcap, "security.capability", xattr, 0); err != nil {
		t.Skipf("setxattr: %v", err)
	}
	const setuidBit = "0000000000000080"
	for _, tc := range []struct {
		sb   *unit.Sandbox
		want map[string]string
	}{
		{&unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setuid"}, SetuidTo: []uint32{65533}}, map[string]string{
			"clear": "ok", "svc_CapPrm": setuidBit, "svc_CapEff": setuidBit, "svc_CapInh": zeroCaps, "svc_CapAmb": zeroCaps,
			"direct_CapPrm": setuidBit, "direct_CapEff": setuidBit, "direct_CapInh": zeroCaps, "direct_CapAmb": zeroCaps, "direct_NoNewPrivs": "1", "direct_Seccomp": "2",
			"tramp_self_CapPrm": zeroCaps, "tramp_CapPrm": zeroCaps, "tramp_CapEff": zeroCaps, "tramp_CapAmb": zeroCaps,
		}},
		{&unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"setuid", "setgid"}, SetuidTo: []uint32{65533}, SetgidTo: []uint32{65533}}, map[string]string{
			"svc_CapPrm": "00000000000000c0", "direct_CapPrm": setuidBit, "direct_CapEff": setuidBit, "tramp_CapPrm": zeroCaps,
		}},
		{&unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}, Caps: []string{"net_bind_service"}}, map[string]string{
			"svc_CapPrm": "0000000000000400", "direct_run": "EPERM", "tramp_self_CapPrm": zeroCaps, "tramp_exec": "EPERM",
		}},
	} {
		got, _, err := runCaps(t, self, ident, tc.sb, "SAHT_CAPS_PROBE=fcap", "SAHT_FCAP="+fcap)
		if err != nil {
			t.Fatal(err)
		}
		wantKeys(t, got, tc.want)
	}
}
