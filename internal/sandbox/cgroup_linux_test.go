// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/cgroup/cgtest"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func prepared(t *testing.T) (*cgroup.Root, *cgroup.Group) {
	t.Helper()
	r, err := cgroup.Open(cgtest.Dir(t))
	if err != nil {
		t.Fatal(err)
	}
	g, err := r.Prepare("svc", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		g.Close()
		if err := r.KillAll("svc", 2*time.Second); err != nil {
			t.Error(err)
		}
	})
	return r, g
}

// helperJoin treats clone3 into a cgroup as missing (on) or present, so
// the helper joins the cgroup itself, or clone3 places the child.
func helperJoin(t *testing.T, on bool) {
	t.Helper()
	prev := noClone.Load()
	noClone.Store(on)
	t.Cleanup(func() { noClone.Store(prev) })
}

// The child is in the service cgroup from its first instruction: through
// clone3, or through the helper writing cgroup.procs when clone3 cannot.
//
// The child runs as uid 65534 (as root in Docker), so the helper joins
// through a cgroup.procs fd the supervisor opened, without write access of
// its own.
func TestLaunchIntoCgroup(t *testing.T) {
	self, ident := helperSelf(t)
	for _, helper := range []bool{false, true} {
		for _, boxed := range []bool{false, true} {
			t.Run(fmt.Sprintf("helper=%v,sandbox=%v", helper, boxed), func(t *testing.T) {
				r, g := prepared(t)
				helperJoin(t, helper)
				var sb *unit.Sandbox
				opts := Options{Cgroup: g, Execution: ident}
				if boxed {
					if ident.UID == nil {
						t.Skip("requires root to run the helper as uid 65534")
					}
					sb = &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}
				}
				cmd, claim, _, err := Launch(context.Background(), self, []string{"/bin/sleep", "30"}, sb, false, 2*time.Second, opts)
				if err != nil {
					if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
						t.Skip(tok)
					}
					t.Fatal(err)
				}
				defer reap(cmd)
				if boxed != IsSandboxClaim(claim) || (!boxed && claim != claimNone) {
					t.Fatalf("claim %q", claim)
				}
				cg, err := cgtest.Cgroup(cmd.Process.Pid)
				if err != nil || cg != r.Path("svc") {
					t.Fatalf("cgroup %q %v, want %q", cg, err, r.Path("svc"))
				}
				if noClone.Load() != helper {
					t.Fatal("clone3 fallback flipped")
				}
			})
		}
	}
}

// A child that cannot join its cgroup does not start.
func TestLaunchCgroupJoinFails(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, helper := range []bool{false, true} {
		t.Run(fmt.Sprintf("helper=%v", helper), func(t *testing.T) {
			_, g := prepared(t)
			helperJoin(t, helper)
			// A cgroup with a domain controller enabled below it is not a
			// leaf: no process may join it (EBUSY).
			f, err := os.OpenFile(g.Dir.Name()+"/cgroup.subtree_control", os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, werr := f.WriteString("+memory")
			f.Close()
			if werr != nil {
				t.Fatal(werr)
			}
			defer os.WriteFile(g.Dir.Name()+"/cgroup.subtree_control", []byte("-memory"), 0)
			cmd, claim, _, err := Launch(context.Background(), self, []string{"/bin/sleep", "30"}, nil, false, 2*time.Second, Options{Cgroup: g})
			if cmd != nil || claim != "" || fail.Token(err) != "cgroup_join" {
				if cmd != nil {
					reap(cmd)
				}
				t.Fatalf("cmd=%v claim=%q err=%v", cmd, claim, err)
			}
		})
	}
}

// A join-only helper must name a cgroup; a sandboxing helper that reports
// "none", or a join-only one that reports a sandbox, is refused.
func TestHelperStatusMatchesRequest(t *testing.T) {
	if _, err := marshalSpec(nil, false, false); err == nil {
		t.Fatal("spec with neither sandbox nor cgroup")
	}
	if _, err := parseStatus(noneLine, true); err == nil {
		t.Fatal("none accepted from a sandboxing helper")
	}
	if _, err := parseStatus(okLine(3, false), false); err == nil {
		t.Fatal("sandbox claim accepted from a join-only helper")
	}
	if claim, err := parseStatus(noneLine, false); err != nil || claim != claimNone {
		t.Fatal(claim, err)
	}
}

// An ENOSYS or E2BIG from a Start into a cgroup flips launches to the helper
// only when clone3 into the cgroup really fails; an execve E2BIG (argument
// list too long) does not.
func TestCloneMissingProbes(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, g := prepared(t)
	execE2BIG := &os.PathError{Op: "fork/exec", Path: "/bin/sleep", Err: syscall.E2BIG}
	if cloneMissing(execE2BIG, self, g) {
		t.Fatal("execve E2BIG taken for missing clone3")
	}
	if cloneMissing(execE2BIG, self, nil) || cloneMissing(&os.PathError{Err: syscall.EACCES}, self, g) {
		t.Fatal("unrelated error taken for missing clone3")
	}
	if err := startErr(execE2BIG, self, g); err == errNoClone || fail.Token(err) != "failed" {
		t.Fatal(err)
	}
}
