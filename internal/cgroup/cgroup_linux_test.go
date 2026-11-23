//go:build linux

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup/cgtest"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestMain(m *testing.M) {
	if os.Getenv("SAHT_CG_OPEN") == "1" {
		r, err := Open("")
		if err != nil {
			fmt.Print(fail.Token(err))
			os.Exit(0)
		}
		own, _ := procCgroup("self")
		fmt.Print(own, " ", r.rel)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var unixPidfdOpen = pidfdOpen

func openRoot(t *testing.T, dir string) *Root {
	t.Helper()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// startIn starts argv inside the group, as the supervisor does.
func startIn(t *testing.T, g *Group, argv ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: int(g.Dir.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go cmd.Wait()
	return cmd
}

func members(t *testing.T, dir string, want int) []int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, err := os.ReadFile(dir + "/cgroup.procs")
		if err != nil {
			t.Fatal(err)
		}
		var pids []int
		for _, f := range strings.Fields(string(raw)) {
			n, _ := strconv.Atoi(f)
			pids = append(pids, n)
		}
		if len(pids) >= want {
			return pids
		}
		if time.Now().After(deadline) {
			t.Fatalf("members %v, want %d", pids, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dead reports whether pid is gone or a zombie.
func dead(pid int) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] == 'Z' || s[i+2] == 'X'
}

func TestOpenRejects(t *testing.T) {
	for _, dir := range []string{"/tmp", "relative", Mount + "/../tmp", Mount + "/x/", Mount + "/missing-sahinit"} {
		if _, err := Open(dir); fail.Token(err) != "cgroup_unavailable" {
			t.Errorf("%s: %v", dir, err)
		}
	}
}

// A setsid double fork leaves the process group and the session, and is
// still killed with its cgroup; the cgroup is then removed. Without
// cgroup.kill the freeze fallback does it, with or without pidfds.
func TestKillAllSetsidDoubleFork(t *testing.T) {
	for _, mode := range []string{"kill", "freeze", "freeze-nopidfd"} {
		hide := mode != "kill"
		t.Run(mode, func(t *testing.T) {
			if mode == "freeze-nopidfd" {
				pidfdOpen = func(int, int) (int, error) { return -1, syscall.ENOSYS }
				defer func() { pidfdOpen = unixPidfdOpen }()
			}
			r := openRoot(t, cgtest.Dir(t))
			r.TestHooks(hide, nil)
			g, err := r.Prepare("svc", unit.Limits{}, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			if st, err := os.Stat(g.Dir.Name()); err != nil || st.Mode().Perm() != 0o755 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				t.Fatalf("%v %v", st.Mode(), err)
			}
			startIn(t, g, "/bin/sh", "-c", "setsid sh -c 'sleep 60 & exec sleep 61' & exec sleep 62")
			pids := members(t, g.Dir.Name(), 3)
			if err := r.KillAll("svc", 3*time.Second); err != nil {
				t.Fatal(err)
			}
			for _, pid := range pids {
				if !dead(pid) {
					t.Errorf("pid %d alive", pid)
				}
			}
			if _, err := os.Stat(g.Dir.Name()); !os.IsNotExist(err) {
				t.Fatalf("cgroup left: %v", err)
			}
		})
	}
}

// The service counts as stopped only when cgroup.events says populated 0.
func TestKillAllStuck(t *testing.T) {
	r := openRoot(t, cgtest.Dir(t))
	g, err := r.Prepare("svc", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	r.TestHooks(false, func(string) (bool, error) { return true, nil })
	start := time.Now()
	if err := r.KillAll("svc", 200*time.Millisecond); fail.Token(err) != "cgroup_stuck" {
		t.Fatal(err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("returned before the timeout")
	}
	r.TestHooks(false, nil)
	if err := r.KillAll("svc", time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareWritesLimits(t *testing.T) {
	r := openRoot(t, cgtest.Dir(t))
	l := unit.Limits{MemoryMax: 64 << 20, PidsMax: 7, CPUQuota: 50000, CPUPeriod: 100000}
	g, err := r.Prepare("svc", l, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	want := map[string]string{"memory.max": "67108864", "pids.max": "7", "cpu.max": "50000 100000"}
	if _, err := os.Stat(g.Dir.Name() + "/memory.swap.max"); err == nil {
		want["memory.swap.max"] = "0"
	} else {
		t.Log("no swap accounting: memory.swap.max not checked")
	}
	for file, want := range want {
		raw, err := os.ReadFile(g.Dir.Name() + "/" + file)
		if err != nil || strings.TrimSpace(string(raw)) != want {
			t.Errorf("%s: %q %v", file, raw, err)
		}
	}
	if u, ok := r.Usage("svc"); !ok || u.PidsCurrent != 0 {
		t.Fatalf("%+v %v", u, ok)
	}
	if r.Path("svc") != cgtest.Rel(g.Dir.Name()) {
		t.Fatal(r.Path("svc"))
	}
	if err := r.KillAll("svc", time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Usage("svc"); ok {
		t.Fatal("usage of a removed cgroup")
	}
}

// A limit needing a controller the root does not offer is refused.
func TestControllerUnavailable(t *testing.T) {
	r := openRoot(t, cgtest.DirOffering(t, "memory"))
	if err := r.Supports(unit.Limits{MemoryMax: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	pids := unit.Limits{PidsMax: 4}
	if err := r.Supports(pids); fail.Token(err) != "cgroup_controller" {
		t.Fatal(err)
	}
	if _, err := r.Prepare("svc", pids, time.Second); fail.Token(err) != "cgroup_controller" {
		t.Fatal(err)
	}
	// Even if Supports were bypassed, the missing limit file refuses.
	if _, err := setUp(r.dir, pids); fail.Token(err) != "cgroup_controller" {
		t.Fatal(err)
	}
}

func TestSupervised(t *testing.T) {
	dir := cgtest.Dir(t)
	r := openRoot(t, dir)
	if !r.Supervised(0) || !r.Supervised(-1) {
		t.Fatal("unknown pid accepted")
	}
	if r.Supervised(os.Getpid()) {
		t.Fatal("test process refused")
	}
	g, err := r.Prepare("svc", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	defer r.KillAll("svc", 2*time.Second)
	in := startIn(t, g, "/bin/sleep", "60")
	if !r.Supervised(in.Process.Pid) {
		t.Fatal("service process accepted")
	}
	// Below a service cgroup is still the service.
	sub := g.Dir.Name() + "/sub"
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(sub+"/cgroup.procs", strconv.Itoa(in.Process.Pid)); err != nil {
		t.Fatal(err)
	}
	if !r.Supervised(in.Process.Pid) {
		t.Fatal("process below a service cgroup accepted")
	}
	// A service that moved itself into the supervisor's leaf, or into the
	// root itself, is still supervised.
	other := dir + "/" + leaf
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	defer cgtest.Remove(other)
	for _, into := range []string{other, dir} {
		if err := writeFile(into+"/cgroup.procs", strconv.Itoa(in.Process.Pid)); err != nil {
			// A root with controllers enabled below it takes no process.
			if into == dir && errors.Is(err, syscall.EBUSY) {
				continue
			}
			t.Fatal(err)
		}
		if !r.Supervised(in.Process.Pid) {
			t.Fatalf("process in %s accepted", into)
		}
	}
	if err := writeFile(sub+"/cgroup.procs", strconv.Itoa(in.Process.Pid)); err != nil {
		t.Fatal(err)
	}
	// A cgroup removed under a zombie reads as deleted, and is refused.
	if !r.supervisedPath("/elsewhere (deleted)") || r.supervisedPath("/elsewhere") || r.supervisedPath(r.rel+"x") {
		t.Fatal("path rule")
	}
}

// startOutside starts a process in the test's own cgroup, outside any root.
func startOutside(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// killMember signals only a member of the cgroup, through a pidfd or, where
// there is none, directly; a pid outside it is left alone.
func TestKillMemberRechecks(t *testing.T) {
	for _, nopidfd := range []bool{false, true} {
		t.Run(fmt.Sprintf("nopidfd=%v", nopidfd), func(t *testing.T) {
			if nopidfd {
				pidfdOpen = func(int, int) (int, error) { return -1, syscall.ENOSYS }
				defer func() { pidfdOpen = unixPidfdOpen }()
			}
			r := openRoot(t, cgtest.Dir(t))
			g, err := r.Prepare("svc", unit.Limits{}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			defer r.KillAll("svc", 2*time.Second)
			in := startIn(t, g, "/bin/sleep", "60")
			out := startOutside(t)
			rel := r.Path("svc")
			if killMember(out.Process.Pid, rel, false) {
				t.Fatal("non-member signalled")
			}
			time.Sleep(50 * time.Millisecond)
			if dead(out.Process.Pid) {
				t.Fatal("non-member killed")
			}
			if !killMember(in.Process.Pid, rel, false) {
				t.Fatal("member not signalled")
			}
		})
	}
}

// A process that left its service cgroup for the supervisor's leaf, or for
// the root, is found and killed. (With controllers enabled below it the
// root takes no process at all, so this root offers none.)
func TestKillStrays(t *testing.T) {
	dir := cgtest.DirOffering(t)
	r := openRoot(t, dir)
	l := dir + "/" + leaf
	if err := os.Mkdir(l, 0o755); err != nil {
		t.Fatal(err)
	}
	g, err := r.Prepare("svc", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	defer r.KillAll("svc", 2*time.Second)
	a := startIn(t, g, "/bin/sleep", "60")
	b := startIn(t, g, "/bin/sleep", "60")
	keep := startIn(t, g, "/bin/sleep", "60")
	if err := writeFile(l+"/cgroup.procs", strconv.Itoa(a.Process.Pid)); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(dir+"/cgroup.procs", strconv.Itoa(b.Process.Pid)); err != nil {
		t.Fatal(err)
	}
	killed := r.KillStrays()
	if len(killed) != 2 {
		t.Fatalf("killed %v", killed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !dead(a.Process.Pid) || !dead(b.Process.Pid) {
		if time.Now().After(deadline) {
			t.Fatal("strays alive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if dead(keep.Process.Pid) {
		t.Fatal("service process killed")
	}
}

// Service cgroups an earlier instance left are killed and removed by Open.
func TestOpenKillsLeftovers(t *testing.T) {
	dir := cgtest.Dir(t)
	r := openRoot(t, dir)
	g, err := r.Prepare("old", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	in := startIn(t, g, "/bin/sleep", "60")
	g.Close()
	again := openRoot(t, dir)
	if got := again.Leftovers(); len(got) != 1 || got[0] != "old.service" {
		t.Fatal(got)
	}
	if !dead(in.Process.Pid) {
		t.Fatal("leftover alive")
	}
	if _, err := os.Stat(dir + "/old.service"); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// With no directory named, the root is the supervisor's own cgroup: the
// supervisor moves into ROOT/supervisor and enables the controllers.
func TestOpenOwnCgroupMovesIntoLeaf(t *testing.T) {
	dir := cgtest.Dir(t)
	r := openRoot(t, dir)
	g, err := r.Prepare("host", unit.Limits{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	defer r.KillAll("host", 2*time.Second)
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SAHT_CG_OPEN=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(g.Dir.Fd())}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	host := cgtest.Rel(g.Dir.Name())
	if string(out) != host+"/supervisor "+host {
		t.Fatalf("%q", out)
	}
	// Restarted from inside that leaf, the root is still its parent.
	lf, err := os.Open(g.Dir.Name() + "/supervisor")
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	cmd = exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SAHT_CG_OPEN=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(lf.Fd())}
	if out, err = cmd.Output(); err != nil || string(out) != host+"/supervisor "+host {
		t.Fatalf("%q %v", out, err)
	}
	raw, err := os.ReadFile(g.Dir.Name() + "/cgroup.subtree_control")
	if err != nil || !strings.Contains(string(raw), "memory") || !strings.Contains(string(raw), "pids") {
		t.Fatalf("%q %v", raw, err)
	}
}
