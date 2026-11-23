//go:build linux

package cgroup

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// Mount is where the unified hierarchy must be mounted.
const Mount = "/sys/fs/cgroup"

// controllers are the ones the supervisor enables for service cgroups when
// its root offers them.
var controllers = []string{"cpu", "memory", "pids"}

// Supported reports whether this platform has cgroups.
func Supported() bool { return true }

// Root is the delegated cgroup that holds one cgroup per service.
type Root struct {
	dir  string          // path below Mount
	rel  string          // the same path as /proc/PID/cgroup shows it
	ctrl map[string]bool // controllers enabled for service cgroups

	mu        sync.Mutex
	hideKill  bool
	populated func(dir string) (bool, error)
}

// Open checks and prepares the root. An empty dir is the supervisor's own
// cgroup. The hierarchy must be cgroup2 at Mount and the root writable by
// the supervisor: otherwise cgroup_unavailable. When the supervisor is in
// the root itself it moves into ROOT/supervisor first. The cpu, memory and
// pids controllers are enabled for service cgroups where the root offers
// them; a missing one only refuses units whose limits need it.
func Open(dir string) (*Root, error) {
	unavailable := fail.E("cgroup_unavailable")
	var sfs unix.Statfs_t
	if err := unix.Statfs(Mount, &sfs); err != nil || sfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, unavailable
	}
	own, err := procCgroup("self")
	if err != nil {
		return nil, unavailable
	}
	if dir == "" {
		dir = filepath.Join(Mount, own)
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || (dir != Mount && !strings.HasPrefix(dir, Mount+"/")) {
		return nil, unavailable
	}
	rel := "/" + strings.TrimPrefix(strings.TrimPrefix(dir, Mount), "/")
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return nil, unavailable
	}
	if err := unix.Statfs(dir, &sfs); err != nil || sfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, unavailable
	}
	for _, p := range []string{dir, dir + "/cgroup.procs", dir + "/cgroup.subtree_control"} {
		if unix.Access(p, unix.W_OK) != nil {
			return nil, unavailable
		}
	}
	switch {
	case own == rel:
		l := filepath.Join(dir, leaf)
		if err := os.Mkdir(l, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, unavailable
		}
		if err := writeFile(l+"/cgroup.procs", "0"); err != nil {
			return nil, unavailable
		}
	case below(own, rel) && own != joinRel(rel, leaf):
		// The supervisor would sit inside a service cgroup, or somewhere
		// else below the root it is meant to manage.
		return nil, unavailable
	}
	offered, err := os.ReadFile(dir + "/cgroup.controllers")
	if err != nil {
		return nil, unavailable
	}
	for _, c := range controllers {
		if hasWord(offered, c) {
			// Best effort: a root that still holds other processes refuses
			// with EBUSY, and units needing c are then refused.
			writeFile(dir+"/cgroup.subtree_control", "+"+c)
		}
	}
	enabled, err := os.ReadFile(dir + "/cgroup.subtree_control")
	if err != nil {
		return nil, unavailable
	}
	r := &Root{dir: dir, rel: rel, ctrl: map[string]bool{}}
	for _, c := range controllers {
		if hasWord(enabled, c) {
			r.ctrl[c] = true
		}
	}
	return r, nil
}

// TestHooks is for tests only: hideKill makes cgroup.kill look absent, so
// the freeze-and-kill fallback runs; populated, when not nil, replaces the
// read of cgroup.events.
func (r *Root) TestHooks(hideKill bool, populated func(dir string) (bool, error)) {
	r.mu.Lock()
	r.hideKill, r.populated = hideKill, populated
	r.mu.Unlock()
}

// Supports is cgroup_controller when l needs a controller the root has not
// enabled for service cgroups.
func (r *Root) Supports(l unit.Limits) error {
	for _, c := range l.Controllers() {
		if !r.ctrl[c] {
			return fail.E("cgroup_controller")
		}
	}
	return nil
}

// Path is the service cgroup as /proc/PID/cgroup shows it.
func (r *Root) Path(name string) string {
	return joinRel(r.rel, name+suffix)
}

func (r *Root) svcDir(name string) (string, error) {
	if !unit.NameOK(name) {
		return "", fail.E("failed")
	}
	return filepath.Join(r.dir, name+suffix), nil
}

// Prepare empties and removes whatever is left of the service cgroup, makes
// a fresh one (mode 0755, owned by the supervisor's uid), writes the limits
// and opens it for the child to join. The caller closes the group.
func (r *Root) Prepare(name string, l unit.Limits, timeout time.Duration) (*Group, error) {
	dir, err := r.svcDir(name)
	if err != nil {
		return nil, err
	}
	if err := r.Supports(l); err != nil {
		return nil, err
	}
	if err := r.KillAll(name, timeout); err != nil {
		return nil, err
	}
	if err := unix.Mkdir(dir, 0o755); err != nil {
		return nil, fail.E("cgroup_unavailable")
	}
	g, err := setUp(dir, l)
	if err != nil {
		removeTree(dir)
		return nil, err
	}
	return g, nil
}

func setUp(dir string, l unit.Limits) (*Group, error) {
	if err := unix.Chmod(dir, 0o755); err != nil {
		return nil, fail.E("failed")
	}
	limit := func(file, value string) error {
		err := writeFile(dir+"/"+file, value)
		if errors.Is(err, unix.ENOENT) {
			return fail.E("cgroup_controller")
		}
		if err != nil {
			return fail.E("failed")
		}
		return nil
	}
	if l.MemoryMax != 0 {
		if err := limit("memory.max", strconv.FormatUint(l.MemoryMax, 10)); err != nil {
			return nil, err
		}
		// Without swap off, a service over memory.max is swapped, not killed.
		if err := writeFile(dir+"/memory.swap.max", "0"); err != nil && !errors.Is(err, unix.ENOENT) {
			return nil, fail.E("failed")
		}
	}
	if l.PidsMax != 0 {
		if err := limit("pids.max", strconv.FormatUint(l.PidsMax, 10)); err != nil {
			return nil, err
		}
	}
	if l.CPUQuota != 0 {
		if err := limit("cpu.max", l.CPUMax()); err != nil {
			return nil, err
		}
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fail.E("failed")
	}
	pfd, err := unix.Open(dir+"/cgroup.procs", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		unix.Close(dfd)
		return nil, fail.E("failed")
	}
	return &Group{Dir: os.NewFile(uintptr(dfd), dir), Procs: os.NewFile(uintptr(pfd), dir+"/cgroup.procs")}, nil
}

// KillAll kills every process in the service cgroup and below, waits until
// cgroup.events reports populated 0, and removes the cgroup. A cgroup that
// does not exist is already done. It is cgroup_stuck when the cgroup is not
// empty and removed within timeout.
//
// cgroup.kill (Linux 5.14) is used where it exists. Otherwise the cgroup is
// frozen, every member is sent SIGKILL through a pidfd opened while it is
// frozen and still a member, and the cgroup is thawed, until it is empty.
//
// Threats: a frozen member cannot fork, and cannot exit except by a fatal
// signal, so the pid read from cgroup.procs is still that member when its
// pidfd is opened; membership is checked again through /proc before the
// signal. Without pidfd_open (before 5.3) the pid is signalled directly.
func (r *Root) KillAll(name string, timeout time.Duration) error {
	dir, err := r.svcDir(name)
	if err != nil {
		return err
	}
	if timeout <= 0 {
		timeout = unit.DefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	var killed time.Time
	for {
		pop, err := r.isPopulated(dir)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return fail.E("failed")
		}
		if !pop {
			err := removeTree(dir)
			if err == nil || errors.Is(err, unix.ENOENT) {
				return nil
			}
		} else if time.Since(killed) >= 50*time.Millisecond {
			r.kill(dir)
			killed = time.Now()
		}
		if time.Now().After(deadline) {
			return fail.E("cgroup_stuck")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *Root) isPopulated(dir string) (bool, error) {
	r.mu.Lock()
	hook := r.populated
	r.mu.Unlock()
	if hook != nil {
		return hook(dir)
	}
	return eventFlag(dir, "populated")
}

func (r *Root) kill(dir string) {
	r.mu.Lock()
	hide := r.hideKill
	r.mu.Unlock()
	if !hide {
		err := writeFile(dir+"/cgroup.kill", "1")
		if err == nil || !errors.Is(err, unix.ENOENT) {
			return
		}
	}
	freezeKill(dir)
}

// freezeKill is the fallback for kernels without cgroup.kill.
func freezeKill(dir string) {
	if writeFile(dir+"/cgroup.freeze", "1") != nil {
		return
	}
	defer writeFile(dir+"/cgroup.freeze", "0")
	for i := 0; i < 20; i++ {
		if frozen, err := eventFlag(dir, "frozen"); err != nil || frozen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	rel := "/" + strings.TrimPrefix(strings.TrimPrefix(dir, Mount), "/")
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p + "/cgroup.procs")
		if err != nil {
			return nil
		}
		for _, f := range strings.Fields(string(raw)) {
			if pid, err := strconv.Atoi(f); err == nil && pid > 0 {
				killMember(pid, rel)
			}
		}
		return nil
	})
}

func killMember(pid int, rel string) {
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ENOSYS) {
		if cg, err := procCgroup(strconv.Itoa(pid)); err == nil && (cg == rel || below(cg, rel)) {
			unix.Kill(pid, unix.SIGKILL)
		}
		return
	}
	if err != nil {
		return
	}
	defer unix.Close(fd)
	if cg, err := procCgroup(strconv.Itoa(pid)); err != nil || (cg != rel && !below(cg, rel)) {
		return
	}
	unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

// Usage reads the service cgroup's memory.current, pids.current and the
// usage_usec line of cpu.stat. It is false when the cgroup does not exist.
func (r *Root) Usage(name string) (Usage, bool) {
	dir, err := r.svcDir(name)
	if err != nil {
		return Usage{}, false
	}
	if _, err := os.Lstat(dir + "/cgroup.procs"); err != nil {
		return Usage{}, false
	}
	var u Usage
	u.MemoryCurrent = readUint(dir + "/memory.current")
	u.PidsCurrent = readUint(dir + "/pids.current")
	if raw, err := os.ReadFile(dir + "/cpu.stat"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
				u.CPUUsageUsec, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			}
		}
	}
	return u, true
}

// Supervised reports whether pid is in a service cgroup of this root, or
// below one. A pid whose cgroup cannot be read counts as supervised.
//
// Threats: the cgroup is read from /proc/PID/cgroup after the request, so a
// peer that exited and whose pid was reused is judged by the new process: it
// is accepted only if that process is outside every service cgroup, which a
// supervised service cannot arrange for itself.
func (r *Root) Supervised(pid int) bool {
	if pid <= 0 {
		return true
	}
	cg, err := procCgroup(strconv.Itoa(pid))
	if err != nil {
		return true
	}
	if !below(cg, r.rel) {
		return false
	}
	rest := strings.TrimPrefix(cg, r.rel)
	rest = strings.TrimPrefix(rest, "/")
	first, _, _ := strings.Cut(rest, "/")
	return strings.HasSuffix(first, suffix)
}

// procCgroup returns the cgroup v2 path of a process ("self" or a pid).
func procCgroup(pid string) (string, error) {
	f, err := os.Open("/proc/" + pid + "/cgroup")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok && strings.HasPrefix(p, "/") {
			return p, nil
		}
	}
	return "", fail.E("failed")
}

// below reports whether p is strictly below root (both as /proc shows them).
func below(p, root string) bool {
	if root == "/" {
		return p != "/" && strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, root+"/")
}

func joinRel(root, name string) string {
	if root == "/" {
		return "/" + name
	}
	return root + "/" + name
}

func eventFlag(dir, key string) (bool, error) {
	raw, err := os.ReadFile(dir + "/cgroup.events")
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return false, errno
		}
		return false, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, key+" "); ok {
			return strings.TrimSpace(v) == "1", nil
		}
	}
	return false, fail.E("failed")
}

func readUint(p string) uint64 {
	raw, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return n
}

func hasWord(raw []byte, w string) bool {
	for _, f := range bytes.Fields(raw) {
		if string(f) == w {
			return true
		}
	}
	return false
}

// writeFile writes one value to a cgroup file and returns the bare errno.
func writeFile(p, v string) error {
	fd, err := unix.Open(p, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.Write(fd, []byte(v))
	return err
}

// removeTree removes an empty cgroup and any cgroups below it, deepest first.
func removeTree(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return errno
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := removeTree(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
	}
	return unix.Rmdir(dir)
}
