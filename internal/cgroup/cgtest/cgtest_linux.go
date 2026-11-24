// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

// Package cgtest prepares delegated cgroups for tests.
//
// The cgroup tests need root and a writable cgroup2 in a private cgroup
// namespace, for example:
//
//	docker run --rm --init --privileged --cgroupns=private ... go test ./...
//
// The first test process to get here moves every process out of the
// namespace root into /init.leaf (as a container entrypoint for nested
// cgroups does), enables cpu, memory and pids below the root and below
// /sahinit-test, and makes /sahinit-test/PID for its own tests. Each test
// then takes a fresh child of that directory as the supervisor's root.
// Anywhere else (not root, read-only cgroup2, or the host's real root
// cgroup) the tests are skipped with the reason.
package cgtest

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const mount = "/sys/fs/cgroup"

var ctrls = []string{"cpu", "memory", "pids"}

var seq atomic.Uint64

var base = sync.OnceValues(setup)

// Base returns the directory the tests of this process use, or "" and why
// the cgroup tests cannot run here.
func Base() (string, string) {
	return base()
}

// Dir returns a fresh, empty cgroup directory for one test, with cpu,
// memory and pids offered to it; it is emptied and removed at cleanup. The
// test is skipped when cgroup tests cannot run here.
func Dir(t *testing.T) string {
	return DirOffering(t, ctrls...)
}

// DirOffering is Dir with only the named controllers offered to it.
func DirOffering(t *testing.T, offer ...string) string {
	t.Helper()
	b, why := Base()
	if b == "" {
		t.Skip("cgroup tests skipped: " + why)
	}
	mid := filepath.Join(b, "t"+strconv.FormatUint(seq.Add(1), 10))
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := Remove(mid); err != nil {
			t.Errorf("remove %s: %v", mid, err)
		}
	})
	for _, c := range offer {
		if err := write(mid+"/cgroup.subtree_control", "+"+c); err != nil {
			t.Fatalf("enable %s: %v", c, err)
		}
	}
	dir := mid + "/root"
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Remove kills everything in dir and below and removes it, deepest first.
func Remove(dir string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		write(dir+"/cgroup.kill", "1")
		err := removeTree(dir)
		if err == nil || errors.Is(err, unix.ENOENT) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func removeTree(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
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

// Cgroup returns the cgroup v2 path of a process.
func Cgroup(pid int) (string, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return p, nil
		}
	}
	return "", errors.New("no cgroup v2 line")
}

// Rel is dir as /proc/PID/cgroup shows it.
func Rel(dir string) string {
	return "/" + strings.TrimPrefix(strings.TrimPrefix(dir, mount), "/")
}

func setup() (string, string) {
	if os.Geteuid() != 0 {
		return "", "need root (run the Docker suite with --privileged --cgroupns=private)"
	}
	var sfs unix.Statfs_t
	if err := unix.Statfs(mount, &sfs); err != nil || sfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return "", "no cgroup2 mounted at " + mount
	}
	// The host's real root cgroup has no cgroup.events; never reorganise it.
	if _, err := os.Stat(mount + "/cgroup.events"); err != nil {
		return "", "refusing to reorganise the host's root cgroup; run in a private cgroup namespace"
	}
	if unix.Access(mount+"/cgroup.procs", unix.W_OK) != nil {
		return "", "cgroup2 is read-only (run Docker with --privileged --cgroupns=private)"
	}
	own, err := Cgroup(os.Getpid())
	if err != nil || (own != "/" && own != "/init.leaf") {
		return "", "not at the root of a private cgroup namespace"
	}
	if err := os.Mkdir(mount+"/init.leaf", 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", "mkdir init.leaf: " + err.Error()
	}
	for _, c := range ctrls {
		if err := enableRoot(c); err != nil {
			return "", fmt.Sprintf("enable %s: %v", c, err)
		}
	}
	top := mount + "/sahinit-test"
	dir := filepath.Join(top, strconv.Itoa(os.Getpid()))
	for _, d := range []string{top, dir} {
		if err := os.Mkdir(d, 0o755); err != nil && (d == dir || !errors.Is(err, os.ErrExist)) {
			return "", "mkdir: " + err.Error()
		}
		for _, c := range ctrls {
			if err := write(d+"/cgroup.subtree_control", "+"+c); err != nil {
				return "", fmt.Sprintf("enable %s in %s: %v", c, d, err)
			}
		}
	}
	return dir, ""
}

// enableRoot moves every process of the namespace root into init.leaf and
// enables c below the root, retrying while other test processes start.
func enableRoot(c string) error {
	var err error
	for i := 0; i < 100; i++ {
		raw, rerr := os.ReadFile(mount + "/cgroup.procs")
		if rerr != nil {
			return rerr
		}
		for _, f := range strings.Fields(string(raw)) {
			write(mount+"/init.leaf/cgroup.procs", f)
		}
		if err = write(mount+"/cgroup.subtree_control", "+"+c); err == nil {
			return nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

func write(p, v string) error {
	fd, err := unix.Open(p, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.Write(fd, []byte(v))
	return err
}
