//go:build linux

package hostinit

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Run refuses ordinary processes before doing anything with mounts or signals.
// Once running as PID 1 it never returns, including on configuration errors.
func Run(args []string) error {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return fmt.Errorf("init requires root Linux PID 1")
	}
	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
	c, configErr := Parse(args)
	if configErr != nil {
		c, _ = Parse(nil)
	}
	setupErr := setup()
	console()
	log("started pid=1")
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_CAD_OFF); err != nil {
		log("cad: %v", err)
	}
	self, err := os.Executable()
	if err != nil && setupErr == nil {
		setupErr = err
	}
	if configErr != nil {
		setupErr = configErr
	}
	if setupErr != nil {
		log("recovery: setup: %v", setupErr)
	}
	manager, recovery := 0, 0
	var retry time.Time
	retryBoot := false
	startManager := func() {
		if setupErr != nil {
			return
		}
		manager, err = start(self, []string{"supervise", "--dir", c.Units, "--socket", c.Socket, "--boot-strict"}, false, true)
		if err != nil {
			log("recovery: supervisor start: %v", err)
		} else {
			log("supervisor pid=%d", manager)
		}
	}
	startManager()
	tick := time.NewTicker(100 * time.Millisecond)
	for {
		// Single wait owner, including children which exited before SIGCHLD
		// delivery; polling also handles coalesced signal notifications.
		reap(func(pid int, status unix.WaitStatus) {
			if pid == manager {
				manager = 0
				log("recovery: supervisor exited status=%d", status)
				if err := os.WriteFile("/sys/fs/cgroup/sahinit/cgroup.kill", []byte("1"), 0); err != nil {
					log("recovery cgroup cleanup: %v", err)
				}
			} else if pid == recovery {
				recovery = 0
				retry = time.Now().Add(time.Second)
				log("recovery exited status=%d; SIGHUP retries boot", status)
			} else {
				log("reaped orphan pid=%d", pid)
			}
		})
		if retryBoot && manager == 0 && recovery == 0 {
			retryBoot = false
			c, configErr = Parse(args)
			if configErr != nil {
				c, _ = Parse(nil)
				setupErr = configErr
			} else {
				setupErr = setup()
			}
			startManager()
		}
		if manager == 0 && recovery == 0 && c.Recovery != "" && !time.Now().Before(retry) {
			recovery, err = start(c.Recovery, nil, true, false)
			retry = time.Now().Add(5 * time.Second)
			if err != nil {
				log("recovery executable: %v", err)
			}
		}
		select {
		case sig := <-sigs:
			switch sig {
			case syscall.SIGTERM, syscall.SIGUSR2:
				shutdown(manager, c.ShutdownTimeout, unix.LINUX_REBOOT_CMD_POWER_OFF)
			case syscall.SIGINT:
				shutdown(manager, c.ShutdownTimeout, unix.LINUX_REBOOT_CMD_RESTART)
			case syscall.SIGUSR1:
				shutdown(manager, c.ShutdownTimeout, unix.LINUX_REBOOT_CMD_HALT)
			case syscall.SIGHUP:
				// Queue until recovery has been reaped, so an exiting
				// recovery program can request retry without a signal race.
				if manager == 0 {
					retryBoot = true
				}
			}
		case <-tick.C:
		}
	}
}

func log(format string, args ...any) { fmt.Fprintf(os.Stderr, "sahinit-init: "+format+"\n", args...) }

func mount(target, kind string, magic int64, flags uintptr, data string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	var st unix.Statfs_t
	// Matching statfs alone is insufficient: an initramfs root may itself
	// be tmpfs, while /dev and /run are merely empty directories on it.
	mounted := false
	if raw, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		mounted = mountedAs(string(raw), target, kind)
	} else if target == "/proc" {
		mounted = true // proc's unique magic suffices before mountinfo exists.
	}
	if err := unix.Statfs(target, &st); mounted && err == nil && int64(st.Type) == magic {
		return nil
	}
	if err := unix.Mount(kind, target, kind, flags, data); err != nil {
		return fmt.Errorf("mount %s: %w", target, err)
	}
	return nil
}

func mountedAs(raw, target, kind string) bool {
	mounted := false
	for _, line := range strings.Split(raw, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		fields, fs := strings.Fields(left), strings.Fields(right)
		if ok && len(fields) > 4 && len(fs) > 0 && fields[4] == target {
			mounted = fs[0] == kind
		}
	}
	return mounted
}

func setup() error {
	// Host-only contract: an initramfs has already made the local root
	// available. Network, storage discovery and module loading are services.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	for _, m := range []struct {
		path, kind string
		magic      int64
		flags      uintptr
		data       string
	}{
		{"/proc", "proc", unix.PROC_SUPER_MAGIC, unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"/sys", "sysfs", unix.SYSFS_MAGIC, unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"/dev", "devtmpfs", unix.TMPFS_MAGIC, unix.MS_NOSUID, "mode=0755"},
		{"/run", "tmpfs", unix.TMPFS_MAGIC, unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
		{"/sys/fs/cgroup", "cgroup2", unix.CGROUP2_SUPER_MAGIC, unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
	} {
		if err := mount(m.path, m.kind, m.magic, m.flags, m.data); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/run/sahinit", 0700); err != nil {
		return err
	}
	if err := os.MkdirAll("/sys/fs/cgroup/sahinit/supervisor", 0755); err != nil {
		return err
	}
	if _, err := os.Stat("/sys/fs/cgroup/sahinit/cgroup.kill"); err != nil {
		return fmt.Errorf("host init requires cgroup.kill: %w", err)
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return err
	}
	for _, name := range strings.Fields(string(controllers)) {
		if name == "cpu" || name == "memory" || name == "pids" {
			if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+"+name), 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func console() {
	f, err := os.OpenFile("/dev/console", os.O_RDWR, 0)
	if err != nil {
		log("console: %v", err)
		return
	}
	if f.Fd() > 2 {
		defer f.Close()
	}
	for fd := 0; fd < 3; fd++ {
		if int(f.Fd()) != fd {
			if err := unix.Dup2(int(f.Fd()), fd); err != nil {
				log("console dup: %v", err)
			}
		}
	}
}

func start(path string, args []string, terminal, managed bool) (int, error) {
	attr := &syscall.SysProcAttr{Setsid: true}
	if terminal {
		attr.Setctty = true
		attr.Ctty = 0
	}
	if managed {
		g, err := os.Open("/sys/fs/cgroup/sahinit/supervisor")
		if err != nil {
			return 0, err
		}
		defer g.Close()
		attr.UseCgroupFD, attr.CgroupFD = true, int(g.Fd())
	}
	p, err := os.StartProcess(path, append([]string{path}, args...), &os.ProcAttr{
		Dir: "/", Env: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=linux"},
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}, Sys: attr,
	})
	if err != nil {
		return 0, err
	}
	pid := p.Pid
	// Release the Go handle, NOT the child. Only reap calls wait4 here.
	p.Release()
	return pid, nil
}

func reap(onExit func(int, unix.WaitStatus)) bool {
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return false
		}
		if err != nil || pid == 0 {
			return true
		}
		onExit(pid, status)
	}
}

func shutdown(manager int, timeout time.Duration, action int) {
	log("shutdown action=%d", action)
	if manager > 0 {
		unix.Kill(manager, unix.SIGTERM)
		deadline := time.Now().Add(timeout)
		for manager != 0 && time.Now().Before(deadline) {
			reap(func(pid int, _ unix.WaitStatus) {
				if pid == manager {
					manager = 0
				}
			})
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Includes escaped service descendants and the recovery console. Linux
	// excludes PID 1 from kill(-1). This function is reachable only in Run.
	unix.Kill(-1, unix.SIGTERM)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && reap(func(int, unix.WaitStatus) {}) {
		time.Sleep(20 * time.Millisecond)
	}
	unix.Kill(-1, unix.SIGKILL)
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && reap(func(int, unix.WaitStatus) {}) {
		time.Sleep(20 * time.Millisecond)
	}
	unix.Sync()
	unmount()
	unix.Sync()
	if err := unix.Reboot(action); err != nil {
		log("reboot failed: %v; staying alive", err)
	}
	// Never exit PID 1, even when the kernel refuses a power operation.
	for {
		reap(func(int, unix.WaitStatus) {})
		time.Sleep(time.Second)
	}
}

// Unmount deepest/newest first, retaining pseudo filesystems for diagnostics.
// Busy filesystems are remounted read-only; failures are reported, never hidden
// with lazy detach. Root is remounted last (initramfs root may refuse this).
func unmount() {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		log("mountinfo: %v", err)
		return
	}
	paths := mountPaths(string(raw))
	for _, path := range paths {
		if path != "/" {
			if err := unix.Unmount(path, 0); err == nil {
				continue
			}
		}
		if err := unix.Mount("", path, "", unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			log("unmount/remount %s: %v", path, err)
		}
	}
}

func mountPaths(raw string) []string {
	var paths []string
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := decode.Replace(fields[4])
		if !filepath.IsAbs(path) {
			continue
		}
		keep := false
		for _, prefix := range []string{"/proc", "/sys", "/dev", "/run"} {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				keep = true
			}
		}
		if !keep {
			paths = append(paths, path)
		}
	}
	sort.SliceStable(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	return paths
}
