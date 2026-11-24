// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

// A purpose-built VM fixture, never included in the installed init binary.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var output *os.File

func mark(s string)    { fmt.Fprintln(output, "BOOTTEST: "+s) }
func fatal(s string)   { mark("FAIL " + s); syscall.Kill(1, syscall.SIGTERM); park() }
func scenario() string { b, _ := os.ReadFile("/scenario"); return strings.TrimSpace(string(b)) }

func park() {
	for {
		time.Sleep(time.Second)
	}
}

func main() {
	// The sash service's spawned process runs as nobody and cannot open the
	// console: it reports readiness on the readiness pipe and waits for TERM.
	if len(os.Args) > 1 && os.Args[1] == "sleeper" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM)
		ready := os.NewFile(3, "ready")
		ready.Write([]byte("x"))
		ready.Close()
		<-sig
		return
	}
	output, _ = os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if output == nil {
		os.Exit(90)
	}
	mode := "recovery"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "sdnotify":
		c, err := net.Dial("unixgram", os.Getenv("NOTIFY_SOCKET"))
		if err != nil {
			fatal("notify socket")
		}
		defer c.Close()
		if os.Getenv("WATCHDOG_USEC") != "500000" {
			fatal("watchdog environment")
		}
		os.WriteFile("/run/notify-pid", []byte(strconv.Itoa(os.Getpid())), 0600)
		c.Write([]byte("READY=1"))
		mark("sd_notify ready")
		for i := 0; i < 3; i++ {
			time.Sleep(100 * time.Millisecond)
			c.Write([]byte("WATCHDOG=1"))
		}
		mark("sd_notify heartbeats stopped")
		park()
	case "disk":
		b, _ := os.ReadFile("/var/lib/sahinit/boots")
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		n++
		if err := os.WriteFile("/var/lib/sahinit/boots", []byte(strconv.Itoa(n)+"\n"), 0600); err != nil {
			fatal("persistent write")
		}
		mark("persistent boot " + strconv.Itoa(n))
		syscall.Kill(1, syscall.SIGTERM)
		park()
	case "fail":
		os.Exit(17)
	case "recovery":
		if scenario() == "retry" {
			if err := os.WriteFile("/etc/sahinit/units/app.json", []byte(`{"name":"app","exec":["/probe","app"],"type":"simple","ready":"exec","boot":true,"needs":["provider"],"timeout":"2s"}`), 0644); err != nil {
				fatal("repair config")
			}
			mark("recovery retry")
			syscall.Kill(1, syscall.SIGHUP)
			return
		}
		if s := scenario(); s != "badconfig" && s != "bootfail" && s != "runtimefail" && s != "crash" {
			fatal("unexpected recovery")
		}
		mark("recovery " + scenario())
		syscall.Kill(1, syscall.SIGTERM)
		park()
	case "sashlaunch":
		sashLaunch()
	case "sashdrive":
		sashDrive()
	case "fork":
		c := exec.Command("/probe", "orphan")
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := c.Start(); err != nil {
			os.Exit(91)
		}
		os.WriteFile("/run/orphan-pid", []byte(strconv.Itoa(c.Process.Pid)), 0600)
		return
	case "orphan":
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
			if os.Getppid() == 1 {
				mark("orphan adopted")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		fatal("orphan not adopted")
	case "provider":
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM)
		os.WriteFile("/run/provider-ready", nil, 0600)
		if scenario() == "notify" {
			for end := time.Now().Add(10 * time.Second); ; {
				if b, e := os.ReadFile("/run/notify-pid"); e == nil {
					if _, e := os.Stat("/proc/" + string(b)); os.IsNotExist(e) {
						mark("watchdog killed unresponsive service")
						syscall.Kill(1, syscall.SIGTERM)
						break
					}
				}
				if time.Now().After(end) {
					fatal("watchdog failed")
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		<-sig
		if s := scenario(); s == "poweroff" || s == "reboot" || s == "retry" {
			if _, err := os.Stat("/run/app-stopped"); err != nil {
				fatal("shutdown order")
			}
			mark("reverse shutdown")
		}
		return
	case "app":
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM)
		for end := time.Now().Add(5 * time.Second); ; {
			if _, err := os.Stat("/run/provider-ready"); err == nil {
				break
			}
			if time.Now().After(end) {
				fatal("provider readiness")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if scenario() == "runtimefail" {
			time.Sleep(500 * time.Millisecond)
			os.Exit(23)
		}
		if scenario() == "crash" {
			mark("crashing supervisor")
			syscall.Kill(os.Getppid(), syscall.SIGKILL)
			park()
		}
		cg, _ := os.ReadFile("/proc/self/cgroup")
		if !strings.Contains(string(cg), "/sahinit/app.service") {
			fatal("service cgroup " + string(cg))
		}
		mark("service cgroup")
		if scenario() != "retry" {
			for file, want := range map[string]string{"memory.max": "134217728", "pids.max": "64"} {
				b, err := os.ReadFile("/sys/fs/cgroup/sahinit/app.service/" + file)
				if err != nil || strings.TrimSpace(string(b)) != want {
					fatal("resource limit " + file)
				}
			}
		}
		if err := exec.Command("/probe", "fork").Run(); err != nil {
			fatal("fork")
		}
		b, err := os.ReadFile("/run/orphan-pid")
		if err != nil {
			fatal("orphan pid")
		}
		for end := time.Now().Add(5 * time.Second); ; {
			if _, err := os.Stat("/proc/" + string(b)); os.IsNotExist(err) {
				break
			}
			if time.Now().After(end) {
				fatal("orphan not reaped")
			}
			time.Sleep(10 * time.Millisecond)
		}
		mark("orphan reaped")
		if scenario() == "stuck" {
			signal.Ignore(syscall.SIGTERM)
			mark("ignoring TERM")
		}
		action := syscall.SIGTERM
		if scenario() == "reboot" {
			action = syscall.SIGINT
		}
		syscall.Kill(1, action)
		if scenario() == "stuck" {
			for {
				time.Sleep(time.Second)
			}
		}
		<-sig
		os.WriteFile("/run/app-stopped", nil, 0600)
		mark("app stopped")
	}
}

// sashLaunch is a root oneshot unit without a sandbox (cgroup_trusted): it
// starts the sash driver in a new session and moves it to the root cgroup,
// because the control socket refuses peers that are supervised services.
func sashLaunch() {
	c := exec.Command("/probe", "sashdrive")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		fatal("sash driver start")
	}
	if err := os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(strconv.Itoa(c.Process.Pid)), 0); err != nil {
		fatal("sash driver cgroup: " + err.Error())
	}
	mark("sash driver detached")
}

type sashRow struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Ready     bool   `json:"ready"`
	LastError string `json:"last_error"`
	Restarts  int    `json:"restarts"`
	Sash      *struct {
		Serial  uint64 `json:"grant_serial"`
		Entries []struct {
			Entry string `json:"entry"`
			Exit  int    `json:"exit"`
		} `json:"entries"`
		Procs []struct {
			Name  string `json:"name"`
			Pid   int    `json:"pid"`
			State string `json:"state"`
		} `json:"procs"`
	} `json:"sash"`
}

func ctl(op, name string) (string, bool) {
	out, err := exec.Command("/init", "ctl", "--socket", "/run/sahinit/control.sock", op, name).CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

func status(name string) sashRow {
	out, ok := ctl("status", name)
	var resp struct {
		Rows []sashRow `json:"rows"`
	}
	if !ok || json.Unmarshal([]byte(out), &resp) != nil || len(resp.Rows) != 1 {
		fatal("sash status " + name + ": " + out)
	}
	return resp.Rows[0]
}

// mounted is the fstype and options of the mount at dir, or "".
func mounted(dir string) string {
	raw, _ := os.ReadFile("/proc/self/mountinfo")
	found := ""
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		for i, w := range f {
			if w == "-" && len(f) > 4 && f[4] == dir && i+1 < len(f) {
				found = f[i+1] + " " + f[5]
			}
		}
	}
	return found
}

func owned(path string, dir bool, mode uint32) bool {
	var st syscall.Stat_t
	if syscall.Lstat(path, &st) != nil || st.Uid != 65534 || st.Gid != 65534 {
		return false
	}
	isDir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	return isDir == dir && (mode == 0 || st.Mode&0o7777 == mode)
}

// sashDrive checks the sash service from outside every service cgroup,
// through the control socket, then powers the VM off.
func sashDrive() {
	var row sashRow
	for end := time.Now().Add(60 * time.Second); ; {
		if row = status("svc"); row.State == "running" && row.Ready {
			break
		}
		if time.Now().After(end) || row.State == "failed" {
			fatal(fmt.Sprintf("sash service not ready: %+v", row))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if row.Sash == nil || row.Sash.Serial != 5 || len(row.Sash.Procs) != 1 || row.Sash.Procs[0].Name != "main" || row.Sash.Procs[0].State != "running" {
		fatal(fmt.Sprintf("sash row %+v", row.Sash))
	}
	mark("sash service ready")
	pid := strconv.Itoa(row.Sash.Procs[0].Pid)
	cg, _ := os.ReadFile("/proc/" + pid + "/cgroup")
	st, _ := os.ReadFile("/proc/" + pid + "/status")
	if strings.TrimSpace(string(cg)) != "0::/sahinit/svc.service" || !strings.Contains(string(st), "\nUid:\t65534\t") {
		fatal("sash spawn " + string(cg))
	}
	mark("sash spawn in cgroup sahinit/svc.service as 65534")
	if !owned("/srv/svc/d", true, 0o750) || !owned("/srv/svc/d/f", false, 0) {
		fatal("sash file verbs")
	}
	mark("sash file verbs")
	if m := mounted("/mnt/svc"); !strings.HasPrefix(m, "tmpfs ") || !strings.Contains(m, "nosuid") || !strings.Contains(m, "nodev") || !strings.Contains(m, "noexec") {
		fatal("sash tmpfs mount " + m)
	}
	mark("sash tmpfs mount")
	if out, ok := ctl("start", "revoked"); ok || !strings.Contains(out, "sash_grant_revoked") {
		fatal("sash revoked start: " + out)
	}
	if r := status("revoked"); r.State != "failed" || r.LastError != "sash_grant_revoked" || r.Restarts != 0 {
		fatal(fmt.Sprintf("sash revoked %+v", r))
	}
	if r := status("svc"); r.State != "running" {
		fatal("sash svc after refusal " + r.State)
	}
	mark("sash grant below floor refused")
	if out, ok := ctl("stop", "svc"); !ok {
		fatal("sash stop: " + out)
	}
	row = status("svc")
	stopped := false
	for _, e := range row.Sash.Entries {
		stopped = stopped || e.Entry == "stop" && e.Exit == 0
	}
	if row.State != "stopped" || !stopped || !owned("/srv/svc/stopped", false, 0) {
		fatal(fmt.Sprintf("sash stop entry %+v %+v", row, row.Sash))
	}
	mark("sash stop entry")
	if _, err := os.Stat("/proc/" + pid); !os.IsNotExist(err) {
		fatal("sash spawn survived stop")
	}
	if _, err := os.Stat("/sys/fs/cgroup/sahinit/svc.service"); !os.IsNotExist(err) {
		fatal("sash cgroup left")
	}
	mark("sash cgroup killed")
	if m := mounted("/mnt/svc"); m != "" {
		fatal("sash mount left " + m)
	}
	mark("sash mounts removed")
	syscall.Kill(1, syscall.SIGTERM)
}
