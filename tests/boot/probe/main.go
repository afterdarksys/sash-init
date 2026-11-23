//go:build linux

// A purpose-built VM fixture, never included in the installed init binary.
package main

import (
	"fmt"
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
	output, _ = os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if output == nil {
		os.Exit(90)
	}
	mode := "recovery"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
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
