// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

func runHost(args []string, out, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, hostUsage)
		return 2
	}
	switch args[0] {
	case "device-wait":
		f := flag.NewFlagSet("device-wait", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		path := f.String("path", "", "")
		timeout := f.Duration("timeout", 30*time.Second, "")
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 || !filepath.IsAbs(*path) || *timeout <= 0 || *timeout > 5*time.Minute {
			fmt.Fprint(stderr, hostUsage)
			return 2
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		ctx, deadline := context.WithTimeout(ctx, *timeout)
		defer deadline()
		for {
			if st, err := os.Stat(*path); err == nil && st.Mode()&os.ModeDevice != 0 {
				return 0
			}
			select {
			case <-ctx.Done():
				fmt.Fprintln(stderr, "device_timeout")
				return 1
			case <-time.After(50 * time.Millisecond):
			}
		}
	case "notify-adapter":
		return runNotifyAdapter(args[1:], out, stderr)
	default:
		fmt.Fprint(stderr, hostUsage)
		return 2
	}
}

const hostUsage = "usage: sahinit host device-wait --path DEVICE [--timeout DURATION]\n" +
	"usage: sahinit host notify-adapter [--watchdog DURATION] -- PROGRAM [ARG]...\n"

// The adapter accepts READY=1 and WATCHDOG=1 from its direct child's Linux
// SCM_CREDENTIALS only. It forwards readiness/heartbeats to the inherited pipe.
// Other sd_notify features (FDSTORE, MAINPID, barriers) are deliberately absent.
func runNotifyAdapter(args []string, out, stderr io.Writer) int {
	f := flag.NewFlagSet("notify-adapter", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	watchdog := f.Duration("watchdog", 0, "")
	if err := f.Parse(args); err != nil || f.NArg() == 0 || *watchdog < 0 || *watchdog > 5*time.Minute {
		fmt.Fprint(stderr, hostUsage)
		return 2
	}
	fd, err := strconv.Atoi(os.Getenv("SAHINIT_READY_FD"))
	if err != nil || fd != 3 {
		fmt.Fprintln(stderr, "notify_pipe_missing")
		return 2
	}
	// The child must not inherit the ready pipe: it would hold the unit's
	// readiness (and watchdog) without going through the checks below.
	unix.CloseOnExec(fd)
	pipe := os.NewFile(uintptr(fd), "ready")
	defer pipe.Close()
	path, err := unit.ResolveExec(f.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "exec_not_file")
		return 1
	}
	dir, err := os.MkdirTemp("/tmp", "sahn-")
	if err != nil {
		return 1
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return 1
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return 1
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || sockErr != nil {
		return 1
	}
	cmd := exec.Command(path, f.Args()[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = stderr
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SAHINIT_") && !strings.HasPrefix(e, "NOTIFY_SOCKET=") && !strings.HasPrefix(e, "WATCHDOG_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "NOTIFY_SOCKET="+sock)
	if *watchdog > 0 {
		cmd.Env = append(cmd.Env, "WATCHDOG_USEC="+strconv.FormatInt(watchdog.Microseconds(), 10))
	}
	if err := cmd.Start(); err != nil {
		return 1
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	go func() {
		buf, oob := make([]byte, 8192), make([]byte, 256)
		ready := false
		for {
			n, on, flags, _, err := conn.ReadMsgUnix(buf, oob)
			if err != nil {
				return
			}
			if !fromChild(oob[:on], cmd.Process.Pid) || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
				continue
			}
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if line == "READY=1" && !ready {
					if _, err := pipe.Write([]byte{1}); err != nil {
						return
					}
					ready = true
				}
				if line == "WATCHDOG=1" && ready && *watchdog > 0 {
					if _, err := pipe.Write([]byte{1}); err != nil {
						return
					}
				}
			}
		}
	}()
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigs)
	for {
		select {
		case err := <-done:
			if err == nil {
				return 0
			}
			if code := cmd.ProcessState.ExitCode(); code > 0 {
				return code
			}
			return 1
		case sig := <-sigs:
			_ = cmd.Process.Signal(sig)
		}
	}
}

// fromChild reports whether a datagram's control data carries the
// credentials of pid, the adapter's direct child. Any descriptors passed
// along are closed.
func fromChild(oob []byte, pid int) bool {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return false
	}
	matched := false
	for _, m := range msgs {
		if rights, e := unix.ParseUnixRights(&m); e == nil {
			for _, fd := range rights {
				unix.Close(fd)
			}
		}
		if cred, e := unix.ParseUnixCredentials(&m); e == nil && int(cred.Pid) == pid {
			matched = true
		}
	}
	return matched
}
