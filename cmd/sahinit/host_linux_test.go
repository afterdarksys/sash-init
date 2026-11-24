// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Only datagrams carrying the direct child's pid count.
func TestNotifyFromChildOnly(t *testing.T) {
	oob := func(pid int32) []byte {
		return unix.UnixCredentials(&unix.Ucred{Pid: pid, Uid: 0, Gid: 0})
	}
	if !fromChild(oob(4242), 4242) {
		t.Fatal("the child's credentials refused")
	}
	if fromChild(oob(4243), 4242) || fromChild(nil, 4242) {
		t.Fatal("another process's credentials accepted")
	}
}

func TestNotifyAdapterHelper(t *testing.T) {
	if os.Getenv("SAHINIT_ADAPTER_HELPER") != "1" {
		return
	}
	os.Exit(runNotifyAdapter([]string{"--", "/bin/sh", "-c", `if [ -e /proc/$$/fd/3 ]; then echo leaked; else echo clean; fi`}, os.Stdout, os.Stderr))
}

// The adapter's child does not inherit the ready pipe (fd 3).
func TestNotifyAdapterClosesReadyPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNotifyAdapterHelper$")
	cmd.Env = append(os.Environ(), "SAHINIT_ADAPTER_HELPER=1", "SAHINIT_READY_FD=3")
	cmd.ExtraFiles = []*os.File{w}
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	w.Close()
	if err != nil || !strings.Contains(out.String(), "clean") {
		t.Fatalf("%v %q", err, out.String())
	}
}
