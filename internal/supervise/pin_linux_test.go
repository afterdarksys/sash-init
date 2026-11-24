// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// A peer pinned at accept that exits while its request is read is refused,
// even when its pid now names an unsupervised process. The reuse is
// injected by pointing the pin's pid at the test process.
func TestPeerPinRefusesReuse(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"idle": newSvc("idle", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})})
	peer := exec.Command("/bin/sleep", "60")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(peer.Process.Pid, 0)
	if err != nil {
		peer.Process.Kill()
		peer.Wait()
		t.Skip("no pidfd_open")
	}
	pin := peerPin{fd: fd, pid: peer.Process.Pid}
	defer pin.close()
	if sup.peerRefused(pin) {
		t.Fatal("live unsupervised peer refused")
	}
	peer.Process.Kill()
	peer.Wait()
	pin.pid = os.Getpid()
	if !sup.peerRefused(pin) {
		t.Fatal("reused pid accepted")
	}
	// Without a pidfd the start time stands in for it.
	own := peerPin{fd: -1, pid: os.Getpid(), start: startTime(os.Getpid())}
	if own.start == "" || sup.peerRefused(own) {
		t.Fatalf("start-time pin refused: %+v", own)
	}
	own.start += "0"
	if !sup.peerRefused(own) {
		t.Fatal("start-time mismatch accepted")
	}
	if !sup.peerRefused(peerPin{fd: -1, pid: os.Getpid()}) {
		t.Fatal("unpinned peer accepted")
	}
}

// The pin taken at accept names the connecting process.
func TestPinPeerSocket(t *testing.T) {
	path := tmpPath("pin")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, pid, err := peerCred(conn)
	if err != nil {
		t.Fatal(err)
	}
	pin := pinPeer(conn, pid)
	defer pin.close()
	if pin.fd < 0 || pin.pid != os.Getpid() || !pin.same() {
		t.Fatalf("%+v", pin)
	}
}
