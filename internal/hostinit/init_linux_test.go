// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package hostinit

import (
	"reflect"
	"testing"
)

func TestMountpointRequiredOnTmpfsRoot(t *testing.T) {
	root := "1 0 0:1 / / rw - tmpfs rootfs rw\n"
	if mountedAs(root, "/dev", "devtmpfs") || mountedAs(root, "/run", "tmpfs") {
		t.Fatal("ordinary directories counted as mounts")
	}
	dev := root + "2 1 0:2 / /dev rw - devtmpfs devtmpfs rw\n"
	if !mountedAs(dev, "/dev", "devtmpfs") {
		t.Fatal("missed devtmpfs mount")
	}
	if mountedAs(dev+"3 2 0:3 / /dev rw - tmpfs tmpfs rw\n", "/dev", "devtmpfs") {
		t.Fatal("accepted covered devtmpfs")
	}
}

func TestUnmountOrder(t *testing.T) {
	raw := "1 0 8:1 / / rw - ext4 /dev/root rw\n" +
		"2 1 8:2 / /data rw - ext4 /dev/data rw\n" +
		`3 2 8:3 / /data/has\040space rw - ext4 /dev/other rw` + "\n" +
		"4 1 0:1 / /proc rw - proc proc rw\n" +
		"5 1 0:2 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n" +
		"6 1 0:3 / /run rw - tmpfs tmpfs rw\n"
	want := []string{"/data/has space", "/data", "/"}
	if got := mountPaths(raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSwapPaths(t *testing.T) {
	got := swapPaths("Filename Type Size Used Priority\n/swap\\040file file 1024 0 -2\n/dev/vdb partition 2048 0 -3\n")
	if !reflect.DeepEqual(got, []string{"/swap file", "/dev/vdb"}) {
		t.Fatal(got)
	}
}
