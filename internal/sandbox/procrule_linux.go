// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// A unit holding setuid or setgid must not be able to write any procfs
// (docs/design/unit-caps-1.md, sandbox_proc).
//
// Threats: Landlock rules attach to the inode a path names, so a
// read_write path that is a procfs (a bind mount of /proc, say) makes /proc
// itself writable, and one with a procfs mounted anywhere beneath it makes
// that procfs writable. Either would let the service write a user
// namespace's id map. The load rule sees only path names; these checks see
// the filesystems. A mount made after the check (by root) is not covered.

// notProc refuses an open read_write path that is itself a procfs.
func notProc(fd int) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return fail.E("failed")
	}
	if st.Type == unix.PROC_SUPER_MAGIC {
		return fail.E("sandbox_proc")
	}
	return nil
}

// noProcInMounts refuses when a procfs is mounted at or beneath any of the
// paths, as listed in this mount namespace's /proc/self/mountinfo.
func noProcInMounts(paths []string) error {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return fail.E("failed")
	}
	defer f.Close()
	return noProcBeneath(f, paths)
}

// noProcBeneath is noProcInMounts reading mountinfo from r. A read error
// fails closed.
func noProcBeneath(r io.Reader, paths []string) error {
	raw, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return fail.E("failed")
	}
	points, err := procMounts(raw)
	if err != nil {
		return err
	}
	for _, mp := range points {
		for _, p := range paths {
			if mp == p || p == "/" || strings.HasPrefix(mp, p+"/") {
				return fail.E("sandbox_proc")
			}
		}
	}
	return nil
}

// procMounts returns the mount points of every proc mount in mountinfo
// (proc(5): field 5 is the mount point, the type follows the " - "
// separator). Mount points are octal-escaped (\040 for a space).
func procMounts(raw []byte) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			return nil, fail.E("failed")
		}
		f := strings.Fields(pre)
		t := strings.Fields(post)
		if len(f) < 5 || len(t) < 1 {
			return nil, fail.E("failed")
		}
		if t[0] != "proc" {
			continue
		}
		mp, err := unescapeMount(f[4])
		if err != nil {
			return nil, err
		}
		out = append(out, mp)
	}
	if sc.Err() != nil {
		return nil, fail.E("failed")
	}
	return out, nil
}

func unescapeMount(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", fail.E("failed")
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fail.E("failed")
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}
