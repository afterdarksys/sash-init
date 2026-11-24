package sash

// The mount allowlists, copied from sash's internal/grant/policy.go
// (feat/init-phase1 at f28285b). testdata/sash-mount-vectors.json holds
// sash's own answers, and TestMountTablesMatchSash compares.
//
// Threats: a mount whose type or options bring another tree in (overlay
// lowerdir, move, x-bind) or re-enable setuid binaries and device nodes.
// Both lists are allowlists: a type or option not listed is refused.

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// MountTypes are the filesystem types mount may name.
var MountTypes = map[string]bool{"tmpfs": true, "proc": true, "sysfs": true, "devpts": true}

var (
	mountFlags = map[string]bool{"ro": true, "rw": true, "nosuid": true, "nodev": true, "noexec": true, "bind": true, "rbind": true, "remount": true}
	mountSize  = regexp.MustCompile(`^[0-9]{1,15}[kmg%]?$`)
	mountNum   = regexp.MustCompile(`^[0-9]{1,10}$`)
	mountMode  = regexp.MustCompile(`^[0-7]{3,4}$`)
)

const mountIDMax = 1<<32 - 2

func mountValueOK(k, v string) bool {
	switch k {
	case "size", "nr_inodes":
		if !mountSize.MatchString(v) {
			return false
		}
		num, unit := v, byte(0)
		if c := v[len(v)-1]; c < '0' || c > '9' {
			num, unit = v[:len(v)-1], c
		}
		n, err := strconv.ParseUint(num, 10, 64)
		if err != nil || (unit == '%' && (k != "size" || n > 100)) {
			return false
		}
		shift := map[byte]uint{'k': 10, 'm': 20, 'g': 30}[unit]
		return n <= (1<<63-1)>>shift
	case "mode":
		n, err := strconv.ParseUint(v, 8, 32)
		return mountMode.MatchString(v) && err == nil && n <= 0o1777
	case "uid", "gid":
		n, err := strconv.ParseUint(v, 10, 64)
		return mountNum.MatchString(v) && err == nil && n <= mountIDMax
	}
	return false
}

// MountForcedOpts are on every mount.
var MountForcedOpts = []string{"nosuid", "nodev"}

// CheckMountOpts checks a mount's source, type ("" for a bind) and options,
// as sash does; it returns whether the mount is a bind.
func CheckMountOpts(src, typ string, opts []string) (bool, error) {
	bind, ro, rw := false, false, false
	for _, o := range opts {
		k, v, hasVal := strings.Cut(o, "=")
		switch {
		case !hasVal && mountFlags[o]:
			bind = bind || o == "bind" || o == "rbind"
			ro, rw = ro || o == "ro", rw || o == "rw"
		case hasVal && mountValueOK(k, v):
		default:
			return false, fail.E("mount_opt_refused")
		}
	}
	if ro && rw || bind && typ != "" || !bind && (!MountTypes[typ] || src != typ) {
		return false, fail.E("mount_opt_refused")
	}
	return bind, nil
}

// AllowsMount reports whether dir is exactly one of the mount points.
func (g Grant) AllowsMount(dir string) bool { return exact(g.Mounts, dir) }

// AllowsMountSource reports whether src is a listed name, or a clean path
// equal to or beneath a listed path.
func (g Grant) AllowsMountSource(src string) bool {
	if !strings.HasPrefix(src, "/") {
		return exact(g.MountSources, src)
	}
	if path.Clean(src) != src {
		return false
	}
	return under(g.MountSources, src)
}
