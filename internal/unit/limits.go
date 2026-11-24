// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
)

// Limits are the optional cgroup limits of a unit. A zero field is no limit.
// They are written to the service's cgroup before the child starts; a
// controller the supervisor cannot use refuses the unit (cgroup_controller)
// and is never ignored.
type Limits struct {
	MemoryMax uint64 // bytes, memory.max
	PidsMax   uint64 // pids.max
	CPUQuota  uint64 // microseconds per period, cpu.max
	CPUPeriod uint64
}

const (
	minMemory    = 1 << 20
	maxMemory    = 1 << 50
	maxPids      = 4194304 // PID_MAX_LIMIT
	minCPUPeriod = 1000
	maxCPUPeriod = 1000000
	minCPUQuota  = 1000
	maxCPUs      = 1024
)

var (
	memoryRE = regexp.MustCompile(`^[1-9][0-9]{0,15}[KMG]?$`)
	cpuRE    = regexp.MustCompile(`^[1-9][0-9]{0,12} [1-9][0-9]{0,6}$`)
)

// cgroupMount is where the cgroup2 hierarchy is mounted.
const cgroupMount = "/sys/fs/cgroup"

// cgroupBypassCaps are the capabilities a sandboxed unit may keep that let
// it write cgroupfs files it does not own: dac_override and fowner bypass
// the file permission check, chown can take a file over, setuid can become
// the supervisor's uid, and sys_admin can mount or unshare its own view.
// dac_read_search only bypasses reads and is not in the list.
var cgroupBypassCaps = map[string]bool{"dac_override": true, "fowner": true, "chown": true, "setuid": true, "sys_admin": true}

// CgroupTrusted reports whether svc may be able to write cgroup.procs under
// the delegated root, and so leave its cgroup (or stop the supervisor).
// Kill-all, limits and peer_supervised are promised only for the others.
// It is trusted when it runs without a sandbox as root or as the
// supervisor's own uid; or, sandboxed, when a read_write path is
// /sys/fs/cgroup, an ancestor of it ("/", "/sys", "/sys/fs") or a path
// inside it, or when it keeps a capability in cgroupBypassCaps.
func CgroupTrusted(svc *Service) bool {
	if svc == nil {
		return false
	}
	if sb := svc.Sandbox; sb != nil {
		for _, p := range sb.ReadWrite {
			if p == "/" || p == cgroupMount || strings.HasPrefix(cgroupMount, p+"/") || strings.HasPrefix(p, cgroupMount+"/") {
				return true
			}
		}
		for _, c := range sb.Caps {
			if cgroupBypassCaps[c] {
				return true
			}
		}
		return false
	}
	uid := svc.Execution.UID
	return uid == nil || *uid == 0 || *uid == uint32(os.Geteuid())
}

// Any reports whether some limit is set.
func (l Limits) Any() bool {
	return l.MemoryMax != 0 || l.PidsMax != 0 || l.CPUQuota != 0
}

// Controllers names the cgroup v2 controllers the limits need.
func (l Limits) Controllers() []string {
	var out []string
	if l.CPUQuota != 0 {
		out = append(out, "cpu")
	}
	if l.MemoryMax != 0 {
		out = append(out, "memory")
	}
	if l.PidsMax != 0 {
		out = append(out, "pids")
	}
	return out
}

// CPUMax is the cpu.max line ("QUOTA PERIOD"), or "" without a CPU limit.
func (l Limits) CPUMax() string {
	if l.CPUQuota == 0 {
		return ""
	}
	return strconv.FormatUint(l.CPUQuota, 10) + " " + strconv.FormatUint(l.CPUPeriod, 10)
}

// parseLimits reads memory_max ("64M": bytes with an optional K, M or G
// binary suffix, at least 1M), pids_max (an integer from 1 to 4194304) and
// cpu_max ("QUOTA PERIOD" in microseconds: period 1000 to 1000000, quota at
// least 1000 and at most 1024 periods). Anything else is limit_invalid.
func parseLimits(obj map[string]json.RawMessage) (Limits, error) {
	var l Limits
	bad := fail.E("limit_invalid")
	if raw, ok := obj["memory_max"]; ok {
		var s string
		if err := jsonobj.Unmarshal(raw, &s); err != nil || !memoryRE.MatchString(s) {
			return l, bad
		}
		mult := uint64(1)
		switch s[len(s)-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		}
		n, err := strconv.ParseUint(strings.TrimRight(s, "KMG"), 10, 64)
		if err != nil || n > maxMemory/mult || n*mult < minMemory {
			return l, bad
		}
		l.MemoryMax = n * mult
	}
	if raw, ok := obj["pids_max"]; ok {
		var v uint64
		if err := jsonobj.Unmarshal(raw, &v); err != nil || v < 1 || v > maxPids {
			return l, bad
		}
		l.PidsMax = v
	}
	if raw, ok := obj["cpu_max"]; ok {
		var s string
		if err := jsonobj.Unmarshal(raw, &s); err != nil || !cpuRE.MatchString(s) {
			return l, bad
		}
		q, p, _ := strings.Cut(s, " ")
		quota, err1 := strconv.ParseUint(q, 10, 64)
		period, err2 := strconv.ParseUint(p, 10, 64)
		if err1 != nil || err2 != nil || period < minCPUPeriod || period > maxCPUPeriod ||
			quota < minCPUQuota || quota > period*maxCPUs {
			return l, bad
		}
		l.CPUQuota, l.CPUPeriod = quota, period
	}
	return l, nil
}
