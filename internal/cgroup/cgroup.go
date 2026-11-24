// Package cgroup gives each service its own cgroup v2 below a delegated root.
//
// A service is its cgroup: children that call setsid or fork twice stay in
// it, and killing the cgroup kills them all. The root is the supervisor's own
// cgroup unless a directory is named; it must be writable by the supervisor
// (delegated). The supervisor never mounts cgroup2 or enables controllers
// above its root: that belongs to PID 1 or the outer manager.
//
// Threats: a service cannot move itself out of its cgroup unless it can
// write to cgroup.procs of another cgroup in the hierarchy, which needs write
// access to the delegated root; service cgroups are mode 0755 and owned by
// the supervisor's uid, so a service running as another uid cannot. A
// service running as the supervisor's uid, or as root, can still escape;
// that is outside this package. Service names are checked with unit.NameOK
// before any path is built, so a name cannot leave the root.
package cgroup

import "os"

// Usage is the current use of a service cgroup. A controller that is not
// enabled reads as zero.
type Usage struct {
	MemoryCurrent uint64 `json:"memory_current"`
	PidsCurrent   uint64 `json:"pids_current"`
	CPUUsageUsec  uint64 `json:"cpu_usage_usec"`
}

// Group is a prepared service cgroup, open for a child to join: Dir for
// clone3(CLONE_INTO_CGROUP), Procs (its cgroup.procs, opened for writing)
// for a helper that joins itself before exec.
type Group struct {
	Dir   *os.File
	Procs *os.File
}

// Close closes both files.
func (g *Group) Close() error {
	if g == nil {
		return nil
	}
	var first error
	for _, f := range []*os.File{g.Dir, g.Procs} {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

const (
	// leaf is the cgroup the supervisor moves itself into when its root is
	// its own cgroup, so the root holds no process and controllers can be
	// enabled for the service cgroups ("no internal processes").
	leaf   = "supervisor"
	suffix = ".service"
	// control is where systemd runs ExecReload and similar for a unit with
	// Delegate=yes; it is the outer manager's, like the root itself.
	control = ".control"
	// scratch is the suffix of a throwaway cgroup (PrepareScratch).
	scratch = ".scratch"
)
