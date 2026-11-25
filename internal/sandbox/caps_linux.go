// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"errors"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// Capabilities for a non-root unit (docs/design/unit-caps-1.md).
//
// The supervisor starts the helper as the unit's uid with the granted set
// plus CAP_SETPCAP in its permitted, effective, inheritable and ambient sets
// (ambientCaps, through SysProcAttr.AmbientCaps). The helper checks it holds
// exactly that (enterCaps), cuts the bounding set to the granted set, drops
// CAP_SETPCAP and checks again; restrict and the id filter follow, and
// checkCaps runs once more just before exec.
//
// Threats: the helper holds CAP_SETPCAP only between its start and the end
// of enterCaps, and runs only its own code in that window; a same-uid
// process cannot ptrace it then, because its permitted set is not a subset
// of the caller's (ptrace(2), access mode check step 5.2). Every state is
// checked as a whole: a missing, extra or stale bit in any of the five sets
// is sandbox_cap and nothing is executed.

// capMask returns the bit mask of the named caps. An unknown name is
// sandbox_cap.
func capMask(names []string) (uint64, error) {
	var m uint64
	for _, name := range names {
		bit, ok := unit.LookupCap(name)
		if !ok || bit > 63 {
			return 0, fail.E("sandbox_cap")
		}
		m |= 1 << bit
	}
	return m, nil
}

// ambientCaps is the set the supervisor raises in the helper: the granted
// set and CAP_SETPCAP, which the helper needs to cut its bounding set. It is
// a variable so a test can start a helper with a wrong set.
var ambientCaps = func(names []string) ([]uintptr, error) {
	m, err := capMask(names)
	if err != nil {
		return nil, err
	}
	m |= 1 << unix.CAP_SETPCAP
	var out []uintptr
	for bit := uintptr(0); bit < 64; bit++ {
		if m&(1<<bit) != 0 {
			out = append(out, bit)
		}
	}
	return out, nil
}

// capState is the calling thread's capability sets.
type capState struct {
	eff, prm, inh, amb, bnd uint64
}

// lastCap is the kernel's highest capability number, probed with
// PR_CAPBSET_READ, which fails with EINVAL past it.
func lastCap() (int, error) {
	last := -1
	for c := 0; c < 64; c++ {
		_, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if errors.Is(err, unix.EINVAL) {
			break
		}
		if err != nil {
			return 0, fail.E("sandbox_cap")
		}
		last = c
	}
	if last < unix.CAP_SETPCAP {
		return 0, fail.E("sandbox_cap")
	}
	return last, nil
}

func readCaps() (capState, error) {
	var st capState
	var data [2]unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return st, fail.E("sandbox_cap")
	}
	st.eff = uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	st.prm = uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32
	st.inh = uint64(data[0].Inheritable) | uint64(data[1].Inheritable)<<32
	last, err := lastCap()
	if err != nil {
		return st, err
	}
	for c := 0; c <= last; c++ {
		in, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil || in < 0 || in > 1 {
			return st, fail.E("sandbox_cap")
		}
		amb, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(c), 0, 0)
		if err != nil || amb < 0 || amb > 1 {
			return st, fail.E("sandbox_cap")
		}
		st.bnd |= uint64(in) << c
		st.amb |= uint64(amb) << c
	}
	return st, nil
}

// checkCaps requires every set, the bounding set included, to be exactly
// want.
func checkCaps(want uint64) error {
	st, err := readCaps()
	if err != nil {
		return err
	}
	if st.eff != want || st.prm != want || st.inh != want || st.amb != want || st.bnd != want {
		return fail.E("sandbox_cap")
	}
	return nil
}

// enterCaps runs first in a helper whose unit holds caps: it checks the
// helper holds exactly the granted set and CAP_SETPCAP in every set but the
// bounding set, drops every other capability from the bounding set
// (CAP_SETPCAP last), capsets the granted set (which lowers CAP_SETPCAP from
// the ambient set with it) and checks that all five sets are then exactly
// the granted set.
func enterCaps(names []string) error {
	want, err := capMask(names)
	if err != nil {
		return err
	}
	if want == 0 {
		return fail.E("sandbox_cap")
	}
	entry := want | 1<<unix.CAP_SETPCAP
	st, err := readCaps()
	if err != nil {
		return err
	}
	if st.eff != entry || st.prm != entry || st.inh != entry || st.amb != entry || st.bnd&entry != entry {
		return fail.E("sandbox_cap")
	}
	last, err := lastCap()
	if err != nil {
		return err
	}
	for c := 0; c <= last; c++ {
		if want&(1<<c) != 0 || c == unix.CAP_SETPCAP {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fail.E("sandbox_cap")
		}
	}
	if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SETPCAP, 0, 0, 0); err != nil {
		return fail.E("sandbox_cap")
	}
	if err := setCaps(want); err != nil {
		return err
	}
	return checkCaps(want)
}

// setCaps sets the effective, permitted and inheritable sets to m.
func setCaps(m uint64) error {
	var data [2]unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	for i := range data {
		v := uint32(m >> (32 * i))
		data[i] = unix.CapUserData{Effective: v, Permitted: v, Inheritable: v}
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fail.E("sandbox_cap")
	}
	return nil
}
