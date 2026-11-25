// SPDX-License-Identifier: GPL-3.0-or-later

package sash

// The boot verbs: the verb server's side (sash's
// docs/plans/2026-11-24-sash-boot-verbs-contract.md, "Per-verb rules").
//
// Threats: a compromised boot script, running unprivileged in its cgroup,
// asks for host operations by name. Every request is checked here again,
// never trusting that sash checked it, through the contract's gates in
// order: the key is in entitlements (denied); the grant is a sash/3 boot
// grant (denied, even when a sash/1 or sash/2 grant lists the key); the
// unit opted in (sash_boot_ops); the session is a start entry, never check
// (boot_entry); the boot waves have not ended (boot_over); the service has
// boot calls left this boot, counted across sessions so a restart gets no
// fresh budget (boot_call_limit); and nothing but Key and Argv is set
// (denied). Then each verb's argv has its exact shape and its name is in
// the grant's list for that verb (denied) and, for a device, mount or
// profile, declared in host.json (not_found): the script never supplies a
// path, target, address, interface or file. A host mount may not lie at,
// under or above a file_write root (mount_overlap), and a device source
// must have been checked by device wait earlier in this boot
// (device_changed), so the mount goes through a checked dev_t. service
// start and stop never reach the caller (boot_self), another boot-ops unit
// (boot_chain), a boot unit (boot_unit_auto), a unit that needs or comes
// after the caller (boot_cycle) or an essential unit (boot_essential, stop),
// and each unit at most once per boot each way (boot_once), which with the
// budget rules out stop/start loops. A host error is passed on only as one
// of the contract's codes, never an errno or a path; anything else is
// failed. Does NOT perform anything: BootHost does, and re-checks what only
// the kernel can tell (the module tree, the device node and its sysfs
// identity, mountinfo, netlink).

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// MaxBootCalls is the most boot verbs one service may call in one boot.
const MaxBootCalls = 64

// maxDeviceWait is the longest device wait one call may ask for.
const maxDeviceWait = 60

// bootKeys are the boot keys. A check session refuses every one
// (boot_entry), device wait included, so none needs a mutates flag.
var bootKeys = map[string]bool{
	"boot.module": true, "boot.device": true, "boot.mount": true,
	"boot.net": true, "boot.start": true, "boot.stop": true,
}

// bootCodes are the host errors a boot verb answers with as they are.
var bootCodes = map[string]bool{
	"module_disabled": true, "module_sig_unenforced": true, "module_tree": true, "module_unknown": true, "module_failed": true,
	"device_unsafe": true, "device_mismatch": true, "device_absent": true, "device_changed": true,
	"mount_target": true, "mount_conflict": true, "mount_failed": true, "mount_overlap": true,
	"net_unknown_link": true, "net_unguarded": true, "net_failed": true,
	"busy": true, "not_found": true, "timeout": true, "denied": true, "unsupported": true,
}

// DevID is a device number.
type DevID struct{ Major, Minor uint32 }

// UnitInfo is what the start and stop rules read of a catalog unit.
type UnitInfo struct {
	Boot, BootOps, Essential bool
	Needs, After             []string
}

// ModuleResult is a module load's answer: done or already, and the
// dependencies loaded first, in modules.dep's order.
type ModuleResult struct {
	State string
	Deps  []string
}

// NetResult is a network apply's answer.
type NetResult struct {
	Link    string
	State   string
	Changes int
}

// HostMountPlan is a checked mount ensure: the declaration, and for a
// device source its declaration and the dev_t device wait recorded.
type HostMountPlan struct {
	Name   string
	Decl   MountDecl
	Device *DeviceDecl
	Dev    DevID
}

// BootHost performs the boot verbs the server has checked. Each call is
// bounded by ctx, which ends with the session.
type BootHost interface {
	// LoadModule loads name and its modules.dep dependencies from the
	// trusted module tree.
	LoadModule(ctx context.Context, name string) (ModuleResult, error)
	// WaitDevice waits up to d for decl's node and checks its identity.
	WaitDevice(ctx context.Context, name string, decl DeviceDecl, d time.Duration) (DevID, error)
	// EnsureMount mounts plan's source at its target unless it is there.
	EnsureMount(ctx context.Context, plan HostMountPlan) (string, error)
	// ApplyNetwork adds a static profile's mtu, addresses and routes.
	ApplyNetwork(ctx context.Context, name string, decl NetworkDecl) (NetResult, error)
	// Unit is a catalog unit's start and stop facts (not_found when there
	// is none).
	Unit(name string) (UnitInfo, error)
	// StartUnit and StopUnit start and stop a catalog unit as ctl does
	// (user=true) and answer its status row, and whether it was already
	// running (or exited 0) or already stopped.
	StartUnit(ctx context.Context, name string) (Row, bool, error)
	StopUnit(ctx context.Context, name string) (Row, bool, error)
}

// BootState is one boot's record, shared by every session: the boot calls
// each service made, the devices each service's device wait checked, and
// the units a boot verb started or stopped (one set for both, so a unit is
// touched at most once per boot whichever way).
type BootState struct {
	// Over reports that the boot waves have ended.
	Over func() bool

	mu      sync.Mutex
	calls   map[string]int
	devs    map[string]DevID // service + "/" + device
	touched map[string]bool
}

// NewBootState is a fresh boot record; over reports the end of boot.
func NewBootState(over func() bool) *BootState {
	return &BootState{Over: over, calls: map[string]int{}, devs: map[string]DevID{}, touched: map[string]bool{}}
}

func (b *BootState) spend(service string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.calls[service] >= MaxBootCalls {
		return false
	}
	b.calls[service]++
	return true
}

// Calls is how many boot verbs service has called this boot.
func (b *BootState) Calls(service string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[service]
}

func (b *BootState) dev(service, name string) (DevID, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.devs[service+"/"+name]
	return d, ok
}

func (b *BootState) setDev(service, name string, d DevID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.devs[service+"/"+name] = d
}

// once marks unit touched and reports whether it was the first time.
func (b *BootState) once(unit string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.touched[unit] {
		return false
	}
	b.touched[unit] = true
	return true
}

func bootErr(err error) error {
	if bootCodes[fail.Token(err)] {
		return err
	}
	return fail.E("failed")
}

var unitCols = []string{"name", "state", "since", "pid"}

// boot answers one boot verb: the gates, then the verb's own checks.
func (s *Server) boot(req Request) (Response, error) {
	switch {
	case !s.G.Has(req.Key) || !s.G.BootOps():
		return Response{}, errDenied
	case !s.BootOps:
		return Response{}, fail.E("sash_boot_ops")
	case s.Entry != "start" || s.Check:
		return Response{}, fail.E("boot_entry")
	case s.Boot == nil || s.Boot.Over == nil || s.Boot.Over():
		return Response{}, fail.E("boot_over")
	case !s.Boot.spend(s.G.Service):
		return Response{}, fail.E("boot_call_limit")
	case req.Path != "" || len(req.Body) > 0 || req.Mode != "":
		return Response{}, errDenied
	}
	bh, ok := s.Host.(BootHost)
	if !ok {
		return Response{}, errUnsupported
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	a := req.Argv
	switch req.Key {
	case "boot.module":
		if len(a) != 3 || a[0] != "module" || a[1] != "load" || !ModuleName.MatchString(a[2]) || !exact(s.G.Modules, a[2]) {
			return Response{}, errDenied
		}
		r, err := bh.LoadModule(ctx, a[2])
		if err != nil {
			return Response{}, bootErr(err)
		}
		return rows([]string{"name", "state", "deps"}, Row{"name": a[2], "state": r.State, "deps": strings.Join(r.Deps, ",")}), nil
	case "boot.device":
		return s.deviceWait(ctx, bh, a)
	case "boot.mount":
		return s.mountEnsure(ctx, bh, a)
	case "boot.net":
		return s.networkApply(ctx, bh, a)
	case "boot.start", "boot.stop":
		start := req.Key == "boot.start"
		list, word := s.G.UnitsStop, "stop"
		if start {
			list, word = s.G.UnitsStart, "start"
		}
		if len(a) != 3 || a[0] != "service" || a[1] != word || !UnitName.MatchString(a[2]) || !exact(list, a[2]) {
			return Response{}, errDenied
		}
		row, _, err := s.unitVerb(ctx, bh, a[2], start)
		if err != nil {
			return Response{}, err
		}
		return rows(unitCols, row), nil
	}
	return Response{}, errUnsupported
}

func (s *Server) deviceWait(ctx context.Context, bh BootHost, a []string) (Response, error) {
	if len(a) != 5 || a[0] != "device" || a[1] != "wait" || a[3] != "timeout" || !BootName.MatchString(a[2]) || !exact(s.G.Devices, a[2]) {
		return Response{}, errDenied
	}
	n, err := strconv.Atoi(a[4])
	if err != nil || n < 1 || n > maxDeviceWait || strconv.Itoa(n) != a[4] {
		return Response{}, errDenied
	}
	decl, ok := s.declDevice(a[2])
	if !ok {
		return Response{}, fail.E("not_found")
	}
	d := time.Duration(n) * time.Second
	if !s.Deadline.IsZero() {
		if left := s.Deadline.Sub(s.now()); left < d {
			d = left
		}
	}
	if d <= 0 {
		return Response{}, fail.E("timeout")
	}
	dev, err := bh.WaitDevice(ctx, a[2], decl, d)
	if err != nil {
		return Response{}, bootErr(err)
	}
	s.Boot.setDev(s.G.Service, a[2], dev)
	return rows([]string{"name", "path", "major", "minor"}, Row{"name": a[2], "path": decl.Path,
		"major": strconv.FormatUint(uint64(dev.Major), 10), "minor": strconv.FormatUint(uint64(dev.Minor), 10)}), nil
}

func (s *Server) mountEnsure(ctx context.Context, bh BootHost, a []string) (Response, error) {
	if len(a) != 3 || a[0] != "mount" || a[1] != "ensure" || !BootName.MatchString(a[2]) || !exact(s.G.HostMounts, a[2]) {
		return Response{}, errDenied
	}
	if s.Decl == nil {
		return Response{}, fail.E("not_found")
	}
	m, ok := s.Decl.Mounts[a[2]]
	if !ok {
		return Response{}, fail.E("not_found")
	}
	for _, root := range s.G.FileWrite {
		if within(m.Target, root) || within(root, m.Target) {
			return Response{}, fail.E("mount_overlap")
		}
	}
	plan := HostMountPlan{Name: a[2], Decl: m}
	if m.Source != "tmpfs" {
		dd, ok := s.declDevice(m.Source)
		if !ok {
			return Response{}, fail.E("not_found")
		}
		// No device wait for this device by this service earlier in this
		// boot: there is no checked dev_t to mount through. This is
		// device_changed even when the device is also absent (phase 1
		// note 7): the server cannot look, and the host is not asked.
		dev, waited := s.Boot.dev(s.G.Service, m.Source)
		if !waited {
			return Response{}, fail.E("device_changed")
		}
		plan.Device, plan.Dev = &dd, dev
	}
	state, err := bh.EnsureMount(ctx, plan)
	if err != nil {
		return Response{}, bootErr(err)
	}
	return rows([]string{"name", "target", "fstype", "state"}, Row{"name": a[2], "target": m.Target, "fstype": m.FSType, "state": state}), nil
}

func (s *Server) networkApply(ctx context.Context, bh BootHost, a []string) (Response, error) {
	if len(a) != 3 || a[0] != "network" || a[1] != "apply" || !BootName.MatchString(a[2]) || !exact(s.G.NetProfiles, a[2]) {
		return Response{}, errDenied
	}
	if s.Decl == nil {
		return Response{}, fail.E("not_found")
	}
	n, ok := s.Decl.Network[a[2]]
	if !ok {
		return Response{}, fail.E("not_found")
	}
	cols := []string{"name", "link", "state", "changes"}
	if n.Kind == "unit" {
		// The profile is the unit's grant: the start rules apply, except
		// the units_start listing.
		_, already, err := s.unitVerb(ctx, bh, n.Unit, true)
		if err != nil {
			return Response{}, err
		}
		state := "done"
		if already {
			state = "already"
		}
		return rows(cols, Row{"name": a[2], "link": "", "state": state, "changes": "0"}), nil
	}
	for _, u := range n.Requires {
		row, err := s.Host.Status(u)
		if err != nil || (row["state"] != "ready" && row["state"] != "exited") {
			return Response{}, fail.E("net_unguarded")
		}
	}
	r, err := bh.ApplyNetwork(ctx, a[2], n)
	if err != nil {
		return Response{}, bootErr(err)
	}
	return rows(cols, Row{"name": a[2], "link": r.Link, "state": r.State, "changes": strconv.Itoa(r.Changes)}), nil
}

// unitVerb checks the start or stop rules for name, then performs it, and
// answers the unit's status row and whether it already matched.
func (s *Server) unitVerb(ctx context.Context, bh BootHost, name string, start bool) (Row, bool, error) {
	info, err := bh.Unit(name)
	if err != nil {
		return nil, false, fail.E("not_found")
	}
	switch {
	case name == s.G.Service:
		return nil, false, fail.E("boot_self")
	case info.BootOps:
		return nil, false, fail.E("boot_chain")
	case start && info.Boot:
		return nil, false, fail.E("boot_unit_auto")
	case start && s.reaches(bh, name, map[string]bool{}):
		return nil, false, fail.E("boot_cycle")
	case !start && info.Essential:
		return nil, false, fail.E("boot_essential")
	}
	if !s.Boot.once(name) {
		return nil, false, fail.E("boot_once")
	}
	var row Row
	var already bool
	if start {
		row, already, err = bh.StartUnit(ctx, name)
	} else {
		row, already, err = bh.StopUnit(ctx, name)
	}
	if err != nil {
		return nil, false, bootErr(err)
	}
	out := Row{}
	for _, c := range unitCols {
		out[c] = row[c]
	}
	return out, already, nil
}

// reaches reports whether from needs or comes after the caller, directly
// or through other units.
func (s *Server) reaches(bh BootHost, from string, seen map[string]bool) bool {
	if seen[from] {
		return false
	}
	seen[from] = true
	info, err := bh.Unit(from)
	if err != nil {
		return false
	}
	for _, list := range [][]string{info.Needs, info.After} {
		for _, n := range list {
			if n == s.G.Service || s.reaches(bh, n, seen) {
				return true
			}
		}
	}
	return false
}

func (s *Server) declDevice(name string) (DeviceDecl, bool) {
	if s.Decl == nil {
		return DeviceDecl{}, false
	}
	d, ok := s.Decl.Devices[name]
	return d, ok
}
