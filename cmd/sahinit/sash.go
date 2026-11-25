// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
	"github.com/afterdarksys/sahinit/internal/supervise"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const sashUsage = "usage: sahinit sash floor-install --dir DIR --fleet-pub PATH FILE\n" +
	"usage: sahinit sash floor-show --dir DIR --fleet-pub PATH [SERVICE]\n"

// readFleetPub reads the fleet public key: a file reached by the trusted
// walk, owned by root (or the supervisor's uid), not group- or
// other-writable, holding 32 raw bytes or 64 hex digits (and an optional
// newline).
//
// Threats: whoever can replace this key can sign grants and floors for
// every sash service on the host.
func readFleetPub(p string) (ed25519.PublicKey, error) {
	bad := fail.E("sash_fleet_key")
	r, err := unit.ResolveTrusted(p)
	if err != nil {
		return nil, bad
	}
	f, err := os.OpenFile(r, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, bad
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, bad
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (sys.Uid != 0 && sys.Uid != uint32(os.Geteuid())) || st.Mode().Perm()&0o022 != 0 {
		return nil, bad
	}
	raw, err := io.ReadAll(io.LimitReader(f, 130))
	if err != nil {
		return nil, bad
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) == 2*ed25519.PublicKeySize {
		if k, err := hex.DecodeString(text); err == nil {
			return ed25519.PublicKey(k), nil
		}
	}
	return nil, bad
}

func runSash(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "floor-install" && args[0] != "floor-show") {
		fmt.Fprint(stderr, sashUsage)
		return 2
	}
	fs := flag.NewFlagSet("sash", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	pub := fs.String("fleet-pub", "", "")
	if err := fs.Parse(args[1:]); err != nil || *dir == "" || *pub == "" || (args[0] == "floor-install" && fs.NArg() != 1) || fs.NArg() > 1 {
		fmt.Fprint(stderr, sashUsage)
		return 2
	}
	key, err := readFleetPub(*pub)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 1
	}
	store, err := sash.OpenFloorStore(*dir, key)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 1
	}
	defer store.Close()
	show := func(d *sash.FloorDoc) {
		f := d.Floor()
		b, _ := json.Marshal(map[string]any{"service": f.Service, "min_serial": f.MinSerial, "issued_at": f.IssuedAt, "digest": d.Digest()})
		fmt.Fprintln(stdout, string(b))
	}
	if args[0] == "floor-install" {
		raw, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, "failed")
			return 1
		}
		d, err := store.Install(raw)
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
		show(d)
		return 0
	}
	names := []string{fs.Arg(0)}
	if fs.NArg() == 0 {
		if names, err = store.Services(); err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			return 1
		}
	}
	code := 0
	for _, n := range names {
		d, err := store.Floor(n)
		if err == nil && d == nil {
			err = fail.E("sash_floor_missing")
		}
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err), n)
			code = 1
			continue
		}
		show(d)
	}
	return code
}

// sashFlags are supervise's sash settings. hostDecl is --host-decl ("" is
// the default path, where a missing file means no declarations); hostID is
// the trust file's host_id ("" without --trust).
type sashFlags struct {
	binary, fleetPub, floorDir string
	hostDecl, hostID           string
}

// loadHostDecl reads host.json and checks the units it names against the
// catalog: a unit profile's unit must exist and not be a boot unit.
func loadHostDecl(f sashFlags, svcs map[string]*unit.Service) (*sash.HostDecl, error) {
	p := f.hostDecl
	if p == "" {
		p = unit.DefaultHostDecl
	}
	decl, err := unit.LoadHostDecl(p, f.hostDecl != "")
	if err != nil || decl == nil {
		return decl, err
	}
	units, _ := decl.ProfileUnits()
	for _, u := range units {
		if svc, ok := svcs[u]; !ok || svc.Boot {
			return nil, fail.E("host_decl_invalid")
		}
	}
	return decl, nil
}

// refuseBootOps leaves out every boot-ops unit, named on stderr as
// "TOKEN FILE", when host.json could not be used (declErr), and returns how
// many it left out.
func refuseBootOps(svcs map[string]*unit.Service, declErr error, stderr io.Writer) int {
	if declErr == nil {
		return 0
	}
	var names []string
	for n, svc := range svcs {
		if svc.Sash != nil && svc.Sash.BootOps {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintln(stderr, fail.Token(declErr), n+".json")
		delete(svcs, n)
	}
	return len(names)
}

// setupSash prepares every sash unit in svcs: the sash binary, the fleet
// key and the floor store, then sash --describe for each, deriving its
// unit. A unit that fails is left out and named on stderr as "TOKEN FILE";
// the rest of the catalog still loads. A boot-ops unit is also refused when
// host.json is not usable (host_decl_invalid or host_decl_perm). It returns
// the config for the supervisor (nil when there is no sash unit) and how
// many were refused.
func setupSash(f sashFlags, svcs map[string]*unit.Service, root *cgroup.Root, self string, stderr io.Writer) (*supervise.SashConfig, int) {
	var names []string
	for name, svc := range svcs {
		if svc.Sash != nil {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, 0
	}
	sort.Strings(names)
	refuse := func(tok string) (*supervise.SashConfig, int) {
		for _, n := range names {
			fmt.Fprintln(stderr, tok, n+".json")
			delete(svcs, n)
		}
		return nil, len(names)
	}
	bin, err := unit.ResolveExec(f.binary)
	if err != nil {
		return refuse("sash_binary")
	}
	if f.fleetPub == "" {
		return refuse("sash_fleet_key")
	}
	key, err := readFleetPub(f.fleetPub)
	if err != nil {
		return refuse(fail.Token(err))
	}
	if f.floorDir == "" {
		return refuse("sash_floor_store")
	}
	store, err := sash.OpenFloorStore(f.floorDir, key)
	if err != nil {
		return refuse("sash_floor_store")
	}
	if root == nil {
		store.Close()
		return refuse("sash_cgroups")
	}
	decl, declErr := loadHostDecl(f, svcs)
	refused := refuseBootOps(svcs, declErr, stderr)
	lookUser, lookGroup := supervise.LookupIDs()
	for _, n := range names {
		svc, ok := svcs[n]
		if !ok {
			continue
		}
		d, err := supervise.Describe(context.Background(), root, self, bin, svc)
		if err == nil {
			err = unit.ApplyDescribe(svc, d, lookUser, lookGroup)
		}
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err), n+".json")
			delete(svcs, n)
			refused++
		}
	}
	return &supervise.SashConfig{Binary: bin, Fleet: key, Floors: store, StateDir: f.floorDir, HostID: f.hostID, HostDecl: decl}, refused
}
