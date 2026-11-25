// SPDX-License-Identifier: GPL-3.0-or-later

package sash

// Host declarations (host.json): what each boot verb name means on this
// host (sash's docs/plans/2026-11-24-sash-boot-verbs-contract.md, "Host
// declarations").
//
// Threats: the grant (fleet key) only says which names a boot script may
// use; host.json (root on this host) says what each name is, so a forged or
// loosened declaration is a host takeover by name. ParseHostDecl reads it
// strictly and fails closed: at most 64 KiB; every key exact,
// case-sensitive and once per object (encoding/json alone would match keys
// without case and keep the last of a duplicate); no null anywhere; one
// document and nothing after it; at most 64 entries per table. A device is
// a clean path under /dev with a known kind and at most 8 known sysfs match
// attributes; a mount is an allowed fstype from a declared device (or
// tmpfs), at a clean absolute target that no other mount shares, with
// allowlisted options and no contradicting pair (ro/rw, suid/nosuid,
// dev/nodev); a network profile is static (a MAC, an optional kernel name,
// mtu, at most 8 addresses and 16 routes) or names a unit. A static profile
// with a public address must list requires (decision 5), so it goes live
// only behind a firewall unit. Does NOT check the file's owner and mode
// (unit.LoadHostDecl does, with the trusted walk), that a profile's unit
// exists and is not a boot unit (the catalog's check at load), or that a
// path has no symlink component (the device check opens it with
// RESOLVE_NO_SYMLINKS).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// MaxHostDecl is the largest host.json sahinit reads.
const MaxHostDecl = 64 * 1024

const maxHostTable = 64

// HostDecl is a parsed host.json.
type HostDecl struct {
	Devices map[string]DeviceDecl  `json:"devices"`
	Mounts  map[string]MountDecl   `json:"mounts"`
	Network map[string]NetworkDecl `json:"network"`
}

// DeviceDecl is one device: its node, its kind and the sysfs attributes
// that identify it.
type DeviceDecl struct {
	Path  string            `json:"path"`
	Kind  string            `json:"kind"`
	Match map[string]string `json:"match"`
}

// MountDecl is one host mount.
type MountDecl struct {
	Target  string   `json:"target"`
	FSType  string   `json:"fstype"`
	Source  string   `json:"source"`
	Options []string `json:"options"`
}

// NetworkDecl is one network profile, static or unit.
type NetworkDecl struct {
	Kind      string      `json:"kind"`
	Link      string      `json:"link"`
	Name      string      `json:"name"`
	MTU       int         `json:"mtu"`
	Addresses []string    `json:"addresses"`
	Routes    []RouteDecl `json:"routes"`
	Requires  []string    `json:"requires"`
	Unit      string      `json:"unit"`
}

// RouteDecl is one static route.
type RouteDecl struct {
	Dst string `json:"dst"`
	GW  string `json:"gw"`
}

var (
	// MatchAttrs are the sysfs attributes a device may be matched on.
	MatchAttrs   = map[string]bool{"serial": true, "wwid": true, "device/serial": true, "device/wwid": true, "size": true, "partition": true, "dm/uuid": true}
	hostFSTypes  = map[string]bool{"ext4": true, "xfs": true, "vfat": true, "tmpfs": true}
	hostMountOpt = map[string]bool{"ro": true, "rw": true, "noexec": true, "noatime": true, "relatime": true, "nosuid": true, "nodev": true, "suid": true, "dev": true}
	macRe        = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	ifNameRe     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,14}$`)
	devPathRe    = regexp.MustCompile(`^/dev/[a-zA-Z0-9._/-]+$`)
	optConflict  = [][2]string{{"ro", "rw"}, {"suid", "nosuid"}, {"dev", "nodev"}}
)

func errHostDecl() error { return fail.E("host_decl_invalid") }

// ParseHostDecl reads host.json. Any problem is host_decl_invalid.
func ParseHostDecl(doc []byte) (*HostDecl, error) {
	if len(doc) > MaxHostDecl {
		return nil, errHostDecl()
	}
	if err := strictHostJSON(doc); err != nil {
		return nil, err
	}
	var h HostDecl
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, errHostDecl()
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errHostDecl()
	}
	if len(h.Devices) > maxHostTable || len(h.Mounts) > maxHostTable || len(h.Network) > maxHostTable {
		return nil, errHostDecl()
	}
	for name, d := range h.Devices {
		if !BootName.MatchString(name) || path.Clean(d.Path) != d.Path || !devPathRe.MatchString(d.Path) ||
			(d.Kind != "block" && d.Kind != "char") || len(d.Match) > 8 {
			return nil, errHostDecl()
		}
		for a, v := range d.Match {
			if !MatchAttrs[a] || v == "" || len(v) > 256 || strings.ContainsRune(v, 0) {
				return nil, errHostDecl()
			}
		}
	}
	targets := map[string]bool{}
	for name, m := range h.Mounts {
		if !BootName.MatchString(name) || !hostFSTypes[m.FSType] || !strings.HasPrefix(m.Target, "/") ||
			path.Clean(m.Target) != m.Target || m.Target == "/" || strings.ContainsRune(m.Target, 0) || targets[m.Target] {
			return nil, errHostDecl()
		}
		targets[m.Target] = true
		if (m.Source == "tmpfs") != (m.FSType == "tmpfs") {
			return nil, errHostDecl()
		}
		if _, ok := h.Devices[m.Source]; m.Source != "tmpfs" && !ok {
			return nil, errHostDecl()
		}
		for _, pair := range optConflict {
			if slices.Contains(m.Options, pair[0]) && slices.Contains(m.Options, pair[1]) {
				return nil, errHostDecl()
			}
		}
		seen := map[string]bool{}
		for _, o := range m.Options {
			k, v, val := strings.Cut(o, "=")
			if seen[k] {
				return nil, errHostDecl()
			}
			seen[k] = true
			switch {
			case !val && hostMountOpt[o]:
			case val && m.FSType == "tmpfs" && (k == "size" || k == "mode") && mountValueOK(k, v):
			default:
				return nil, errHostDecl()
			}
		}
	}
	for name, n := range h.Network {
		if !BootName.MatchString(name) {
			return nil, errHostDecl()
		}
		switch n.Kind {
		case "unit":
			if !UnitName.MatchString(n.Unit) || n.Link != "" || n.Name != "" || n.MTU != 0 || len(n.Addresses)+len(n.Routes)+len(n.Requires) > 0 {
				return nil, errHostDecl()
			}
		case "static":
			if !macRe.MatchString(n.Link) || (n.Name != "" && !ifNameRe.MatchString(n.Name)) || n.Unit != "" ||
				len(n.Addresses) > 8 || len(n.Routes) > 16 || len(n.Requires) > 16 || n.MTU < 0 || n.MTU > 65535 {
				return nil, errHostDecl()
			}
			public := false
			for _, a := range n.Addresses {
				p, err := netip.ParsePrefix(a)
				if err != nil || p.Addr().Zone() != "" {
					return nil, errHostDecl()
				}
				ad := p.Addr().Unmap()
				if !ad.IsPrivate() && !ad.IsLoopback() && !ad.IsLinkLocalUnicast() {
					public = true
				}
			}
			for _, r := range n.Routes {
				if _, err := netip.ParsePrefix(r.Dst); err != nil {
					return nil, errHostDecl()
				}
				if gw, err := netip.ParseAddr(r.GW); err != nil || gw.Zone() != "" {
					return nil, errHostDecl()
				}
			}
			for _, u := range n.Requires {
				if !UnitName.MatchString(u) {
					return nil, errHostDecl()
				}
			}
			// Decision 5: a public address goes live only behind a unit.
			if public && len(n.Requires) == 0 {
				return nil, errHostDecl()
			}
		default:
			return nil, errHostDecl()
		}
	}
	return &h, nil
}

// ProfileUnits is every unit host.json names: a unit profile's unit and a
// static profile's requires. The catalog check at load refuses a unit
// profile's unit that is missing or a boot unit; a requires unit that is
// missing is checked at network apply (net_unguarded).
func (h *HostDecl) ProfileUnits() (units, requires []string) {
	if h == nil {
		return nil, nil
	}
	for _, n := range h.Network {
		if n.Kind == "unit" {
			units = append(units, n.Unit)
		}
		requires = append(requires, n.Requires...)
	}
	return units, requires
}

// hostSchema is host.json's shape for strictHostJSON: an object's exact
// keys, a table (name to entry), a list, or a scalar.
type hostSchema struct {
	fields map[string]*hostSchema
	table  *hostSchema
	list   *hostSchema
	scalar bool
}

var (
	hsScalar      = &hostSchema{scalar: true}
	hsStrings     = &hostSchema{list: hsScalar}
	hostSchemaTop = &hostSchema{fields: map[string]*hostSchema{
		"devices": {table: &hostSchema{fields: map[string]*hostSchema{
			"path": hsScalar, "kind": hsScalar, "match": {table: hsScalar},
		}}},
		"mounts": {table: &hostSchema{fields: map[string]*hostSchema{
			"target": hsScalar, "fstype": hsScalar, "source": hsScalar, "options": hsStrings,
		}}},
		"network": {table: &hostSchema{fields: map[string]*hostSchema{
			"kind": hsScalar, "link": hsScalar, "name": hsScalar, "mtu": hsScalar, "addresses": hsStrings,
			"routes":   {list: &hostSchema{fields: map[string]*hostSchema{"dst": hsScalar, "gw": hsScalar}}},
			"requires": hsStrings, "unit": hsScalar,
		}}},
	}}
)

// strictHostJSON walks doc token by token against hostSchemaTop: every key
// an exact, case-sensitive match, none twice in one object, no null at any
// level, and nothing after the document.
func strictHostJSON(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var walk func(s *hostSchema, depth int) error
	walk = func(s *hostSchema, depth int) error {
		if depth > 8 {
			return errHostDecl()
		}
		tok, err := dec.Token()
		if err != nil || tok == nil {
			return errHostDecl()
		}
		t, delim := tok.(json.Delim)
		if !delim {
			if !s.scalar {
				return errHostDecl()
			}
			return nil
		}
		switch {
		case t == '{' && (s.fields != nil || s.table != nil):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				k, ok := kt.(string)
				if err != nil || !ok || seen[k] {
					return errHostDecl()
				}
				seen[k] = true
				next := s.table
				if s.fields != nil {
					next = s.fields[k]
				}
				if next == nil {
					return errHostDecl()
				}
				if err := walk(next, depth+1); err != nil {
					return err
				}
			}
		case t == '[' && s.list != nil:
			for dec.More() {
				if err := walk(s.list, depth+1); err != nil {
					return err
				}
			}
		default:
			return errHostDecl()
		}
		if _, err := dec.Token(); err != nil {
			return errHostDecl()
		}
		return nil
	}
	if err := walk(hostSchemaTop, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errHostDecl()
	}
	return nil
}
