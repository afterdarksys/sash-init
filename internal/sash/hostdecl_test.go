// SPDX-License-Identifier: GPL-3.0-or-later

package sash

import (
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// HostFixture is the host.json of sash's double (prototest.HostFixture).
const HostFixture = `{
  "devices": {
    "data": {"path": "/dev/vdb", "kind": "block", "match": {"serial": "DATA0001", "size": "2097152"}},
    "logs": {"path": "/dev/disk/by-id/logs", "kind": "block", "match": {"wwid": "naa.5000c500"}}
  },
  "mounts": {
    "data": {"target": "/data", "fstype": "ext4", "source": "data", "options": ["noatime"]},
    "scratch": {"target": "/scratch", "fstype": "tmpfs", "source": "tmpfs", "options": ["size=64m", "mode=0755"]}
  },
  "network": {
    "lan": {"kind": "static", "link": "52:54:00:12:34:56", "mtu": 1500,
      "addresses": ["10.0.2.15/24"], "routes": [{"dst": "0.0.0.0/0", "gw": "10.0.2.2"}]},
    "wan": {"kind": "static", "link": "52:54:00:aa:bb:cc", "addresses": ["203.0.113.7/24"], "requires": ["firewall"]},
    "dhcp": {"kind": "unit", "unit": "dhcp"}
  }
}`

func TestHostDeclFixture(t *testing.T) {
	h, err := ParseHostDecl([]byte(HostFixture))
	if err != nil {
		t.Fatal(err)
	}
	if h.Devices["data"].Match["serial"] != "DATA0001" || h.Mounts["scratch"].FSType != "tmpfs" || h.Network["wan"].Requires[0] != "firewall" {
		t.Fatalf("%+v", h)
	}
	units, req := h.ProfileUnits()
	if len(units) != 1 || units[0] != "dhcp" || len(req) != 1 || req[0] != "firewall" {
		t.Fatalf("%v %v", units, req)
	}
	if _, err := ParseHostDecl([]byte(`{}`)); err != nil {
		t.Fatalf("empty: %v", err)
	}
}

func TestHostDeclRefusals(t *testing.T) {
	r := strings.NewReplacer
	for name, doc := range map[string]string{
		"unknown key":          r(`"kind": "block", "match"`, `"kind": "block", "extra": 1, "match"`).Replace(HostFixture),
		"unknown top key":      `{"devices": {}, "modules": {}}`,
		"key in another case":  r(`"target": "/data"`, `"Target": "/data"`).Replace(HostFixture),
		"duplicate key":        `{"devices": {}, "devices": {}}`,
		"duplicate name":       `{"devices": {"a": {"path": "/dev/a", "kind": "block", "match": {}}, "a": {"path": "/dev/b", "kind": "block", "match": {}}}}`,
		"null top":             `null`,
		"null table":           `{"devices": null}`,
		"null match":           r(`"match": {"wwid": "naa.5000c500"}`, `"match": null`).Replace(HostFixture),
		"null option":          r(`["noatime"]`, `[null]`).Replace(HostFixture),
		"trailing":             HostFixture + ` {}`,
		"oversized":            `{"devices": {}}` + strings.Repeat(" ", MaxHostDecl),
		"duplicate target":     r(`"target": "/scratch"`, `"target": "/data"`).Replace(HostFixture),
		"root target":          r(`"target": "/data"`, `"target": "/"`).Replace(HostFixture),
		"unclean target":       r(`"target": "/data"`, `"target": "/data/../etc"`).Replace(HostFixture),
		"relative target":      r(`"target": "/data"`, `"target": "data"`).Replace(HostFixture),
		"device outside /dev":  r(`"/dev/vdb"`, `"/etc/vdb"`).Replace(HostFixture),
		"device unclean":       r(`"/dev/vdb"`, `"/dev/../etc/shadow"`).Replace(HostFixture),
		"device kind":          r(`"kind": "block", "match": {"serial"`, `"kind": "fifo", "match": {"serial"`).Replace(HostFixture),
		"match attribute":      r(`"serial": "DATA0001"`, `"vendor": "DATA0001"`).Replace(HostFixture),
		"match empty":          r(`"serial": "DATA0001"`, `"serial": ""`).Replace(HostFixture),
		"device name":          r(`"data": {"path"`, `"Data": {"path"`).Replace(HostFixture),
		"undeclared source":    r(`"source": "data"`, `"source": "other"`).Replace(HostFixture),
		"tmpfs from a device":  r(`"source": "tmpfs"`, `"source": "data"`).Replace(HostFixture),
		"ext4 from tmpfs":      r(`"source": "data"`, `"source": "tmpfs"`).Replace(HostFixture),
		"fstype":               r(`"fstype": "ext4"`, `"fstype": "btrfs"`).Replace(HostFixture),
		"ro and rw":            r(`["noatime"]`, `["ro", "rw"]`).Replace(HostFixture),
		"suid and nosuid":      r(`["noatime"]`, `["suid", "nosuid"]`).Replace(HostFixture),
		"dev and nodev":        r(`["noatime"]`, `["dev", "nodev"]`).Replace(HostFixture),
		"option twice":         r(`["noatime"]`, `["noatime", "noatime"]`).Replace(HostFixture),
		"unknown option":       r(`["noatime"]`, `["errors=remount-ro"]`).Replace(HostFixture),
		"size on ext4":         r(`["noatime"]`, `["size=1m"]`).Replace(HostFixture),
		"tmpfs size":           r(`"size=64m"`, `"size=64x"`).Replace(HostFixture),
		"tmpfs mode":           r(`"mode=0755"`, `"mode=9999"`).Replace(HostFixture),
		"public no requires":   r(`, "requires": ["firewall"]`, ``).Replace(HostFixture),
		"mac upper case":       r(`52:54:00:12:34:56`, `52:54:00:12:34:5G`).Replace(HostFixture),
		"bad address":          r(`10.0.2.15/24`, `10.0.2.15`).Replace(HostFixture),
		"bad gateway":          r(`"gw": "10.0.2.2"`, `"gw": "10.0.2.2/32"`).Replace(HostFixture),
		"mtu":                  r(`"mtu": 1500`, `"mtu": 70000`).Replace(HostFixture),
		"mtu string":           r(`"mtu": 1500`, `"mtu": "1500"`).Replace(HostFixture),
		"interface name":       r(`"mtu": 1500`, `"name": "eth0;rm", "mtu": 1500`).Replace(HostFixture),
		"profile kind":         r(`"kind": "unit"`, `"kind": "bridge"`).Replace(HostFixture),
		"unit profile address": r(`"kind": "unit", "unit": "dhcp"`, `"kind": "unit", "unit": "dhcp", "addresses": ["10.0.0.1/8"]`).Replace(HostFixture),
		"unit name":            r(`"unit": "dhcp"`, `"unit": "dh_cp"`).Replace(HostFixture),
		"requires name":        r(`["firewall"]`, `["-firewall"]`).Replace(HostFixture),
		"not an object":        `[]`,
	} {
		if _, err := ParseHostDecl([]byte(doc)); fail.Token(err) != "host_decl_invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
