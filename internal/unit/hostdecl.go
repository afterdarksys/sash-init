// SPDX-License-Identifier: GPL-3.0-or-later

package unit

// Threats: host.json says what each boot verb name means, so a file someone
// else can write would let them point mount ensure at any target or network
// apply at any link. It follows the unit file rules: not a symlink itself,
// every directory on the way passing the trusted walk, a regular file owned
// by root (or the supervisor's uid) and not group- or other-writable, at
// most 64 KiB (host_decl_perm otherwise), then sash.ParseHostDecl
// (host_decl_invalid).

import (
	"errors"
	"os"
	"path"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
)

// DefaultHostDecl is where host.json is read when --host-decl is not given.
const DefaultHostDecl = "/etc/sahinit/host.json"

// LoadHostDecl reads the host declarations at p. A missing file is no
// declarations (nil) unless required, when it is host_decl_perm.
func LoadHostDecl(p string, required bool) (*sash.HostDecl, error) {
	perm := fail.E("host_decl_perm")
	if p == "" || !path.IsAbs(p) || path.Clean(p) != p {
		return nil, perm
	}
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) && !required {
		return nil, nil
	}
	dir, err := TrustedDir(path.Dir(p))
	if err != nil {
		return nil, perm
	}
	raw, err := readUnit(path.Join(dir, path.Base(p)))
	if err != nil {
		return nil, perm
	}
	if len(raw) > sash.MaxHostDecl {
		return nil, perm
	}
	return sash.ParseHostDecl(raw)
}
