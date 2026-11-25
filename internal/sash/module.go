// SPDX-License-Identifier: GPL-3.0-or-later

package sash

// Threats: modules.dep comes from the root-owned module tree, but a line in
// it is still only text: a forged line could name a file outside the tree
// (an absolute path or ".."), or a file whose name matches the module only
// after a wrong suffix strip (x.ko.gz.xz, x.xz). ResolveModule takes the one
// line whose file's base name, with ".ko" and at most one compression
// suffix removed and "-" read as "_", equals the module name; every path in
// that line must be relative and clean (module_tree), and two such lines
// are module_tree as well. Does NOT open anything: the host opens each file
// beneath the tree with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS.

import (
	"bytes"
	"path"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// MaxModulesDep is the largest modules.dep sahinit reads.
const MaxModulesDep = 8 << 20

// ModuleFile is one module of a load: its name and its file in the tree.
type ModuleFile struct {
	Name string
	File string
}

// ModuleBase is the module name a modules.dep file stands for, or "" when
// the file is not a module: the base name less ".ko" and at most one of
// ".xz", ".zst" and ".gz", with "-" read as "_".
func ModuleBase(file string) string {
	b := path.Base(file)
	for _, z := range []string{".xz", ".zst", ".gz"} {
		if strings.HasSuffix(b, ".ko"+z) {
			b = strings.TrimSuffix(b, z)
			break
		}
	}
	if !strings.HasSuffix(b, ".ko") {
		return ""
	}
	return strings.ReplaceAll(strings.TrimSuffix(b, ".ko"), "-", "_")
}

// ResolveModule finds name in dep (modules.dep): the module's own file and
// its dependencies, in the order the line gives them. The host loads the
// dependencies from the end of the line first, as modprobe does.
func ResolveModule(dep []byte, name string) (ModuleFile, []ModuleFile, error) {
	tree := fail.E("module_tree")
	if len(dep) > MaxModulesDep {
		return ModuleFile{}, nil, tree
	}
	if !ModuleName.MatchString(name) {
		return ModuleFile{}, nil, fail.E("module_unknown")
	}
	var own ModuleFile
	var deps []ModuleFile
	found := false
	for _, line := range bytes.Split(dep, []byte("\n")) {
		head, rest, ok := strings.Cut(string(line), ":")
		if !ok || ModuleBase(head) != name {
			continue
		}
		if found {
			return ModuleFile{}, nil, tree
		}
		found = true
		files := append([]string{head}, strings.Fields(rest)...)
		for i, f := range files {
			if f == "" || path.IsAbs(f) || path.Clean(f) != f || f == "." || strings.HasPrefix(f, "../") || f == ".." || strings.ContainsRune(f, 0) {
				return ModuleFile{}, nil, tree
			}
			m := ModuleFile{Name: ModuleBase(f), File: f}
			if m.Name == "" || !ModuleName.MatchString(m.Name) {
				return ModuleFile{}, nil, tree
			}
			if i == 0 {
				own = m
			} else {
				deps = append(deps, m)
			}
		}
	}
	if !found {
		return ModuleFile{}, nil, fail.E("module_unknown")
	}
	return own, deps, nil
}
