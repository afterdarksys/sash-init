// SPDX-License-Identifier: GPL-3.0-or-later

package sash

// Threats: modules.dep comes from the root-owned module tree, but a line in
// it is still only text: a forged line could name a file outside the tree
// (an absolute path or ".."), or a file whose name matches the module only
// after a wrong suffix strip (x.ko.gz.xz, x.xz). ResolveModule takes the one
// line whose file's base name, with ".ko" and at most one compression
// suffix removed and "-" read as "_", equals the module name; every path in
// the file must be relative and clean (module_tree), and no matching line or
// two of them is module_unknown, as sash's double. Does NOT open anything: the host opens each file
// beneath the tree with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS.

import (
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
// dependencies from the end of the line first, as modprobe does. As sash's
// double: any non-empty line without ":" or with a path that is absolute,
// unclean or holds ".." makes the whole file module_tree; no matching line,
// or more than one, is module_unknown.
func ResolveModule(dep []byte, name string) (ModuleFile, []ModuleFile, error) {
	tree := fail.E("module_tree")
	if len(dep) > MaxModulesDep {
		return ModuleFile{}, nil, tree
	}
	var own ModuleFile
	var deps []ModuleFile
	n := 0
	for _, line := range strings.Split(string(dep), "\n") {
		if line == "" {
			continue
		}
		head, rest, ok := strings.Cut(line, ":")
		if !ok {
			return ModuleFile{}, nil, tree
		}
		files := append([]string{head}, strings.Fields(rest)...)
		for _, f := range files {
			if f == "" || path.IsAbs(f) || path.Clean(f) != f || strings.Contains(f, "..") || strings.ContainsRune(f, 0) {
				return ModuleFile{}, nil, tree
			}
		}
		if !ModuleName.MatchString(name) || ModuleBase(head) != name {
			continue
		}
		n++
		own, deps = ModuleFile{Name: name, File: head}, nil
		for _, f := range files[1:] {
			m := ModuleFile{Name: ModuleBase(f), File: f}
			if !ModuleName.MatchString(m.Name) {
				return ModuleFile{}, nil, tree
			}
			deps = append(deps, m)
		}
	}
	if n != 1 {
		return ModuleFile{}, nil, fail.E("module_unknown")
	}
	return own, deps, nil
}
