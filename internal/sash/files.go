package sash

// The file verbs and mount (batch 2, docs/design/sash-services-2.md): the
// checks sahinit makes before its host performs them as root.
//
// Threats: see the contract. Here: every path is absolute, clean and at or
// under a file_write root (and the request's path is argv's); rm and ln
// never touch a root itself; a mode is at most 1777 (no setuid or setgid);
// an owner is only the grant's own identity; a mount point is exactly one
// of the grant's mounts, holds no file_write root and lies under none; its
// source and options pass sash's allowlists, with nosuid and nodev always
// present; remount and umount touch only a mount this service made. The
// host resolves every path with no symlinks.

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
)

var fileOps = map[string]bool{"mkdir": true, "chown": true, "chmod": true, "touch": true, "ln": true, "rm": true}

var fileMode = regexp.MustCompile(`^[01]?[0-7]{3}$`)

// FileOp is a checked file verb.
type FileOp struct {
	Op     string // mkdir, chown, chmod, touch, ln, rm
	Path   string
	Root   string // the file_write root Path lies under
	Target string // ln: the link's text
	Mode   int    // -1 for none
	// Owner asks for the grant's user and group (chown, mkdir owner).
	Owner       bool
	User, Group string
}

// MountPlan is a checked mount.
type MountPlan struct {
	Src, Dir, Type string
	Bind, Rec      bool
	Remount        bool
	// Flags are ro, rw, nosuid, nodev, noexec; Data the key=value options.
	Flags, Data []string
}

func cleanAbs(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

func (s *Server) file(req Request) (Response, error) {
	a := req.Argv
	if len(a) < 2 || !cleanAbs(a[1]) || req.Path != a[1] {
		return Response{}, errDenied
	}
	op := FileOp{Op: a[0], Path: a[1], Mode: -1, User: s.G.User, Group: s.G.Group}
	op.Root = RootOf(s.G.FileWrite, op.Path)
	if op.Root == "" {
		return Response{}, errDenied
	}
	mode := func(m string) error {
		if !fileMode.MatchString(m) {
			return errDenied
		}
		// The form allows at most 1777: never setuid or setgid.
		n, _ := strconv.ParseUint(m, 8, 32)
		op.Mode = int(n)
		return nil
	}
	owner := func(o string) error {
		if o != s.G.User+":"+s.G.Group {
			return errDenied
		}
		op.Owner = true
		return nil
	}
	var err error
	switch op.Op {
	case "mkdir":
		seen := map[string]bool{}
		rest := a[2:]
		if len(rest)%2 != 0 {
			return Response{}, errDenied
		}
		for i := 0; i < len(rest) && err == nil; i += 2 {
			if seen[rest[i]] {
				return Response{}, errDenied
			}
			seen[rest[i]] = true
			switch rest[i] {
			case "mode":
				err = mode(rest[i+1])
			case "owner":
				err = owner(rest[i+1])
			default:
				err = errDenied
			}
		}
	case "chown":
		if len(a) != 3 {
			return Response{}, errDenied
		}
		err = owner(a[2])
	case "chmod":
		if len(a) != 3 {
			return Response{}, errDenied
		}
		err = mode(a[2])
	case "touch", "rm":
		if len(a) != 2 {
			return Response{}, errDenied
		}
	case "ln":
		if len(a) != 3 || !cleanAbs(a[2]) || RootOf(s.G.FileWrite, a[2]) == "" {
			return Response{}, errDenied
		}
		op.Target = a[2]
	}
	if err != nil {
		return Response{}, err
	}
	if (op.Op == "rm" || op.Op == "ln") && op.Path == op.Root {
		return Response{}, errDenied
	}
	if err := s.Host.File(op); err != nil {
		return Response{}, hostErr(err)
	}
	return Response{Kind: "bytes"}, nil
}

// hostErr passes a host's refusal token through, and anything else as
// failed.
func hostErr(err error) error {
	switch tok := fail.Token(err); tok {
	case "denied", "symlink", "hardlink", "exists", "not_empty", "not_found", "not_mounted", "mount_opt_refused", "mount_overlap", "busy", "unsupported":
		return err
	}
	return fail.E("failed")
}

func within(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }

func (s *Server) mount(a []string) (Response, error) {
	switch {
	case len(a) == 2 && a[0] == "umount":
		dir := a[1]
		if !cleanAbs(dir) || !s.G.AllowsMount(dir) {
			return Response{}, errDenied
		}
		if !s.Table.Mounted(dir) {
			return Response{}, fail.E("not_mounted")
		}
		if err := s.Host.Umount(dir); err != nil {
			return Response{}, hostErr(err)
		}
		s.Table.Unmounted(dir)
		return Response{Kind: "bytes"}, nil
	case len(a) >= 3 && a[0] == "mount":
	default:
		return Response{}, errDenied
	}
	m := MountPlan{Src: a[1], Dir: a[2]}
	if !cleanAbs(m.Dir) || !s.G.AllowsMount(m.Dir) {
		return Response{}, errDenied
	}
	var opts []string
	seen := map[string]bool{}
	rest := a[3:]
	if len(rest)%2 != 0 {
		return Response{}, errDenied
	}
	for i := 0; i < len(rest); i += 2 {
		k, v := rest[i], rest[i+1]
		if seen[k] || (k != "type" && k != "opts") {
			return Response{}, errDenied
		}
		seen[k] = true
		if k == "type" {
			m.Type = v
		} else {
			opts = strings.Split(v, ",")
		}
	}
	bind, err := CheckMountOpts(m.Src, m.Type, opts)
	if err != nil {
		return Response{}, err
	}
	if !s.G.AllowsMountSource(m.Src) {
		return Response{}, errDenied
	}
	if bind != strings.HasPrefix(m.Src, "/") || bind && !cleanAbs(m.Src) {
		return Response{}, errDenied
	}
	for _, f := range MountForcedOpts {
		if !exact(opts, f) {
			return Response{}, fail.E("mount_opt_refused")
		}
	}
	for _, root := range s.G.FileWrite {
		if within(m.Dir, root) || within(root, m.Dir) {
			return Response{}, fail.E("mount_overlap")
		}
	}
	for _, o := range opts {
		switch {
		case o == "bind":
			m.Bind = true
		case o == "rbind":
			m.Bind, m.Rec = true, true
		case o == "remount":
			m.Remount = true
		case strings.Contains(o, "="):
			m.Data = append(m.Data, o)
		default:
			if !exact(m.Flags, o) {
				m.Flags = append(m.Flags, o)
			}
		}
	}
	mounted := s.Table.Mounted(m.Dir)
	if m.Remount && !mounted {
		return Response{}, fail.E("not_mounted")
	}
	// A remount changes only this mount's own flags (ro, rw, nosuid,
	// nodev, noexec), never its filesystem: a size, mode or owner would
	// change a superblock that other mounts, the host's included, share.
	if m.Remount && len(m.Data) > 0 {
		return Response{}, fail.E("mount_opt_refused")
	}
	if !m.Remount && mounted {
		return Response{}, fail.E("exists")
	}
	if err := s.Host.Mount(m); err != nil {
		return Response{}, hostErr(err)
	}
	if !m.Remount {
		s.Table.Mount(m.Dir)
	}
	return Response{Kind: "bytes"}, nil
}
