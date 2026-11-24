// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

// The file verbs and mounts, performed as root after internal/sash checked
// them (docs/design/sash-services-2.md).
//
// Threats: sahinit is root here and the service owns its file_write tree,
// so it can swap any component for a symlink at any moment. Each path is
// opened from its root with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS, and the
// operation then names only one final component relative to an opened
// directory fd (mkdirat, symlinkat, unlinkat, fchownat with
// AT_SYMLINK_NOFOLLOW), or acts on an fd opened O_NOFOLLOW (chmod and the
// times, through /proc/self/fd). A target must be a regular file or a
// directory owned by root or the service, and a file must have one link,
// so a hard link to a file outside the root is never chowned, chmodded or
// touched. Ownership goes only to the service's own uid and gid. A mount's
// source and point are opened with RESOLVE_NO_SYMLINKS and mounted through
// their /proc/self/fd paths, so the inode checked is the one mounted; every
// mount is nosuid and nodev.

import (
	"errors"
	"path"
	goruntime "runtime"
	"strconv"
	"strings"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/sash"
	"golang.org/x/sys/unix"
)

func fdPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// pathErr maps an open error to a token.
func pathErr(err error) error {
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV):
		return fail.E("symlink")
	case errors.Is(err, unix.ENOENT):
		return fail.E("not_found")
	}
	return fail.E("denied")
}

// ids are the service's uid and gid for the grant's names.
func (h *sashHost) ids(op sash.FileOp) (int, int, error) {
	svc := h.s.svc
	lookUser, lookGroup := LookupIDs()
	if h.sup.lookupUser != nil {
		lookUser, lookGroup = h.sup.lookupUser, h.sup.lookupGroup
	}
	uid, uerr := lookUser(op.User)
	gid, gerr := lookGroup(op.Group)
	if uerr != nil || gerr != nil || svc.Execution.UID == nil || uid != *svc.Execution.UID || gid != *svc.Execution.GID {
		return 0, 0, fail.E("denied")
	}
	return int(uid), int(gid), nil
}

// checkTarget is the rule for a file sahinit changes: a regular file or a
// directory, owned by the service, and a file with one link. A root-owned
// file under file_write is never given to the service, chmodded, touched
// or removed by sahinit's root.
func checkTarget(st *unix.Stat_t, uid int) error {
	kind := st.Mode & unix.S_IFMT
	switch {
	case kind == unix.S_IFLNK:
		return fail.E("symlink")
	case kind != unix.S_IFREG && kind != unix.S_IFDIR:
		return fail.E("denied")
	case kind == unix.S_IFREG && st.Nlink != 1:
		return fail.E("hardlink")
	case int(st.Uid) != uid:
		return fail.E("denied")
	}
	return nil
}

func (h *sashHost) File(op sash.FileOp) error {
	uid, gid, err := h.ids(op)
	if err != nil {
		return err
	}
	parent, name := path.Split(op.Path)
	parent = path.Clean(parent)
	if op.Path == op.Root {
		parent, name = op.Root, ""
	}
	if !strings.HasPrefix(parent+"/", op.Root+"/") && parent != op.Root {
		return fail.E("denied")
	}
	dfd, err := sandbox.OpenBeneath(op.Root, parent, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return pathErr(err)
	}
	defer unix.Close(dfd)
	// target opens name (or the directory itself) without following it.
	target := func() (int, *unix.Stat_t, error) {
		fd := dfd
		if name != "" {
			how := unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS}
			var err error
			if fd, err = unix.Openat2(dfd, name, &how); err != nil {
				return -1, nil, pathErr(err)
			}
		} else if fd, err = unix.Dup(dfd); err != nil {
			return -1, nil, fail.E("failed")
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return -1, nil, fail.E("failed")
		}
		if err := checkTarget(&st, uid); err != nil {
			unix.Close(fd)
			return -1, nil, err
		}
		return fd, &st, nil
	}
	chown := func(fd int) error {
		if err := unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fail.E("failed")
		}
		return nil
	}
	chmod := func(fd int, mode int) error {
		if mode < 0 {
			return nil
		}
		if err := unix.Chmod(fdPath(fd), uint32(mode)); err != nil {
			return fail.E("failed")
		}
		return nil
	}
	switch op.Op {
	case "mkdir":
		created := false
		if name != "" {
			err := asService(uid, gid, func() error { return unix.Mkdirat(dfd, name, 0o755) })
			if err != nil && !errors.Is(err, unix.EEXIST) {
				return pathErr(err)
			}
			created = err == nil
		}
		if created {
			// Made as the service, so it is the service's from the
			// start; the mode is set through an fd checked to be that
			// new directory.
			fd, err := openDirNoFollow(dfd, name)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != uid || st.Nlink != 2 {
				return fail.E("denied")
			}
			if op.Mode >= 0 {
				if err := unix.Fchmod(fd, uint32(op.Mode)); err != nil {
					return fail.E("failed")
				}
			}
			return nil
		}
		if !op.Owner && op.Mode < 0 {
			// An existing directory, nothing to change: idempotent.
			var st unix.Stat_t
			if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
				return pathErr(err)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fail.E("exists")
			}
			return nil
		}
		fd, st, err := target()
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fail.E("exists")
		}
		if op.Owner {
			if err := chown(fd); err != nil {
				return err
			}
		}
		return chmod(fd, op.Mode)
	case "chown", "chmod":
		fd, _, err := target()
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if op.Op == "chown" {
			return chown(fd)
		}
		return chmod(fd, op.Mode)
	case "touch":
		how := unix.OpenHow{Flags: uint64(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC), Mode: 0o644, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS}
		var fd int
		err := asService(uid, gid, func() error {
			var oerr error
			fd, oerr = unix.Openat2(dfd, name, &how)
			return oerr
		})
		if err == nil {
			// Created as the service: nothing to give away.
			unix.Close(fd)
			return nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return pathErr(err)
		}
		tfd, st, err := target()
		if err != nil {
			return err
		}
		defer unix.Close(tfd)
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fail.E("exists")
		}
		now := []unix.Timespec{{Nsec: unix.UTIME_NOW}, {Nsec: unix.UTIME_NOW}}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, fdPath(tfd), now, 0); err != nil {
			return fail.E("failed")
		}
		return nil
	case "ln":
		// Made as the service: the link is its own, and nothing is
		// chowned by name afterwards.
		if err := asService(uid, gid, func() error { return unix.Symlinkat(op.Target, dfd, name) }); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return fail.E("exists")
			}
			return pathErr(err)
		}
		return nil
	case "rm":
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return pathErr(err)
		}
		if err := checkTarget(&st, uid); err != nil {
			return err
		}
		flags := 0
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			flags = unix.AT_REMOVEDIR
		}
		if err := unix.Unlinkat(dfd, name, flags); err != nil {
			if errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
				return fail.E("not_empty")
			}
			return pathErr(err)
		}
		return nil
	}
	return fail.E("denied")
}

var mountFlagBits = map[string]uintptr{"ro": unix.MS_RDONLY, "nosuid": unix.MS_NOSUID, "nodev": unix.MS_NODEV, "noexec": unix.MS_NOEXEC, "rw": 0}

var mountAttrBits = map[string]uint64{"ro": unix.MOUNT_ATTR_RDONLY, "nosuid": unix.MOUNT_ATTR_NOSUID, "nodev": unix.MOUNT_ATTR_NODEV, "noexec": unix.MOUNT_ATTR_NOEXEC, "rw": 0}

// Mount performs a checked mount. A type mount is made with its flags. A
// bind is cloned with open_tree (recursively for rbind), given ro, nosuid,
// nodev and noexec with mount_setattr (on every nested mount too), and
// only then attached with move_mount: no mount of the tree is ever
// attached without nosuid and nodev. A kernel without these calls may
// still bind (bind, then a remount on the new mount), but never rbind
// (unsupported). A remount changes only this mount's own flags
// (MS_REMOUNT|MS_BIND), after its mount ID is checked. Each new mount's ID
// is recorded; a mount point another service holds is exists.
func (h *sashHost) Mount(m sash.MountPlan) error {
	var flags uintptr
	var attr uint64
	for _, f := range m.Flags {
		bit, ok := mountFlagBits[f]
		if !ok {
			return fail.E("mount_opt_refused")
		}
		flags |= bit
		attr |= mountAttrBits[f]
	}
	if flags&(unix.MS_NOSUID|unix.MS_NODEV) != unix.MS_NOSUID|unix.MS_NODEV {
		return fail.E("mount_opt_refused")
	}
	reg := h.sup.mounts()
	name := h.s.svc.Name
	if m.Remount {
		rec, ok := reg.get(m.Dir)
		if !ok || rec.Service != name || rec.ID == 0 || len(m.Data) > 0 {
			return fail.E("not_mounted")
		}
		id, fd, err := mountID(m.Dir)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if id != rec.ID {
			h.forget(rec)
			return fail.E("not_mounted")
		}
		if err := unix.Mount("", fdPath(fd), "", flags|unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
			return fail.E("failed")
		}
		return nil
	}
	how := unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS}
	dfd, err := unix.Openat2(unix.AT_FDCWD, m.Dir, &how)
	if err != nil {
		return pathErr(err)
	}
	defer unix.Close(dfd)
	// Without mount IDs a mount could never be checked again, so none is
	// made.
	if _, err := statMountID(dfd); err != nil {
		return fail.E("unsupported")
	}
	// The point is reserved before mounting, under one lock with the
	// check, so two services cannot both mount it.
	if !reg.reserve(name, m.Dir) {
		return fail.E("exists")
	}
	kind := "type"
	if m.Bind {
		kind = "bind"
		if m.Rec {
			kind = "rbind"
		}
		if err := bindMount(m, dfd, attr, flags); err != nil {
			reg.remove(m.Dir)
			return err
		}
	} else if err := unix.Mount(m.Type, fdPath(dfd), m.Type, flags, strings.Join(m.Data, ",")); err != nil {
		reg.remove(m.Dir)
		return fail.E("failed")
	}
	id, nfd, err := mountID(m.Dir)
	if err == nil {
		unix.Close(nfd)
		err = reg.record(mountRec{Service: name, Dir: m.Dir, Kind: kind, ID: id})
	}
	if err != nil {
		// Not recorded, so not kept: detached by its path (nothing else
		// is there, the point being reserved), without asking for its ID
		// again.
		unix.Unmount(m.Dir, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW)
		reg.remove(m.Dir)
		return fail.E("failed")
	}
	return nil
}

// bindMount attaches a bind of m.Src at dfd with its flags already set.
func bindMount(m sash.MountPlan, dfd int, attr uint64, flags uintptr) error {
	sh := unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS}
	sfd, err := unix.Openat2(unix.AT_FDCWD, m.Src, &sh)
	if err != nil {
		return pathErr(err)
	}
	defer unix.Close(sfd)
	treeFlags := uint(unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC | unix.AT_EMPTY_PATH)
	setFlags := uint(unix.AT_EMPTY_PATH)
	if m.Rec {
		treeFlags |= unix.AT_RECURSIVE
		setFlags |= unix.AT_RECURSIVE
	}
	tree, err := unix.OpenTree(sfd, "", treeFlags)
	if errors.Is(err, unix.ENOSYS) {
		if m.Rec {
			return fail.E("unsupported")
		}
		return legacyBind(sfd, dfd, m, flags)
	}
	if err != nil {
		return fail.E("failed")
	}
	defer unix.Close(tree)
	if err := unix.MountSetattr(tree, "", setFlags, &unix.MountAttr{Attr_set: attr}); err != nil {
		if errors.Is(err, unix.ENOSYS) && !m.Rec {
			return legacyBind(sfd, dfd, m, flags)
		}
		if errors.Is(err, unix.ENOSYS) {
			return fail.E("unsupported")
		}
		return fail.E("failed")
	}
	if err := unix.MoveMount(tree, "", dfd, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return fail.E("failed")
	}
	return nil
}

// legacyBind is a single-mount bind on a kernel without the new mount
// calls: bind, then set the flags with a remount on the new mount (dfd
// names the directory beneath it, so the point is opened again); if that
// fails the bind is unmounted.
func legacyBind(sfd, dfd int, m sash.MountPlan, flags uintptr) error {
	if err := unix.Mount(fdPath(sfd), fdPath(dfd), "", unix.MS_BIND, ""); err != nil {
		return fail.E("failed")
	}
	how := unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS}
	nfd, err := unix.Openat2(unix.AT_FDCWD, m.Dir, &how)
	if err != nil {
		return fail.E("failed")
	}
	defer unix.Close(nfd)
	if err := unix.Mount("", fdPath(nfd), "", flags|unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
		unix.Unmount(fdPath(nfd), unix.MNT_DETACH)
		return fail.E("failed")
	}
	return nil
}

// Umount unmounts a mount this service made, after checking its ID.
func (h *sashHost) Umount(dir string) error {
	reg := h.sup.mounts()
	rec, ok := reg.get(dir)
	if !ok || rec.Service != h.s.svc.Name || rec.ID == 0 {
		return fail.E("not_mounted")
	}
	err := reg.unmountRec(rec)
	if fail.Token(err) == "not_mounted" {
		h.forget(rec)
	}
	return err
}

// forget drops a record whose mount is no longer the one sahinit made, so
// the point is free again, and says so.
func (h *sashHost) forget(rec mountRec) {
	h.sup.mounts().remove(rec.Dir)
	h.sup.logf("sash_mount_forgotten %s %s", rec.Service, rec.Dir)
}

// unmountAll unmounts every mount the service made, newest first, when it
// ends; a failure is logged.
func (h *sashHost) unmountAll(t *sash.Table) {
	for _, dir := range t.Mounts() {
		if err := h.Umount(dir); err != nil {
			h.sup.logf("sash_umount %s %s", h.s.svc.Name, fail.Token(err))
			if fail.Token(err) != "not_mounted" {
				continue
			}
		}
		t.Unmounted(dir)
	}
}

// openDirNoFollow opens the directory name beneath dfd for fchmod,
// following nothing.
func openDirNoFollow(dfd int, name string) (int, error) {
	how := unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS}
	fd, err := unix.Openat2(dfd, name, &how)
	if err != nil {
		return -1, pathErr(err)
	}
	return fd, nil
}

// asService runs f on a locked OS thread whose filesystem uid and gid are
// the service's, with no supplementary groups, so whatever f creates is
// the service's own from the start and f gets no more access than the
// service has. The thread's ids and groups are restored and checked before
// it is unlocked; a thread that cannot be restored is ended, never reused.
//
// Threats: creating as root and then chowning by name lets the service,
// which owns the directory, rename one of root's files into that name in
// between and be given it. Created as the service, nothing is given away.
func asService(uid, gid int, f func() error) error {
	errc := make(chan error, 1)
	go func() {
		goruntime.LockOSThread()
		groups, gerr := unix.Getgroups()
		restored := func() bool {
			if gerr != nil || unix.Setgroups(groups) != nil {
				return false
			}
			unix.Setfsuid(0)
			unix.Setfsgid(0)
			u, _ := unix.SetfsuidRetUid(-1)
			g, _ := unix.SetfsgidRetGid(-1)
			return u == 0 && g == 0
		}
		var err error
		if gerr != nil || unix.Setgroups([]int{}) != nil {
			err = fail.E("failed")
		} else {
			unix.Setfsgid(gid)
			unix.Setfsuid(uid)
			u, _ := unix.SetfsuidRetUid(-1)
			g, _ := unix.SetfsgidRetGid(-1)
			if u != uid || g != gid {
				err = fail.E("failed")
			} else {
				err = f()
			}
		}
		if !restored() {
			errc <- fail.E("failed")
			goruntime.Goexit() // still locked: the thread ends with it
		}
		goruntime.UnlockOSThread()
		errc <- err
	}()
	return <-errc
}
