//go:build linux

package supervise

// The mounts sash services made, across all services, by mount point.
//
// Threats: a umount or remount by path would act on whatever is mounted
// there now, which may not be the mount sahinit made (it may be gone, or
// covered by another). Each mount's ID (statx STATX_MNT_ID) is kept and
// checked before sahinit touches it again (not_mounted on a mismatch). One
// mount point belongs to one service at a time (exists). The table is
// persisted, atomically, in sahinit's sash state directory with the boot
// ID, so the mounts of a sahinit that died are found and removed at the
// next start (sash_mount_leftover), and never after a reboot, when mount
// IDs mean something else.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// mountRec is one mount a service made.
type mountRec struct {
	Service string `json:"service"`
	Dir     string `json:"dir"`
	Kind    string `json:"kind"` // type, bind or rbind
	ID      uint64 `json:"id"`
}

type mountState struct {
	Boot   string     `json:"boot"`
	Mounts []mountRec `json:"mounts"`
}

type mountRegistry struct {
	mu   sync.Mutex
	recs []mountRec
	path string // "" keeps it in memory only
	boot string
}

const mountStateFile = "sash-mounts.json"

func bootID() string {
	raw, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return string(bytes.TrimSpace(raw))
}

// mounts is the supervisor's registry, made on first use.
func (sup *Supervisor) mounts() *mountRegistry {
	sup.mountsOnce.Do(func() {
		r := &mountRegistry{boot: bootID()}
		if sup.Sash != nil && sup.Sash.StateDir != "" {
			r.path = filepath.Join(sup.Sash.StateDir, mountStateFile)
		}
		sup.mountReg = r
	})
	return sup.mountReg
}

func (r *mountRegistry) get(dir string) (mountRec, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.recs {
		if m.Dir == dir {
			return m, true
		}
	}
	return mountRec{}, false
}

// under reports whether a tracked mount other than dir lies beneath it.
func (r *mountRegistry) under(dir string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.recs {
		if m.Dir != dir && len(m.Dir) > len(dir) && m.Dir[:len(dir)+1] == dir+"/" {
			return true
		}
	}
	return false
}

func (r *mountRegistry) add(rec mountRec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	if err := r.persistLocked(); err != nil {
		r.recs = r.recs[:len(r.recs)-1]
		return err
	}
	return nil
}

func (r *mountRegistry) remove(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, m := range r.recs {
		if m.Dir == dir {
			r.recs = append(r.recs[:i], r.recs[i+1:]...)
			break
		}
	}
	r.persistLocked()
}

// persistLocked writes the table: temporary file, fsync, rename, directory
// fsync.
func (r *mountRegistry) persistLocked() error {
	if r.path == "" {
		return nil
	}
	recs := r.recs
	if recs == nil {
		recs = []mountRec{}
	}
	raw, err := json.Marshal(mountState{Boot: r.boot, Mounts: recs})
	if err != nil {
		return fail.E("failed")
	}
	var nonce [8]byte
	rand.Read(nonce[:])
	dir := filepath.Dir(r.path)
	tmp := filepath.Join(dir, ".pending-"+hex.EncodeToString(nonce[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fail.E("failed")
	}
	defer os.Remove(tmp)
	if _, err := f.Write(raw); err != nil || f.Sync() != nil {
		f.Close()
		return fail.E("failed")
	}
	if err := f.Close(); err != nil {
		return fail.E("failed")
	}
	if err := os.Rename(tmp, r.path); err != nil {
		return fail.E("failed")
	}
	d, err := os.Open(dir)
	if err != nil {
		return fail.E("failed")
	}
	defer d.Close()
	if d.Sync() != nil {
		return fail.E("failed")
	}
	return nil
}

// mountID is the ID of the mount dir is the root of, or 0. dir is opened
// with no symlinks.
func mountID(dir string) (uint64, int, error) {
	how := unix.OpenHow{Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, dir, &how)
	if err != nil {
		return 0, -1, pathErr(err)
	}
	// The unique ID (Linux 6.8) is never reused; the old one is reused as
	// soon as a mount is gone, so a mount made in its place could match.
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID_UNIQUE, &stx); err == nil && stx.Mask&unix.STATX_MNT_ID_UNIQUE != 0 {
		return stx.Mnt_id, fd, nil
	}
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil || stx.Mask&unix.STATX_MNT_ID == 0 {
		unix.Close(fd)
		return 0, -1, fail.E("unsupported")
	}
	return stx.Mnt_id, fd, nil
}

// unmountRec unmounts rec after checking it is still the mount sahinit
// made. A plain umount, never a lazy one, unless it is an rbind whose
// nested mounts came with it and no tracked mount lies beneath it; a mount
// still in use is busy.
func (r *mountRegistry) unmountRec(rec mountRec) error {
	id, fd, err := mountID(rec.Dir)
	if err != nil {
		return err
	}
	// The fd would itself keep the mount busy: it is closed before the
	// umount, which then names the path (never following a link at its
	// end). Its parents are outside every file_write root (mount_overlap),
	// so the service cannot swap them in between.
	unix.Close(fd)
	if id != rec.ID {
		return fail.E("not_mounted")
	}
	flags := 0
	if rec.Kind == "rbind" {
		if r.under(rec.Dir) {
			return fail.E("busy")
		}
		flags = unix.MNT_DETACH
	}
	if err := unix.Unmount(rec.Dir, flags|unix.UMOUNT_NOFOLLOW); err != nil {
		if err == unix.EBUSY {
			return fail.E("busy")
		}
		return fail.E("failed")
	}
	r.remove(rec.Dir)
	return nil
}

// CleanSashMounts removes the mounts a previous sahinit recorded and did
// not unmount, on this boot only, each after its mount ID is checked, and
// names each as "sash_mount_leftover SERVICE DIR". It runs once, before
// any sash service starts.
func (sup *Supervisor) CleanSashMounts() {
	r := sup.mounts()
	if r.path == "" {
		return
	}
	raw, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var st mountState
	if json.Unmarshal(raw, &st) != nil {
		sup.logf("sash_mount_state_corrupt")
	}
	if st.Boot == r.boot {
		for i := len(st.Mounts) - 1; i >= 0; i-- {
			rec := st.Mounts[i]
			r.mu.Lock()
			r.recs = append(r.recs, rec)
			r.mu.Unlock()
			if err := r.unmountRec(rec); err != nil {
				r.remove(rec.Dir)
				continue
			}
			sup.logf("sash_mount_leftover %s %s", rec.Service, rec.Dir)
		}
	}
	r.mu.Lock()
	r.recs = nil
	r.persistLocked()
	r.mu.Unlock()
}
