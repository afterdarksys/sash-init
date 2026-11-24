// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package supervise

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/sash"
	"golang.org/x/sys/unix"
)

// racer runs f in a loop on a thread whose filesystem ids are the
// service's: the service racing sahinit inside its own file_write tree.
func racer(stop *atomic.Bool, f func()) chan struct{} {
	done := make(chan struct{})
	go func() {
		goruntime.LockOSThread() // never unlocked: the thread ends with the goroutine
		unix.Setfsgid(65534)
		unix.Setfsuid(65534)
		for !stop.Load() {
			f()
		}
		close(done)
	}()
	return done
}

func raceServer(t *testing.T, name string) (*sash.Server, string) {
	t.Helper()
	e := newSashEnv(t)
	g, work, _, _, _ := filesGrant(e, name)
	e.add(name, refusalScript(name, "spawn main /usr/bin/sleep 300"), g, e.fleet)
	var log syncBuf
	sup, _ := e.load(&log)
	s := sup.rt[name]
	return &sash.Server{G: g, Table: s.sashTable(), Host: &sashHost{sup: sup, s: s}}, work
}

// serviceOwnsSecret reports whether root's secret, under any name in
// work, became the service's. It is the only regular file there: the
// service only renames, and sahinit makes links and directories.
func serviceOwnsSecret(work string) bool {
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		var st syscall.Stat_t
		if syscall.Lstat(filepath.Join(work, e.Name()), &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Uid == 65534 {
			return true
		}
	}
	return false
}

// race runs attempt until the secret is the service's or the budget ends,
// with the racer renaming root's secret into the name sahinit creates.
func race(t *testing.T, work, name string, attempt func(), cleanup func()) {
	t.Helper()
	secret, target := filepath.Join(work, "secret"), filepath.Join(work, name)
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	n := 0
	done := racer(&stop, func() {
		n++
		unix.Rename(target, filepath.Join(work, "junk"+strconv.Itoa(n%16)))
		unix.Rename(secret, target)
		unix.Rename(target, secret)
	})
	deadline := time.Now().Add(25 * time.Second)
	for i := 0; i < 100000 && time.Now().Before(deadline); i++ {
		attempt()
		if serviceOwnsSecret(work) {
			stop.Store(true)
			<-done
			t.Fatalf("root's secret was given to the service after %d attempts", i+1)
		}
		cleanup()
		junk, _ := filepath.Glob(filepath.Join(work, "junk*"))
		for _, j := range junk {
			var st syscall.Stat_t
			if syscall.Lstat(j, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG {
				os.Rename(j, secret) // root's secret: put it back, never delete it
				continue
			}
			if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
				os.Remove(j)
			} else {
				syscall.Rmdir(j)
			}
		}
	}
	stop.Store(true)
	<-done
}

// ln and mkdir create as the service, so a rename race inside the
// service's tree never gives it root's file (the build before chowned the
// new name, and lost this race in a few hundred attempts).
func TestSashLnRace(t *testing.T) {
	srv, work := raceServer(t, "rln")
	l := filepath.Join(work, "l")
	race(t, work, "l", func() {
		srv.Handle(sash.Request{Key: "file.write", Argv: []string{"ln", l, work + "/x"}, Path: l})
	}, func() {
		var st syscall.Stat_t
		if syscall.Lstat(l, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			os.Remove(l)
		}
	})
}

func TestSashMkdirRace(t *testing.T) {
	srv, work := raceServer(t, "rmk")
	d := filepath.Join(work, "d")
	race(t, work, "d", func() {
		srv.Handle(sash.Request{Key: "file.write", Argv: []string{"mkdir", d, "mode", "0700"}, Path: d})
	}, func() {
		var st syscall.Stat_t
		if syscall.Lstat(d, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			os.Remove(d)
		}
	})
}

// What sahinit creates is the service's, and sahinit's own thread keeps
// root's filesystem ids afterwards.
func TestSashCreatesAsService(t *testing.T) {
	srv, work := raceServer(t, "rcs")
	for _, a := range [][]string{{"mkdir", work + "/m", "mode", "0750"}, {"touch", work + "/t"}, {"ln", work + "/k", work + "/t"}} {
		if r := srv.Handle(sash.Request{Key: "file.write", Argv: a, Path: a[1]}); r.Error != "" {
			t.Fatalf("%v: %+v", a, r)
		}
		var st syscall.Stat_t
		if err := syscall.Lstat(a[1], &st); err != nil || st.Uid != 65534 || st.Gid != 65534 {
			t.Fatalf("%s: %d:%d %v", a[1], st.Uid, st.Gid, err)
		}
	}
	// Root may still write where only root may: no thread was left with
	// the service's ids.
	for i := 0; i < 50; i++ {
		p := filepath.Join(work, "..", "rootonly-"+strconv.Itoa(i))
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatalf("root write after asService: %v", err)
		}
		os.Remove(p)
	}
}

// mkdir's mode goes only to the directory it made: a racer swapping one of
// root's directories into the name never gets root's directory chmodded.
func TestSashMkdirModeRace(t *testing.T) {
	srv, work := raceServer(t, "rmm")
	d, rd := filepath.Join(work, "d"), filepath.Join(work, "rd")
	if err := os.Mkdir(rd, 0o700); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	n := 0
	done := racer(&stop, func() {
		n++
		unix.Rename(d, filepath.Join(work, "junk"+strconv.Itoa(n%16)))
		unix.Rename(rd, d)
		unix.Rename(d, rd)
	})
	rootChanged := func() bool {
		entries, _ := os.ReadDir(work)
		for _, e := range entries {
			var st syscall.Stat_t
			if syscall.Lstat(filepath.Join(work, e.Name()), &st) == nil && st.Uid == 0 && st.Mode&0o777 == 0o777 {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(25 * time.Second)
	for i := 0; i < 100000 && time.Now().Before(deadline); i++ {
		srv.Handle(sash.Request{Key: "file.write", Argv: []string{"mkdir", d, "mode", "0777"}, Path: d})
		if rootChanged() {
			stop.Store(true)
			<-done
			t.Fatalf("root's directory was chmodded after %d attempts", i+1)
		}
		junk, _ := filepath.Glob(filepath.Join(work, "junk*"))
		for _, j := range junk {
			var st syscall.Stat_t
			if syscall.Lstat(j, &st) == nil && st.Uid == 0 {
				os.Rename(j, rd)
				continue
			}
			syscall.Rmdir(j)
		}
		var st syscall.Stat_t
		if syscall.Lstat(d, &st) == nil && st.Uid == 65534 {
			syscall.Rmdir(d)
		}
	}
	stop.Store(true)
	<-done
}
