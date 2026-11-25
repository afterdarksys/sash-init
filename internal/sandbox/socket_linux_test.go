// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

// bindUnix binds a pathname Unix socket at p and removes it again.
func bindUnix(p string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: p}); err != nil {
		return err
	}
	return unix.Unlink(p)
}

// socketProbe binds a socket in each NAME=DIR of SAHT_BIND, tries every
// other special file in SAHT_SPECIAL, and connects to SAHT_CONNECT.
func socketProbe() {
	for _, kv := range strings.Split(os.Getenv("SAHT_BIND"), ",") {
		name, dir, _ := strings.Cut(kv, "=")
		fmt.Printf("bind_%s=%s\n", name, errName(bindUnix(dir+"/s.sock")))
	}
	if d := os.Getenv("SAHT_SPECIAL"); d != "" {
		fmt.Printf("fifo=%s\n", errName(unix.Mkfifo(d+"/f", 0o600)))
		fmt.Printf("char=%s\n", errName(unix.Mknod(d+"/c", unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3)))))
		fmt.Printf("block=%s\n", errName(unix.Mknod(d+"/b", unix.S_IFBLK|0o600, int(unix.Mkdev(7, 0)))))
		fmt.Printf("sym=%s\n", errName(unix.Symlink("/etc/passwd", d+"/l")))
		fd, err := unix.Open(d+"/r", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
		fmt.Printf("reg=%s\n", errName(err))
		if err == nil {
			unix.Close(fd)
			unix.Unlink(d + "/r")
		}
	}
	if p := os.Getenv("SAHT_CONNECT"); p != "" {
		c, err := net.Dial("unix", p)
		fmt.Printf("connect=%s\n", errName(err))
		if err == nil {
			c.Close()
		}
	}
	statusLines("")
}

type socketDirs struct {
	bin, rw, sock, deep, other, ro, out, file, link string
}

// socketFixture makes the directories, all writable by the service's uid as
// far as file permissions go, so only Landlock decides; the probe is copied
// into bin so that no listed path has to cover /tmp.
func socketFixture(t *testing.T, self string) socketDirs {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "sahsock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	d := socketDirs{bin: base + "/bin", rw: base + "/rw", sock: base + "/rw/sock", deep: base + "/rw/sock/deep",
		other: base + "/other", ro: base + "/ro", out: base + "/out", file: base + "/rw/file", link: base + "/rw/link"}
	for _, p := range []string{d.bin, d.rw, d.sock, d.deep, d.other, d.ro, d.out} {
		if err := os.Mkdir(p, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(d.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.bin+"/probe", raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(d.sock, d.link); err != nil {
		t.Fatal(err)
	}
	return d
}

func runSocketProbe(t *testing.T, self string, ident unit.Execution, d socketDirs, sb *unit.Sandbox, env ...string) (map[string]string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	ident.Environment = append([]string{"SAHT_CAPS_PROBE=socket"}, env...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, claim, _, err := Launch(ctx, self, []string{d.bin + "/probe"}, sb, false, 5*time.Second, Options{Execution: ident, Stdout: &out, Stderr: &errb})
	if err != nil {
		return nil, "", err
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v: %s %s", err, out.String(), errb.String())
	}
	return parseProbe(out.String()), claim, nil
}

// A socket path allows binding beneath it and nowhere else: not in the
// read_write path above it, another read_write path, a read-only path or
// outside every path. Without the field no bind works anywhere (the
// reported failure). FIFOs, device nodes and symlinks stay denied inside a
// socket path; connecting to a socket outside every path still works,
// since Landlock does not confine connect.
func TestSocketPathsBind(t *testing.T) {
	self, ident := capsSetup(t)
	d := socketFixture(t, self)
	ext, err := net.Listen("unix", d.out+"/ext.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ext.Close() })
	if err := os.Chmod(d.out+"/ext.sock", 0o777); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ext.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	bind := "SAHT_BIND=sock=" + d.sock + ",deep=" + d.deep + ",rw=" + d.rw + ",other=" + d.other + ",ro=" + d.ro + ",out=" + d.out
	env := []string{bind, "SAHT_SPECIAL=" + d.sock, "SAHT_CONNECT=" + d.out + "/ext.sock"}
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{d.bin, "/usr", "/proc", d.ro}, ReadWrite: []string{d.rw, d.other}, Sockets: []string{d.sock}}
	got, _, err := runSocketProbe(t, self, ident, d, sb, env...)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys(t, got, map[string]string{
		"bind_sock": "ok", "bind_deep": "ok", "bind_rw": "EACCES", "bind_other": "EACCES", "bind_ro": "EACCES", "bind_out": "EACCES",
		"fifo": "EACCES", "char": "EACCES", "block": "EACCES", "sym": "EACCES", "reg": "ok", "connect": "ok", "NoNewPrivs": "1",
	})
	sb.Sockets = nil
	got, _, err = runSocketProbe(t, self, ident, d, sb, env...)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys(t, got, map[string]string{"bind_sock": "EACCES", "bind_deep": "EACCES", "bind_rw": "EACCES", "reg": "ok", "connect": "ok"})
	// A socket path equal to its read_write path.
	sb.Sockets = []string{d.rw}
	got, _, err = runSocketProbe(t, self, ident, d, sb, "SAHT_BIND=rw="+d.rw+",sock="+d.sock+",other="+d.other)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys(t, got, map[string]string{"bind_rw": "ok", "bind_sock": "ok", "bind_other": "EACCES"})
}

// The helper refuses a socket path outside every read_write path
// (sandbox_socket), and one that is missing, a link or not a directory
// (sandbox_path); nothing runs.
func TestSocketPathsRefused(t *testing.T) {
	self, ident := capsSetup(t)
	d := socketFixture(t, self)
	for sock, want := range map[string]string{
		d.out:              "sandbox_socket",
		d.ro:               "sandbox_socket",
		d.rw + "/missing":  "sandbox_path",
		d.link:             "sandbox_path",
		d.file:             "sandbox_path",
		d.link + "/deep":   "sandbox_path",
		d.sock + "/../out": "sandbox_path",
	} {
		sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{d.bin, "/usr", d.ro}, ReadWrite: []string{d.rw}, Sockets: []string{sock}}
		got, claim, err := runSocketProbe(t, self, ident, d, sb, "SAHT_BIND=sock="+d.sock)
		if fail.Token(err) != want || got != nil || claim != "" {
			t.Errorf("%s: %v %v %q, want %s", sock, err, got, claim, want)
		}
	}
}

// A setuid/setgid unit binds in its socket path under the id filter, and a
// socket path cannot be used to reach /proc.
func TestSocketPathsCapped(t *testing.T) {
	self, ident := capsSetup(t)
	d := socketFixture(t, self)
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{d.bin, "/usr", "/proc"}, ReadWrite: []string{d.rw}, Sockets: []string{d.sock},
		Caps: []string{"setuid", "setgid"}, SetuidTo: []uint32{65533}, SetgidTo: []uint32{65533}}
	got, claim, err := runSocketProbe(t, self, ident, d, sb, "SAHT_BIND=sock="+d.sock+",rw="+d.rw)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys(t, got, map[string]string{"bind_sock": "ok", "bind_rw": "EACCES", "Seccomp": "2"})
	if claim != SandboxClaim(min(landlockABI(), MaxLandlockABI))+idFilterClaim {
		t.Fatalf("claim %q", claim)
	}
	for _, tc := range []struct {
		rw, sock []string
		want     string
	}{
		{[]string{d.rw}, []string{"/proc"}, "sandbox_socket"},
		{[]string{d.rw}, []string{"/proc/self"}, "sandbox_socket"},
		{[]string{"/proc"}, []string{"/proc"}, "sandbox_proc"},
	} {
		sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{d.bin, "/usr"}, ReadWrite: tc.rw, Sockets: tc.sock, Caps: []string{"setuid"}, SetuidTo: []uint32{65533}}
		got, claim, err := runSocketProbe(t, self, ident, d, sb, "SAHT_BIND=sock="+d.sock)
		if fail.Token(err) != tc.want || got != nil || claim != "" {
			t.Errorf("%v %v: %v %v %q, want %s", tc.rw, tc.sock, err, got, claim, tc.want)
		}
	}
}

// The spec carries socket_paths only when there are some, so a unit without
// them sends the helper exactly what it sent before.
func TestSocketPathsSpec(t *testing.T) {
	buf, err := marshalSpecPass(&unit.Sandbox{NoNewPrivs: true, ReadWrite: []string{"/run/a"}}, false, false, 0, nil, nil, Options{})
	if err != nil || bytes.Contains(buf, []byte("socket_paths")) {
		t.Fatalf("%s %v", buf, err)
	}
	buf, err = marshalSpecPass(&unit.Sandbox{NoNewPrivs: true, ReadWrite: []string{"/run/a"}, Sockets: []string{"/run/a"}}, false, false, 0, nil, nil, Options{})
	if err != nil || !bytes.Contains(buf, []byte(`"socket_paths":["/run/a"]`)) {
		t.Fatalf("%s %v", buf, err)
	}
}
