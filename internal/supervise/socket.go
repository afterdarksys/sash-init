package supervise

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/frame"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
	"github.com/afterdarksys/sahinit/internal/unit"
	"golang.org/x/sys/unix"
)

var reqKeys = map[string]struct{}{
	"op": {}, "name": {}, "arg": {},
}

type response struct {
	OK          bool         `json:"ok"`
	Error       string       `json:"error"`
	Rows        []Row        `json:"rows,omitempty"`
	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`
}

// Listen binds a local stream unix socket. The mode follows the allowlist:
// 0600 when only the supervisor's own uid may connect, otherwise 0660 with
// group SocketGID, which must then be set (socket_group). The parent
// directory must be trusted like an executable's (socket_perm). An exclusive
// lock on PATH.lock is taken first and held until Close; a second supervisor
// is refused with socket_busy. A leftover socket is removed only when it is
// a socket, owned by our uid, and refuses a connect; anything else at the
// path is left in place (socket_exists).
//
// Threats: the mode is a first gate only; every request is still checked
// against the allowlist by peer credentials. The socket is bound, chmodded
// and chowned inside a fresh 0700 directory and then hard-linked into place,
// so its mode is set before anyone can reach it and no chmod ever follows a
// link at PATH. A live socket, another uid's socket, or a non-socket is
// never removed, and the lock stops two supervisors from both judging one
// socket stale.
func (sup *Supervisor) Listen(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fail.E("failed")
	}
	mode, gid, err := sup.socketMode()
	if err != nil {
		return err
	}
	dir, err := unit.TrustedDir(filepath.Dir(path))
	if err != nil {
		return fail.E("socket_perm")
	}
	// A sticky directory (/tmp) is trusted for executables, but anyone can
	// pre-create the socket or its lock there and keep the supervisor from
	// starting: the socket's directory must be writable by its owner only.
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm()&0o022 != 0 {
		return fail.E("socket_perm")
	}
	path = filepath.Join(dir, filepath.Base(path))
	lock, err := lockSocket(path + ".lock")
	if err != nil {
		return err
	}
	ln, err := bindSocket(path, mode, gid)
	if err != nil {
		unlockSocket(lock)
		return err
	}
	sup.mu.Lock()
	sup.ln = ln
	sup.bound = path
	sup.lock = lock
	sup.mu.Unlock()
	return nil
}

func bindSocket(path string, mode os.FileMode, gid int) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !staleSocket(path, fi) {
			return nil, fail.E("socket_exists")
		}
		if err := os.Remove(path); err != nil {
			return nil, fail.E("failed")
		}
	} else if !os.IsNotExist(err) {
		return nil, fail.E("failed")
	}
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".s")
	if err != nil {
		return nil, fail.E("failed")
	}
	defer os.RemoveAll(tmp)
	private := tmp + "/s"
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: private, Net: "unix"})
	if err != nil {
		return nil, fail.E("failed")
	}
	ln.SetUnlinkOnClose(false)
	if err := setSocketPerm(private, mode, gid); err != nil {
		ln.Close()
		return nil, fail.E("failed")
	}
	if err := os.Link(private, path); err != nil {
		ln.Close()
		if errors.Is(err, os.ErrExist) {
			return nil, fail.E("socket_exists")
		}
		return nil, fail.E("failed")
	}
	return ln, nil
}

// lockSocket takes an exclusive lock on a private lock file beside the
// socket. A lock file that is not ours is socket_exists; a held lock is
// socket_busy. The open file must still be the one at the path after the
// lock is taken, since Close unlinks it.
func lockSocket(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fail.E("socket_exists")
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 || st.Nlink != 1 {
		f.Close()
		return nil, fail.E("socket_exists")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fail.E("socket_busy")
	}
	var now unix.Stat_t
	if err := unix.Lstat(path, &now); err != nil || now.Dev != st.Dev || now.Ino != st.Ino {
		f.Close()
		return nil, fail.E("socket_busy")
	}
	return f, nil
}

// unlockSocket removes the lock file while still holding the lock, then
// releases it.
func unlockSocket(f *os.File) error {
	if f == nil {
		return nil
	}
	rerr := os.Remove(f.Name())
	cerr := f.Close()
	if rerr != nil && !os.IsNotExist(rerr) {
		return rerr
	}
	return cerr
}

// socketMode returns the socket mode and group (-1 for none).
func (sup *Supervisor) socketMode() (os.FileMode, int, error) {
	euid := uint32(os.Geteuid())
	others := false
	for uid := range sup.Allow {
		if uid != euid {
			others = true
		}
	}
	if !others {
		return 0o600, -1, nil
	}
	if sup.SocketGID == nil {
		return 0, -1, fail.E("socket_group")
	}
	return 0o660, int(*sup.SocketGID), nil
}

func setSocketPerm(path string, mode os.FileMode, gid int) error {
	if gid >= 0 {
		if err := os.Lchown(path, -1, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

func staleSocket(path string, fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || fi.Mode()&os.ModeSocket == 0 || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		c.Close()
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// Close closes the listener and unlinks only the socket this process bound.
func (sup *Supervisor) Close() error {
	sup.mu.Lock()
	ln := sup.ln
	path := sup.bound
	lock := sup.lock
	sup.ln = nil
	sup.bound = ""
	sup.lock = nil
	sup.mu.Unlock()
	var first error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			first = err
		}
	}
	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	if err := unlockSocket(lock); err != nil && first == nil {
		first = err
	}
	if first != nil {
		return fail.E("failed")
	}
	return nil
}

// Serve accepts one request per connection. A second call returns failed.
func (sup *Supervisor) Serve() error {
	if !sup.serving.CompareAndSwap(false, true) {
		return fail.E("failed")
	}
	sup.mu.Lock()
	ln := sup.ln
	sup.mu.Unlock()
	if ln == nil {
		return fail.E("failed")
	}
	n := sup.MaxHandlers
	if n <= 0 {
		n = 32
	}
	slots := make(chan struct{}, n)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fail.E("failed")
		}
		select {
		case slots <- struct{}{}:
			go func(c *net.UnixConn) {
				sup.handle(c)
				<-slots
			}(conn)
		default:
			sup.rejectFull(conn)
		}
	}
}

func (sup *Supervisor) rejectFull(conn *net.UnixConn) {
	defer conn.Close()
	uid, pid, err := peerCred(conn)
	if err != nil || !sup.allowed(uid) {
		sup.writeResp(conn, response{OK: false, Error: "uid_denied"})
		return
	}
	if sup.supervisedPeer(pid) {
		sup.writeResp(conn, response{OK: false, Error: "peer_supervised"})
		return
	}
	sup.writeResp(conn, response{OK: false, Error: "busy"})
}

func (sup *Supervisor) handle(conn *net.UnixConn) {
	defer conn.Close()
	dl := sup.ReadDeadline
	if dl <= 0 {
		dl = 5 * time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(dl)); err != nil {
		return
	}
	uid, pid, uidErr := peerCred(conn)
	payload, readErr := frame.Read(conn)
	if uidErr != nil || !sup.allowed(uid) {
		sup.writeResp(conn, response{OK: false, Error: "uid_denied"})
		return
	}
	// Checked when the request is acted on, after the frame is read, so a
	// service started after the peer connected is still caught.
	if sup.supervisedPeer(pid) {
		sup.writeResp(conn, response{OK: false, Error: "peer_supervised"})
		return
	}
	if readErr != nil {
		sup.writeResp(conn, response{OK: false, Error: fail.Token(readErr)})
		return
	}
	op, name, arg, err := parseReq(payload)
	if err != nil {
		sup.writeResp(conn, sup.mutResp(name, err))
		return
	}
	sup.writeResp(conn, sup.dispatch(op, name, arg))
}

func (sup *Supervisor) dispatch(op, name, arg string) response {
	ctx := context.Background()
	switch op {
	case "diagnostics":
		d, err := sup.Diagnostics(name)
		return response{OK: err == nil, Error: fail.Token(err), Diagnostics: d}
	case "status":
		rows, err := sup.Status(name)
		if err != nil {
			return response{OK: false, Error: fail.Token(err)}
		}
		return response{OK: true, Error: "", Rows: rows}
	case "start":
		if s, ok := sup.oneshot(name); ok {
			return sup.mutResp(s.svc.Name, fail.E("arg_required"))
		}
		return sup.mutResp(name, sup.Start(ctx, name))
	case "stop":
		return sup.mutResp(name, sup.Stop(ctx, name))
	case "restart":
		return sup.mutResp(name, sup.Restart(ctx, name))
	case "oneshot":
		return sup.mutResp(name, sup.Oneshot(ctx, name, arg))
	default:
		resp := response{OK: false, Error: "unknown_op"}
		if unit.NameOK(name) {
			if rows, err := sup.Status(name); err == nil {
				resp.Rows = rows
			}
		}
		return resp
	}
}

func (sup *Supervisor) oneshot(name string) (*runtime, bool) {
	if !unit.NameOK(name) {
		return nil, false
	}
	s, ok := sup.rt[name]
	if !ok || s.svc.Type != "oneshot" {
		return nil, false
	}
	return s, true
}

func (sup *Supervisor) mutResp(name string, err error) response {
	token := fail.Token(err)
	resp := response{OK: err == nil, Error: token}
	if !unit.NameOK(name) {
		return resp
	}
	rows, stErr := sup.Status(name)
	if stErr != nil {
		return resp
	}
	resp.Rows = rows
	return resp
}

// supervisedPeer reports whether pid is in a process group that a service
// has led, now or in an earlier start, while that group has members. Each
// service leads its own group, so a leader's leftover children are still
// recognised after it exits. An unknown pid (0, or a process that is gone)
// counts as supervised.
//
// Threats: a service with an allowed uid could otherwise stop or restart
// other services. Not caught here, until cgroups (batch 2): a service that
// leaves its group with setsid or setpgid, and a peer that exits after
// sending its request whose pid is reused before this check.
func (sup *Supervisor) supervisedPeer(pid int) bool {
	if pid <= 0 {
		return true
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return true
	}
	for _, s := range sup.rt {
		s.mu.Lock()
		hit := s.ledGroupLocked(pgid)
		s.mu.Unlock()
		if hit {
			return true
		}
	}
	return false
}

func (sup *Supervisor) allowed(uid uint32) bool {
	if sup.Allow == nil {
		return uid == uint32(os.Geteuid())
	}
	_, ok := sup.Allow[uid]
	return ok
}

func (sup *Supervisor) writeResp(conn *net.UnixConn, resp response) {
	buf, err := json.Marshal(resp)
	if err != nil {
		return
	}
	dl := sup.ReadDeadline
	if dl <= 0 {
		dl = 5 * time.Second
	}
	if err := conn.SetWriteDeadline(time.Now().Add(dl)); err != nil {
		return
	}
	if err := frame.Write(conn, buf); err != nil {
		return
	}
}

func parseReq(raw []byte) (string, string, string, error) {
	obj, err := jsonobj.Decode(raw, reqKeys)
	if err != nil {
		return "", "", "", err
	}
	rawOp, ok := obj["op"]
	if !ok {
		return "", "", "", fail.E("failed")
	}
	var op, name, arg string
	if err := jsonobj.Unmarshal(rawOp, &op); err != nil {
		return "", "", "", fail.E("failed")
	}
	if rawName, ok := obj["name"]; ok {
		if err := jsonobj.Unmarshal(rawName, &name); err != nil {
			return "", "", "", fail.E("failed")
		}
	}
	if rawArg, ok := obj["arg"]; ok {
		if err := jsonobj.Unmarshal(rawArg, &arg); err != nil {
			return "", "", "", fail.E("failed")
		}
	}
	if op == "" {
		return op, name, arg, fail.E("unknown_op")
	}
	return op, name, arg, nil
}
