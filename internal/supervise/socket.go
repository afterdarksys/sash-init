package supervise

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/frame"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
	"github.com/afterdarksys/sahinit/internal/unit"
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

// Listen binds a local datagram-free unix socket. An existing path is left in place.
func (sup *Supervisor) Listen(path string) error {
	if path == "" {
		return fail.E("failed")
	}
	if _, err := os.Lstat(path); err == nil {
		return fail.E("socket_exists")
	} else if !os.IsNotExist(err) {
		return fail.E("failed")
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail.E("failed")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		cerr := ln.Close()
		rerr := os.Remove(path)
		if cerr != nil || (rerr != nil && !os.IsNotExist(rerr)) {
			return fail.E("failed")
		}
		return fail.E("failed")
	}
	sup.mu.Lock()
	sup.ln = ln
	sup.bound = path
	sup.mu.Unlock()
	return nil
}

// Close closes the listener and unlinks only the socket this process bound.
func (sup *Supervisor) Close() error {
	sup.mu.Lock()
	ln := sup.ln
	path := sup.bound
	sup.ln = nil
	sup.bound = ""
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
	uid, err := peerUID(conn)
	if err != nil || !sup.allowed(uid) {
		sup.writeResp(conn, response{OK: false, Error: "uid_denied"})
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
	uid, uidErr := peerUID(conn)
	payload, readErr := frame.Read(conn)
	if uidErr != nil || !sup.allowed(uid) {
		sup.writeResp(conn, response{OK: false, Error: "uid_denied"})
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
