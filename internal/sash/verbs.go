package sash

// The verb server: sahinit's side of the verb socket for one sash session
// (docs/design/sash-services-1.md, "Verbs (batch 1)").
//
// Threats: sash runs a service script, as an unprivileged user, and a parser
// or interpreter bug in sash must reach no further than the grant. So every
// verb is checked here again, never trusting that sash checked it: the key
// is in the grant; a check session (fn check) mutates nothing
// (check_read_only); spawn's program is absolute, clean, listed in exec and
// (by the host) on the trusted walk; its identity is exactly the grant's;
// each env name is on the grant's env_names and off the denylist; cwd is
// under a file_read or file_write root (the host resolves it with no
// symlinks); caps are in the grant and within the unit's own sandbox caps;
// limits are within sahinit's ceilings; a file: stream lies under file_write
// (the host opens it beneath the root, no symlinks). signal, wait, proc,
// output and probe notify take a name from this service's table, never a
// pid. A tcp probe reaches loopback, or private and link-local addresses
// with allow_private, never a public address, and never looks a name up.
// Anything else, fs.mount and the file verbs included, is unsupported.
// A secret env value reaches only the child's environment: it is never in
// an error, a log line, status or diagnostics (errors here are fixed
// tokens).

import (
	"encoding/json"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Host performs what the server has checked.
type Host interface {
	// Spawn starts plan as p, in the service's cgroup, and arranges
	// p.Exit when it ends and p.SetReady when it writes its readiness fd.
	// It resolves the program with the trusted walk, the identity to the
	// unit's ids, cwd and file streams without symlinks.
	Spawn(plan SpawnPlan, p *Proc) error
	// Signal sends sig (a name from Signals) to p through its pidfd.
	Signal(p *Proc, sig string) error
	// Status is any service's row: name, state, since, pid.
	Status(service string) (Row, error)
	// DialTCP reports whether addr accepts a connection.
	DialTCP(addr string) bool
	// ProbePath reports whether p (unix: a socket that accepts, file: any
	// file) exists beneath root, resolved with no symlinks.
	ProbePath(kind, root, p string) bool
}

// SpawnPlan is a checked spawn.
type SpawnPlan struct {
	Name    string
	Program string
	Argv    []string // argv[0] is Program
	User    string
	Group   string
	Env     []EnvVar
	Cwd     string // "" for none
	CwdRoot string
	Umask   int // -1 for none
	Caps    []string
	Limits  map[string]uint64
	Stdout  Stream
	Stderr  Stream
}

// EnvVar is one environment entry. Secret marks a value that arrived as
// {"secret": ...}: it goes to the child's environment and nowhere else.
type EnvVar struct {
	Name   string
	Value  string
	Secret bool
}

// Stream is where a child's stdout or stderr goes: journal, null, file
// (Path beneath Root) or stdout (stderr only).
type Stream struct {
	Kind string
	Path string
	Root string
}

// Server answers one session's verbs.
type Server struct {
	G     Grant
	Table *Table
	Host  Host
	// Check is a check session: mutating verbs are check_read_only.
	Check bool
	// CapCeiling is the unit's own sandbox caps (sahinit names).
	CapCeiling []string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// verbKeys are the batch 1 keys and whether each mutates.
var verbKeys = map[string]bool{
	"svc.spawn": true, "svc.signal": true, "svc.wait": false, "svc.proc": false,
	"svc.status": false, "svc.probe": false, "svc.output": false,
}

var (
	procName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	umaskRe  = regexp.MustCompile(`^0?[0-7]{3}$`)
)

// limitCeilings are sahinit's ceilings for spawn's limits. core is 0: a
// core dump could hold a secret from the environment.
var limitCeilings = map[string]uint64{
	"nofile": 1 << 16, "nproc": 1 << 16, "core": 0, "memlock": 64 << 20,
	"stack": 64 << 20, "as": 1 << 40, "cpu": 1 << 31, "fsize": 1 << 40,
}

// capNames maps a grant capability to sahinit's closed set.
var capNames = map[string]string{
	"CAP_CHOWN": "chown", "CAP_DAC_OVERRIDE": "dac_override", "CAP_FOWNER": "fowner", "CAP_KILL": "kill",
	"CAP_SETGID": "setgid", "CAP_SETUID": "setuid", "CAP_NET_BIND_SERVICE": "net_bind_service",
	"CAP_NET_ADMIN": "net_admin", "CAP_SYS_ADMIN": "sys_admin",
}

const (
	maxSpawnArgv = 32
	maxSpawnArg  = 256
	maxEnv       = 128
	maxEnvBytes  = 16384
	maxWait      = 24 * time.Hour
	maxTail      = 10000
)

var (
	errDenied      = fail.E("denied")
	errUnsupported = fail.E("unsupported")
)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handle answers one request. It never panics the session: a host panic is
// answered as failed.
func (s *Server) Handle(req Request) (resp Response) {
	defer func() {
		if recover() != nil {
			resp = Response{Error: "failed"}
		}
	}()
	out, err := s.handle(req)
	if err != nil {
		return Response{Error: fail.Token(err)}
	}
	return out
}

func (s *Server) handle(req Request) (Response, error) {
	mutates, known := verbKeys[req.Key]
	if !known {
		return Response{}, errUnsupported
	}
	if !s.G.Has(req.Key) {
		return Response{}, errDenied
	}
	if s.Check && mutates {
		return Response{}, fail.E("check_read_only")
	}
	a := req.Argv
	if len(a) == 0 || len(req.Body) > 0 && req.Key != "svc.spawn" {
		return Response{}, errDenied
	}
	switch req.Key {
	case "svc.spawn":
		return s.spawn(req)
	case "svc.signal":
		if len(a) != 3 || a[0] != "signal" || !Signals[a[2]] {
			return Response{}, errDenied
		}
		p, err := s.lookup(a[1])
		if err != nil {
			return Response{}, err
		}
		if !p.Ended() {
			if err := s.Host.Signal(p, a[2]); err != nil {
				return Response{}, fail.E("failed")
			}
		}
		return Response{Kind: "bytes"}, nil
	case "svc.wait":
		if len(a) != 4 || a[0] != "wait" || a[2] != "timeout" {
			return Response{}, errDenied
		}
		d, err := time.ParseDuration(a[3])
		if err != nil || d <= 0 || d > maxWait {
			return Response{}, errDenied
		}
		p, err := s.lookup(a[1])
		if err != nil {
			return Response{}, err
		}
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-p.Done():
		case <-t.C:
			return Response{}, fail.E("timeout")
		}
		code, sig, at := p.Result()
		return rows([]string{"name", "exit", "signal", "ended_at"}, Row{"name": p.Name, "exit": strconv.Itoa(code), "signal": sig, "ended_at": stamp(at)}), nil
	case "svc.proc":
		if len(a) != 2 || a[0] != "proc" {
			return Response{}, errDenied
		}
		p, err := s.lookup(a[1])
		if err != nil {
			return Response{}, err
		}
		state := "running"
		if p.Ended() {
			state = "exited"
		}
		return rows([]string{"name", "pid", "state", "started_at"}, Row{"name": p.Name, "pid": strconv.Itoa(p.Pid), "state": state, "started_at": stamp(p.Started)}), nil
	case "svc.output":
		return s.output(a)
	case "svc.status":
		if len(a) != 3 || a[0] != "service" || a[1] != "status" || !ServiceName.MatchString(a[2]) {
			return Response{}, errDenied
		}
		row, err := s.Host.Status(a[2])
		if err != nil {
			return Response{}, err
		}
		return rows([]string{"name", "state", "since", "pid"}, row), nil
	case "svc.probe":
		return s.probe(a)
	}
	return Response{}, errUnsupported
}

func rows(cols []string, r Row) Response {
	return Response{Kind: "rows", Cols: cols, Rows: []Row{r}}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) lookup(name string) (*Proc, error) {
	if !procName.MatchString(name) {
		return nil, errDenied
	}
	p := s.Table.Get(name)
	if p == nil {
		return nil, fail.E("unknown_name")
	}
	return p, nil
}

func (s *Server) output(a []string) (Response, error) {
	if len(a) < 2 || a[0] != "output" {
		return Response{}, errDenied
	}
	p, err := s.lookup(a[1])
	if err != nil {
		return Response{}, err
	}
	rest := a[2:]
	tail := p.Stdout
	if len(rest) > 0 && rest[0] == "stderr" {
		tail, rest = p.Stderr, rest[1:]
	}
	n := 0
	if len(rest) == 2 && rest[0] == "tail" {
		v, err := strconv.Atoi(rest[1])
		if err != nil || v < 1 || v > maxTail {
			return Response{}, errDenied
		}
		n, rest = v, nil
	}
	if len(rest) != 0 {
		return Response{}, errDenied
	}
	out := Response{Kind: "rows", Cols: []string{"line", "text"}}
	for i, l := range tail.Lines(n) {
		out.Rows = append(out.Rows, Row{"line": strconv.Itoa(i + 1), "text": l})
	}
	return out, nil
}

func (s *Server) probe(a []string) (Response, error) {
	if len(a) != 3 || a[0] != "probe" {
		return Response{}, errDenied
	}
	ready := false
	switch a[1] {
	case "tcp":
		if !ProbeTarget(a[2], s.G.AllowPrivate) {
			return Response{}, errDenied
		}
		ready = s.Host.DialTCP(a[2])
	case "unix", "file":
		p := a[2]
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsRune(p, 0) {
			return Response{}, errDenied
		}
		root := RootOf(s.G.FileRead, p)
		if root == "" {
			return Response{}, errDenied
		}
		ready = s.Host.ProbePath(a[1], root, p)
	case "notify":
		p, err := s.lookup(a[2])
		if err != nil {
			return Response{}, err
		}
		ready = p.Ready() && !p.Ended()
	default:
		return Response{}, errDenied
	}
	if ready {
		return Response{Kind: "bytes"}, nil
	}
	return Response{Kind: "bytes", Exit: 1}, nil
}

// ProbeTarget reports whether HOST:PORT may be probed: an IP literal or
// localhost (no name lookup), a port 1-65535, and loopback, or with
// allowPrivate a private or link-local address. Never a public one.
func ProbeTarget(target string, allowPrivate bool) bool {
	host, port, ok := strings.Cut(target, ":")
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]:")
		if end < 0 {
			return false
		}
		host, port, ok = target[1:end], target[end+2:], true
	} else if strings.Count(target, ":") != 1 {
		return false
	}
	n, err := strconv.Atoi(port)
	if !ok || err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	return allowPrivate && (addr.IsPrivate() || addr.IsLinkLocalUnicast())
}

var spawnOptKeys = map[string]bool{"user": true, "group": true, "cwd": true, "umask": true, "env": true, "limits": true, "caps": true, "stdout": true, "stderr": true}

func (s *Server) spawn(req Request) (Response, error) {
	a := req.Argv
	if len(a) < 3 || a[0] != "spawn" || !procName.MatchString(a[1]) || len(a)-2 > maxSpawnArgv {
		return Response{}, errDenied
	}
	prog := a[2]
	if !strings.HasPrefix(prog, "/") || path.Clean(prog) != prog || prog == "/" || strings.ContainsAny(prog, " \t\n\r;|&$<>()`'\"*?[]{}\\~#!\x00") {
		return Response{}, errDenied
	}
	if !s.G.AllowsExec(prog) {
		return Response{}, errDenied
	}
	for _, arg := range a[3:] {
		if len(arg) > maxSpawnArg || strings.ContainsRune(arg, 0) {
			return Response{}, errDenied
		}
	}
	plan := SpawnPlan{Name: a[1], Program: prog, Argv: append([]string{prog}, a[3:]...), Umask: -1,
		Stdout: Stream{Kind: "journal"}, Stderr: Stream{Kind: "journal"}}
	opts := map[string]json.RawMessage{}
	if len(req.Body) > 0 {
		if err := decodeObject(req.Body, &opts); err != nil {
			return Response{}, errDenied
		}
	}
	for k := range opts {
		if !spawnOptKeys[k] {
			return Response{}, errDenied
		}
	}
	str := func(k string) (string, bool, error) {
		raw, ok := opts[k]
		if !ok {
			return "", false, nil
		}
		var v string
		if err := decodeObject(raw, &v); err != nil || strings.ContainsRune(v, 0) {
			return "", true, errDenied
		}
		return v, true, nil
	}
	// Identity: exactly the grant's. sash always sends both; an omitted
	// one is the grant's as well.
	plan.User, plan.Group = s.G.User, s.G.Group
	for _, k := range []string{"user", "group"} {
		v, ok, err := str(k)
		if err != nil {
			return Response{}, err
		}
		want := s.G.User
		if k == "group" {
			want = s.G.Group
		}
		if ok && v != want {
			return Response{}, errDenied
		}
	}
	if v, ok, err := str("cwd"); err != nil {
		return Response{}, err
	} else if ok {
		if !strings.HasPrefix(v, "/") || path.Clean(v) != v {
			return Response{}, errDenied
		}
		root := RootOf(s.G.FileRead, v)
		if root == "" {
			root = RootOf(s.G.FileWrite, v)
		}
		if root == "" {
			return Response{}, errDenied
		}
		plan.Cwd, plan.CwdRoot = v, root
	}
	if v, ok, err := str("umask"); err != nil {
		return Response{}, err
	} else if ok {
		if !umaskRe.MatchString(v) {
			return Response{}, errDenied
		}
		n, _ := strconv.ParseUint(v, 8, 32)
		plan.Umask = int(n)
	}
	if raw, ok := opts["env"]; ok {
		env, err := s.env(raw)
		if err != nil {
			return Response{}, err
		}
		plan.Env = env
	}
	if raw, ok := opts["caps"]; ok {
		var caps []string
		if err := decodeObject(raw, &caps); err != nil {
			return Response{}, errDenied
		}
		for _, c := range caps {
			if !s.G.AllowsCap(c) {
				return Response{}, errDenied
			}
			name, known := capNames[c]
			if !known || !exact(s.CapCeiling, name) {
				return Response{}, fail.E("ceiling")
			}
			if !exact(plan.Caps, name) {
				plan.Caps = append(plan.Caps, name)
			}
		}
	}
	if raw, ok := opts["limits"]; ok {
		var lim map[string]json.Number
		if err := decodeObject(raw, &lim); err != nil {
			return Response{}, errDenied
		}
		plan.Limits = map[string]uint64{}
		for k, num := range lim {
			ceil, known := limitCeilings[k]
			n, err := strconv.ParseUint(num.String(), 10, 64)
			if !known || err != nil {
				return Response{}, errDenied
			}
			if n > ceil {
				return Response{}, fail.E("ceiling")
			}
			plan.Limits[k] = n
		}
	}
	for _, k := range []string{"stdout", "stderr"} {
		v, ok, err := str(k)
		if err != nil {
			return Response{}, err
		}
		if !ok {
			continue
		}
		var st Stream
		switch {
		case v == "journal" || v == "null" || (k == "stderr" && v == "stdout"):
			st.Kind = v
		case strings.HasPrefix(v, "file:"):
			p := strings.TrimPrefix(v, "file:")
			if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
				return Response{}, errDenied
			}
			root := RootOf(s.G.FileWrite, p)
			if root == "" || root == p {
				return Response{}, errDenied
			}
			st = Stream{Kind: "file", Path: p, Root: root}
		default:
			return Response{}, errDenied
		}
		if k == "stdout" {
			plan.Stdout = st
		} else {
			plan.Stderr = st
		}
	}
	p, ok := s.Table.Reserve(plan.Name)
	if !ok {
		return Response{}, fail.E("name_in_use")
	}
	if err := s.Host.Spawn(plan, p); err != nil {
		s.Table.Release(p)
		switch tok := fail.Token(err); tok {
		case "denied", "ceiling":
			return Response{}, err
		default:
			return Response{}, fail.E("failed")
		}
	}
	return rows([]string{"name", "pid", "started_at"}, Row{"name": p.Name, "pid": strconv.Itoa(p.Pid), "started_at": stamp(p.Started)}), nil
}

// env checks the env map: each name on the grant's allowlist and off the
// denylist; each value a string or {"secret": string}.
func (s *Server) env(raw json.RawMessage) ([]EnvVar, error) {
	var m map[string]json.RawMessage
	if err := decodeObject(raw, &m); err != nil || len(m) > maxEnv {
		return nil, errDenied
	}
	var out []EnvVar
	total := 0
	for name, v := range m {
		if !s.G.AllowsEnv(name) {
			return nil, fail.E("env_refused")
		}
		e := EnvVar{Name: name}
		if err := decodeObject(v, &e.Value); err != nil {
			var sec struct {
				Secret *string `json:"secret"`
			}
			if err := decodeObject(v, &sec); err != nil || sec.Secret == nil {
				return nil, errDenied
			}
			e.Value, e.Secret = *sec.Secret, true
		}
		if strings.ContainsRune(e.Value, 0) {
			return nil, errDenied
		}
		total += len(name) + 1 + len(e.Value)
		if total > maxEnvBytes {
			return nil, errDenied
		}
		out = append(out, e)
	}
	return out, nil
}

// decodeObject decodes one JSON value strictly: unknown fields and
// trailing data are refused; numbers stay exact.
func decodeObject(raw []byte, dst any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errDenied
	}
	return nil
}

// Serve answers frames on rw until it closes, a frame is too long, or a
// write fails.
func Serve(rw io.ReadWriter, s *Server) error {
	for {
		body, err := ReadFrame(rw)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var resp Response
		if req, derr := DecodeRequest(body); derr != nil {
			resp = Response{Error: "frame body"}
		} else {
			resp = s.Handle(req)
		}
		out, err := EncodeResponse(resp)
		if err != nil {
			out, _ = EncodeResponse(Response{Error: "failed"})
		}
		if err := WriteFrame(rw, out); err != nil {
			return err
		}
	}
}
