// SPDX-License-Identifier: GPL-3.0-or-later

// Package unit loads the static service catalog.
//
// Threats: a unit file is untrusted input. Unknown fields, duplicate keys,
// relative exec paths, symlink unit files, and oversized files are rejected.
// A unit file or unit directory that someone other than root (or the
// supervisor's own uid) owns, or that group or other can write, could be
// swapped for a unit running as root; such a file is refused with unit_perm
// and such a directory refuses the whole catalog.
// This package does not spawn processes and does not grant privileges.
// It does not decide that a sandbox was applied.
package unit

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
	"golang.org/x/sys/unix"
)

const (
	maxFile    = 64 * 1024
	maxUnits   = 256
	maxArgv    = 32
	maxArg     = 256
	maxEdges   = 64
	maxPaths   = 64
	maxPathLen = 4096
	maxTimeout = 5 * time.Minute
)

// DefaultTimeout is the ready, oneshot, and stop-grace limit when a unit
// omits timeout.
const DefaultTimeout = 5 * time.Second

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

var unitKeys = map[string]struct{}{
	"name": {}, "exec": {}, "type": {}, "restart": {}, "ready": {},
	"after": {}, "needs": {}, "wants": {}, "timeout": {}, "boot": {},
	"sandbox": {}, "execution": {},
	"memory_max": {}, "cpu_max": {}, "pids_max": {},
	"sash": {},
}

var sandboxKeys = map[string]struct{}{
	"no_new_privs": {}, "read_only_paths": {}, "read_write_paths": {}, "caps": {},
}

// Closed capability names. Numbers are the Linux capability indexes.
var capByName = map[string]uint32{
	"chown":            0,
	"dac_override":     1,
	"fowner":           3,
	"kill":             5,
	"setgid":           6,
	"setuid":           7,
	"net_bind_service": 10,
	"net_admin":        12,
	"sys_admin":        21,
}

// Service is one catalog entry. Boot is the resolved boot-set bit.
type Service struct {
	Name      string
	Exec      []string
	Type      string
	Restart   string
	Ready     string
	After     []string
	Needs     []string
	Wants     []string
	Timeout   time.Duration
	Boot      bool
	Sandbox   *Sandbox
	Execution Execution
	Limits    Limits
	// Path is Exec[0] resolved and checked by Load. It is empty when that
	// failed at load; the launch then resolves and checks Exec[0] itself.
	Path string
	// Sash is set for a sash service unit (sash.go), which has no Exec.
	Sash *Sash
}

// Sandbox is present only when the unit named a sandbox object.
// NoNewPrivs is always true when Sandbox is non-nil.
type Sandbox struct {
	NoNewPrivs bool
	ReadOnly   []string
	ReadWrite  []string
	Caps       []string
}

// NameOK reports whether name is a catalog key we will accept on the socket.
func NameOK(name string) bool {
	return nameRE.MatchString(name)
}

// LookupCap returns the Linux capability index for a closed name.
func LookupCap(name string) (uint32, bool) {
	v, ok := capByName[name]
	return v, ok
}

// ExecPath rejects relative, unclean, and NUL paths.
func ExecPath(p string) error {
	if p == "" || strings.ContainsRune(p, 0) || !path.IsAbs(p) || path.Clean(p) != p {
		return fail.E("exec_relative")
	}
	return nil
}

// ExecFile resolves p and checks the target, as ResolveExec does.
func ExecFile(p string) error {
	_, err := ResolveExec(p)
	return err
}

// ResolveExec follows symlinks in p once, with ResolveTrusted, and checks
// the result with CheckExec. It returns the resolved path, which is what must
// be run.
//
// Threats: links such as /bin/sh -> dash or /etc/alternatives entries are
// followed once, here; the caller runs the resolved path and never resolves
// the link again, so a link swapped later does not change what runs. A link
// in a directory someone else can write (such as a user's ~/bin) is refused.
func ResolveExec(p string) (string, error) {
	if err := ExecPath(p); err != nil {
		return "", err
	}
	resolved, err := ResolveTrusted(p)
	if err != nil {
		return "", err
	}
	if err := CheckExec(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

const maxLinks = 40

// ResolveTrusted resolves an absolute path one component at a time and
// returns it with no links left. Every directory the walk passes through,
// from / on, must meet the CheckExec directory rule: the directory holding
// each link, and every directory a link target leads into. The final
// component is not checked. A missing component or too many links is
// exec_not_file; an untrusted directory is exec_perm.
func ResolveTrusted(p string) (string, error) {
	if p == "" || p[0] != '/' || strings.ContainsRune(p, 0) {
		return "", fail.E("exec_relative")
	}
	st, err := os.Lstat("/")
	if err != nil || !ownedPerm(st, true) {
		return "", fail.E("exec_perm")
	}
	cur := "/"
	todo := splitPath(p)
	links := 0
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		switch name {
		case ".":
			continue
		case "..":
			cur = path.Dir(cur) // every ancestor of cur was checked on the way in
			continue
		}
		next := path.Join(cur, name)
		st, err := os.Lstat(next)
		if err != nil {
			return "", fail.E("exec_not_file")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxLinks {
				return "", fail.E("exec_not_file")
			}
			target, err := os.Readlink(next)
			if err != nil || target == "" {
				return "", fail.E("exec_not_file")
			}
			if target[0] == '/' {
				cur = "/"
			}
			todo = append(splitPath(target), todo...)
			continue
		}
		if len(todo) == 0 {
			return next, nil
		}
		if !st.IsDir() {
			return "", fail.E("exec_not_file")
		}
		if !ownedPerm(st, true) {
			return "", fail.E("exec_perm")
		}
		cur = next
	}
	return cur, nil
}

// TrustedDir resolves dir with ResolveTrusted and checks the directory
// itself by the same rule (exec_perm when it fails).
func TrustedDir(dir string) (string, error) {
	r, err := ResolveTrusted(dir)
	if err != nil {
		return "", err
	}
	st, err := os.Lstat(r)
	if err != nil || !st.IsDir() {
		return "", fail.E("exec_not_file")
	}
	if !ownedPerm(st, true) {
		return "", fail.E("exec_perm")
	}
	return r, nil
}

func splitPath(p string) []string {
	var out []string
	for _, part := range strings.Split(p, "/") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// CheckExec checks an already resolved path without following any link.
// The file must be a regular executable file. It and every parent directory
// up to / must be owned by root or the supervisor's own uid and not writable
// by group or other; a parent directory with the sticky bit (such as /tmp)
// may be writable by others, since they cannot rename or remove entries they
// do not own. A link anywhere in the path is exec_not_file; a bad owner or
// mode is exec_perm.
//
// Threats: with every component writable only by root or the supervisor,
// nobody else can replace the file between this check and exec. On Linux the
// caller also execs the file through an fd it checks again with fstat.
func CheckExec(p string) error {
	if err := ExecPath(p); err != nil {
		return err
	}
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
		return fail.E("exec_not_file")
	}
	if !ownedPerm(st, false) {
		return fail.E("exec_perm")
	}
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			return fail.E("exec_not_file")
		}
		if !ownedPerm(st, true) {
			return fail.E("exec_perm")
		}
		if dir == "/" {
			return nil
		}
	}
}

func ownedPerm(st os.FileInfo, stickyOK bool) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := uint32(st.Mode().Perm())
	if stickyOK && st.Mode()&os.ModeSticky != 0 {
		perm &^= 0o022
	}
	return trustedOwner(sys.Uid, perm)
}

// Load reads every unit in dir. The directory itself must not be a symlink,
// and it must pass the owner and mode rule or nothing loads (unit_perm). A
// unit file failing that rule is left out and named in refused, keyed by file
// name, while the rest of the catalog still loads.
func Load(dir string) (svcs map[string]*Service, refused map[string]string, err error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, fail.E("failed")
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fail.E("symlink")
	}
	if !fi.IsDir() {
		return nil, nil, fail.E("failed")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || !trustedOwner(st.Uid, uint32(fi.Mode().Perm())) {
		return nil, nil, fail.E("unit_perm")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fail.E("failed")
	}
	if len(entries) == 0 {
		return nil, nil, fail.E("empty")
	}
	var names []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, nil, fail.E("symlink")
		}
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			return nil, nil, fail.E("stray_file")
		}
		names = append(names, name)
	}
	if len(names) > maxUnits {
		return nil, nil, fail.E("too_many")
	}
	out := make(map[string]*Service, len(names))
	refused = map[string]string{}
	for _, name := range names {
		body, err := readUnit(dir + "/" + name)
		if fail.Token(err) == "unit_perm" {
			refused[name] = "unit_perm"
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		svc, err := Parse(body, strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, nil, err
		}
		if _, exists := out[svc.Name]; exists {
			return nil, nil, fail.E("duplicate_field")
		}
		if svc.Sash != nil {
			if tok := checkSashFiles(svc); tok != "" {
				refused[name] = tok
				continue
			}
			if err := resolveSandbox(svc.Sandbox); err != nil {
				return nil, nil, err
			}
			out[svc.Name] = svc
			continue
		}
		if resolved, err := ResolveExec(svc.Exec[0]); err == nil {
			svc.Path = resolved
		}
		if err := resolveSandbox(svc.Sandbox); err != nil {
			return nil, nil, err
		}
		out[svc.Name] = svc
	}
	if len(out) == 0 {
		return nil, refused, fail.E("empty")
	}
	return out, refused, nil
}

// trustedOwner is the owner and mode rule for unit files and the unit
// directory: owned by root or by the supervisor's own uid, and not writable
// by group or other.
func trustedOwner(uid, perm uint32) bool {
	return (uid == 0 || uid == uint32(os.Geteuid())) && perm&0o022 == 0
}

func readUnit(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fail.E("failed")
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fail.E("symlink")
	}
	if !st.Mode().IsRegular() {
		return nil, fail.E("stray_file")
	}
	if st.Size() > maxFile {
		return nil, fail.E("file_size")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			return nil, fail.E("symlink")
		}
		return nil, fail.E("failed")
	}
	defer unix.Close(fd)
	var fst unix.Stat_t
	if err := unix.Fstat(fd, &fst); err != nil {
		return nil, fail.E("failed")
	}
	if uint32(fst.Mode)&unix.S_IFMT != unix.S_IFREG {
		return nil, fail.E("stray_file")
	}
	if !trustedOwner(fst.Uid, uint32(fst.Mode)&0o7777) {
		return nil, fail.E("unit_perm")
	}
	buf := make([]byte, maxFile+1)
	n := 0
	for n < len(buf) {
		r, err := unix.Read(fd, buf[n:])
		n += r
		if r == 0 {
			break
		}
		if err != nil {
			return nil, fail.E("failed")
		}
	}
	if n > maxFile {
		return nil, fail.E("file_size")
	}
	return buf[:n], nil
}

// Parse decodes one unit file. stem is the filename without .json and must
// equal the name field.
func Parse(raw []byte, stem string) (*Service, error) {
	obj, err := jsonobj.Decode(raw, unitKeys)
	if err != nil {
		return nil, err
	}
	if _, ok := obj["sash"]; ok {
		return parseSashUnit(obj, stem)
	}
	for _, key := range []string{"name", "exec", "type", "ready"} {
		if _, ok := obj[key]; !ok {
			return nil, fail.E("failed")
		}
	}
	var name string
	if err := jsonobj.Unmarshal(obj["name"], &name); err != nil {
		return nil, err
	}
	if !nameRE.MatchString(name) {
		return nil, fail.E("name_invalid")
	}
	if name != stem {
		return nil, fail.E("name_mismatch")
	}
	exec, err := argvField(obj["exec"])
	if err != nil {
		return nil, err
	}
	if len(exec) == 0 {
		return nil, fail.E("failed")
	}
	for _, arg := range exec {
		if len(arg) > maxArg || strings.ContainsRune(arg, 0) {
			return nil, fail.E("failed")
		}
	}
	if err := ExecPath(exec[0]); err != nil {
		return nil, err
	}
	var typ, ready string
	if err := jsonobj.Unmarshal(obj["type"], &typ); err != nil {
		return nil, err
	}
	if err := jsonobj.Unmarshal(obj["ready"], &ready); err != nil {
		return nil, err
	}
	restart := "no"
	if raw, ok := obj["restart"]; ok {
		if err := jsonobj.Unmarshal(raw, &restart); err != nil {
			return nil, fail.E("restart_invalid")
		}
		switch restart {
		case "no", "on-failure", "always":
		default:
			return nil, fail.E("restart_invalid")
		}
	}
	switch typ {
	case "simple":
		if ready != "exec" && ready != "notify" {
			return nil, fail.E("ready_invalid")
		}
	case "oneshot":
		if ready != "exit" {
			return nil, fail.E("ready_invalid")
		}
		if restart != "no" {
			return nil, fail.E("restart_invalid")
		}
	default:
		return nil, fail.E("type_invalid")
	}
	after, err := optEdges(obj, "after")
	if err != nil {
		return nil, err
	}
	needs, err := optEdges(obj, "needs")
	if err != nil {
		return nil, err
	}
	wants, err := optEdges(obj, "wants")
	if err != nil {
		return nil, err
	}
	timeout := DefaultTimeout
	if raw, ok := obj["timeout"]; ok {
		var text string
		if err := jsonobj.Unmarshal(raw, &text); err != nil {
			return nil, fail.E("timeout_range")
		}
		d, err := time.ParseDuration(text)
		if err != nil || d <= 0 || d > maxTimeout {
			return nil, fail.E("timeout_range")
		}
		timeout = d
	}
	boot := typ == "simple"
	if raw, ok := obj["boot"]; ok {
		var bit bool
		if err := jsonobj.Unmarshal(raw, &bit); err != nil {
			return nil, err
		}
		boot = bit
	}
	var sb *Sandbox
	if raw, ok := obj["sandbox"]; ok {
		sb, err = parseSandbox(raw)
		if err != nil {
			return nil, err
		}
	}
	execution, err := parseExecution(obj["execution"])
	if err != nil {
		return nil, err
	}
	// Threats: a sandboxed unit running as uid 0 regains every capability
	// at exec and passes the control socket's uid check, so the sandbox
	// would claim confinement it does not have.
	if sb != nil && (execution.UID == nil || *execution.UID == 0) {
		return nil, fail.E("sandbox_root")
	}
	limits, err := parseLimits(obj)
	if err != nil {
		return nil, err
	}
	return &Service{
		Name: name, Exec: exec, Type: typ, Restart: restart, Ready: ready,
		After: after, Needs: needs, Wants: wants, Timeout: timeout, Boot: boot,
		Sandbox: sb, Execution: execution, Limits: limits,
	}, nil
}

func optEdges(obj map[string]json.RawMessage, key string) ([]string, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, nil
	}
	return stringsField(raw, maxEdges, true)
}

// argvField preserves argument order and repetition; argv is not a set.
func argvField(raw json.RawMessage) ([]string, error) {
	var args []string
	if err := jsonobj.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	if len(args) > maxArgv {
		return nil, fail.E("failed")
	}
	return args, nil
}

func stringsField(raw json.RawMessage, limit int, edges bool) ([]string, error) {
	var xs []string
	if err := jsonobj.Unmarshal(raw, &xs); err != nil {
		return nil, err
	}
	if len(xs) > limit {
		return nil, fail.E("failed")
	}
	seen := make(map[string]struct{}, len(xs))
	for _, s := range xs {
		if edges && s == "" {
			return nil, fail.E("edge_empty")
		}
		if _, ok := seen[s]; ok {
			return nil, fail.E("duplicate_field")
		}
		seen[s] = struct{}{}
	}
	return xs, nil
}

func parseSandbox(raw json.RawMessage) (*Sandbox, error) {
	obj, err := jsonobj.Decode(raw, sandboxKeys)
	if err != nil {
		return nil, err
	}
	sb := &Sandbox{}
	present := false
	privs := true
	if raw, ok := obj["no_new_privs"]; ok {
		present = true
		if err := jsonobj.Unmarshal(raw, &privs); err != nil {
			return nil, err
		}
	}
	var ro, rw, caps []string
	if raw, ok := obj["read_only_paths"]; ok {
		ro, err = stringsField(raw, maxPaths, false)
		if err != nil {
			return nil, err
		}
	}
	if raw, ok := obj["read_write_paths"]; ok {
		rw, err = stringsField(raw, maxPaths, false)
		if err != nil {
			return nil, err
		}
	}
	if raw, ok := obj["caps"]; ok {
		caps, err = stringsField(raw, 64, false)
		if err != nil {
			return nil, err
		}
	}
	sb.ReadOnly = ro
	sb.ReadWrite = rw
	sb.Caps = caps
	if err := FinishSandbox(sb, present, privs); err != nil {
		return nil, err
	}
	return sb, nil
}

// FinishSandbox forces no_new_privs and checks paths and capability names.
// privsPresent is false when the key was omitted; an explicit false is refused.
func FinishSandbox(sb *Sandbox, privsPresent, privs bool) error {
	if sb == nil {
		return fail.E("failed")
	}
	if privsPresent && !privs {
		return fail.E("sandbox_privs")
	}
	sb.NoNewPrivs = true
	if len(sb.ReadOnly)+len(sb.ReadWrite) > maxPaths {
		return fail.E("failed")
	}
	seen := make(map[string]struct{})
	for _, p := range append(append([]string{}, sb.ReadOnly...), sb.ReadWrite...) {
		if err := sandboxPath(p); err != nil {
			return err
		}
		if _, ok := seen[p]; ok {
			return fail.E("sandbox_overlap")
		}
		seen[p] = struct{}{}
	}
	for _, name := range sb.Caps {
		if _, ok := capByName[name]; !ok {
			return fail.E("sandbox_cap")
		}
	}
	return nil
}

// resolveSandbox replaces each sandbox path with its target, resolved once
// at load with the executable's trusted walk, so /lib on a merged-/usr system
// becomes /usr/lib. A path that does not resolve, or whose walk passes an
// untrusted directory, is kept as written; the helper then refuses any link
// in it with sandbox_path, since it opens paths without following links.
// Two paths with one target in the same list become one; in both lists they
// are sandbox_overlap.
func resolveSandbox(sb *Sandbox) error {
	if sb == nil {
		return nil
	}
	ro, rw := resolvePaths(sb.ReadOnly), resolvePaths(sb.ReadWrite)
	inRW := make(map[string]struct{}, len(rw))
	for _, p := range rw {
		inRW[p] = struct{}{}
	}
	for _, p := range ro {
		if _, ok := inRW[p]; ok {
			return fail.E("sandbox_overlap")
		}
	}
	sb.ReadOnly, sb.ReadWrite = ro, rw
	return nil
}

func resolvePaths(in []string) []string {
	var out []string
	seen := make(map[string]struct{}, len(in))
	for _, p := range in {
		if r, err := ResolveTrusted(p); err == nil && sandboxPath(r) == nil {
			p = r
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func sandboxPath(p string) error {
	if p == "" || len(p) > maxPathLen || strings.ContainsRune(p, 0) || !path.IsAbs(p) || path.Clean(p) != p {
		return fail.E("sandbox_path")
	}
	return nil
}
