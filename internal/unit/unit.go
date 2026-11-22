// Package unit loads the static service catalog.
//
// Threats: a unit file is untrusted input. Unknown fields, duplicate keys,
// relative exec paths, symlink unit files, and oversized files are rejected.
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
	"sandbox": {},
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
	Name    string
	Exec    []string
	Type    string
	Restart string
	Ready   string
	After   []string
	Needs   []string
	Wants   []string
	Timeout time.Duration
	Boot    bool
	Sandbox *Sandbox
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

// ExecFile checks the path at start time. A symlink is not a regular file.
func ExecFile(p string) error {
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
		return fail.E("exec_not_file")
	}
	return nil
}

// Load reads every unit in dir. The directory itself must not be a symlink.
func Load(dir string) (map[string]*Service, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fail.E("failed")
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fail.E("symlink")
	}
	if !fi.IsDir() {
		return nil, fail.E("failed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fail.E("failed")
	}
	if len(entries) == 0 {
		return nil, fail.E("empty")
	}
	var names []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, fail.E("symlink")
		}
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			return nil, fail.E("stray_file")
		}
		names = append(names, name)
	}
	if len(names) > maxUnits {
		return nil, fail.E("too_many")
	}
	out := make(map[string]*Service, len(names))
	for _, name := range names {
		body, err := readUnit(dir + "/" + name)
		if err != nil {
			return nil, err
		}
		svc, err := Parse(body, strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		if _, exists := out[svc.Name]; exists {
			return nil, fail.E("duplicate_field")
		}
		out[svc.Name] = svc
	}
	return out, nil
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
	exec, err := stringsField(obj["exec"], maxArgv, false)
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
	return &Service{
		Name: name, Exec: exec, Type: typ, Restart: restart, Ready: ready,
		After: after, Needs: needs, Wants: wants, Timeout: timeout, Boot: boot,
		Sandbox: sb,
	}, nil
}

func optEdges(obj map[string]json.RawMessage, key string) ([]string, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, nil
	}
	return stringsField(raw, maxEdges, true)
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

func sandboxPath(p string) error {
	if p == "" || len(p) > maxPathLen || strings.ContainsRune(p, 0) || !path.IsAbs(p) || path.Clean(p) != p {
		return fail.E("sandbox_path")
	}
	return nil
}
