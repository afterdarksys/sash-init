// SPDX-License-Identifier: GPL-3.0-or-later

package unit

// A sash service unit (docs/design/sash-services-1.md, "Unit"):
//
//	{"name": "app", "sash": {"file": "/etc/sahinit/services/app.sash",
//	 "grant": "/etc/sahinit/grants/app.grant"},
//	 "execution": {"uid": 990, "gid": 990}, "sandbox": {...}}
//
// Threats: sash runs a service script as the unit's uid, and the grant is
// the authority for every verb it asks sahinit to perform. A service file
// someone else can write would let them choose what runs; a grant someone
// else can read or replace would let them see or swap it. Both are checked
// with the executable's trusted walk: every directory up to / and the file
// itself owned by root (or the supervisor's uid) and not group- or
// other-writable (sash_file_perm), and the grant mode exactly 0600
// (sash_grant_perm). sash itself never runs as root (sash_root, decision
// B2), always sandboxed (sash_sandbox) and never cgroup_trusted
// (sash_cgroup_trusted), so the cgroup holds everything it spawns. The
// unit's ordering, readiness, stop and restart come from sash --describe;
// a value the unit also sets must agree (ApplyDescribe).

import (
	"encoding/json"
	"os"
	"syscall"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/jsonobj"
	"github.com/afterdarksys/sahinit/internal/sash"
)

// Sash is a sash unit's files and, after load, what describe said.
type Sash struct {
	File  string
	Grant string
	// Desc is set by ApplyDescribe at load. A sash unit without it does
	// not start.
	Desc *sash.Description
}

var sashUnitKeys = map[string]struct{}{"file": {}, "grant": {}}

// sashOnly are the unit keys a sash unit refuses: the service block owns
// what they would say. essential is refused too: a sash boot unit is always
// essential, and a silently ignored false would read as an opt-out.
var sashOnly = []string{"exec", "type", "ready", "timeout", "essential", "restart_delay", "restart_max_delay", "watchdog"}

func parseSashUnit(obj map[string]json.RawMessage, stem string) (*Service, error) {
	for _, k := range sashOnly {
		if _, ok := obj[k]; ok {
			return nil, fail.E("sash_unit_field")
		}
	}
	var name string
	raw, ok := obj["name"]
	if !ok {
		return nil, fail.E("failed")
	}
	if err := jsonobj.Unmarshal(raw, &name); err != nil {
		return nil, err
	}
	if !nameRE.MatchString(name) {
		return nil, fail.E("name_invalid")
	}
	if name != stem {
		return nil, fail.E("name_mismatch")
	}
	files, err := jsonobj.Decode(obj["sash"], sashUnitKeys)
	if err != nil {
		return nil, err
	}
	sh := &Sash{}
	for key, dest := range map[string]*string{"file": &sh.File, "grant": &sh.Grant} {
		raw, ok := files[key]
		if !ok {
			return nil, fail.E("failed")
		}
		if err := jsonobj.Unmarshal(raw, dest); err != nil {
			return nil, err
		}
		if err := ExecPath(*dest); err != nil {
			return nil, fail.E("sash_" + key + "_perm")
		}
	}
	restart := ""
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
	boot := true
	if raw, ok := obj["boot"]; ok {
		if err := jsonobj.Unmarshal(raw, &boot); err != nil {
			return nil, err
		}
	}
	raw, ok = obj["sandbox"]
	if !ok {
		return nil, fail.E("sash_sandbox")
	}
	sb, err := parseSandbox(raw)
	if err != nil {
		return nil, err
	}
	// Threats: caps given to the sash process itself were never reviewed
	// against the grant model, whose spawn caps are refused.
	if len(sb.Caps) > 0 {
		return nil, fail.E("sash_caps")
	}
	execution, err := parseExecution(obj["execution"])
	if err != nil {
		return nil, err
	}
	if execution.UID == nil || *execution.UID == 0 || *execution.GID == 0 {
		return nil, fail.E("sash_root")
	}
	if len(execution.Groups) > 0 || execution.Directory != "" || len(execution.Environment) > 0 {
		return nil, fail.E("sash_unit_field")
	}
	limits, err := parseLimits(obj)
	if err != nil {
		return nil, err
	}
	svc := &Service{
		Name: name, Type: "simple", Restart: restart, After: after, Needs: needs, Wants: wants,
		Timeout: DefaultTimeout, Boot: boot, Essential: boot, Sandbox: sb, Execution: execution, Limits: limits, Sash: sh,
	}
	if CgroupTrusted(svc) {
		return nil, fail.E("sash_cgroup_trusted")
	}
	return svc, nil
}

// CheckSashFiles is checkSashFiles, for the check before each start.
func CheckSashFiles(svc *Service) string {
	if svc == nil || svc.Sash == nil {
		return "failed"
	}
	return checkSashFiles(svc)
}

// checkSashFiles is "" when the service file and grant pass the trusted
// walk and their owner and mode rules, else the refusal token.
func checkSashFiles(svc *Service) string {
	if !trustedFile(svc.Sash.File, false) {
		return "sash_file_perm"
	}
	if !trustedFile(svc.Sash.Grant, true) {
		return "sash_grant_perm"
	}
	return ""
}

// trustedFile resolves p with the trusted walk and checks the regular file
// it names: owned by root or the supervisor's uid, not group- or
// other-writable, and for a grant exactly mode 0600.
func trustedFile(p string, grant bool) bool {
	r, err := ResolveTrusted(p)
	if err != nil {
		return false
	}
	st, err := os.Lstat(r)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !trustedOwner(sys.Uid, uint32(st.Mode().Perm())) {
		return false
	}
	if grant && st.Mode()&os.ModePerm != 0o600 {
		return false
	}
	return st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

// ApplyDescribe derives a sash unit's identity check, ordering and restart
// policy from sash --describe, or checks the values the unit already set
// against it. lookup resolves a user or group name to its id.
func ApplyDescribe(svc *Service, d *sash.Description, lookupUser, lookupGroup func(string) (uint32, error)) error {
	if svc == nil || svc.Sash == nil || d == nil {
		return fail.E("failed")
	}
	if d.Name != svc.Name {
		return fail.E("sash_name_mismatch")
	}
	if d.User == "" || d.Group == "" {
		return fail.E("sash_identity_mismatch")
	}
	uid, uerr := lookupUser(d.User)
	gid, gerr := lookupGroup(d.Group)
	if uerr != nil || gerr != nil || uid != *svc.Execution.UID || gid != *svc.Execution.GID {
		return fail.E("sash_identity_mismatch")
	}
	if d.Entry() == "" {
		return fail.E("sash_describe")
	}
	for _, e := range []struct {
		unit *[]string
		desc []string
	}{{&svc.Needs, d.Requires}, {&svc.After, d.After}, {&svc.Wants, d.Wants}} {
		for _, n := range e.desc {
			if !NameOK(n) {
				return fail.E("sash_order_mismatch")
			}
		}
		if *e.unit == nil {
			*e.unit = append([]string{}, e.desc...)
			continue
		}
		if !sameSet(*e.unit, e.desc) {
			return fail.E("sash_order_mismatch")
		}
	}
	if err := lifecycleLimits(d); err != nil {
		return err
	}
	policy := "no"
	if d.Restart != nil && d.Restart.Policy != "never" {
		policy = d.Restart.Policy
	}
	if svc.Restart != "" && svc.Restart != policy {
		return fail.E("sash_lifecycle_mismatch")
	}
	svc.Restart = policy
	svc.Sash.Desc = d
	return nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	in := make(map[string]bool, len(a))
	for _, s := range a {
		in[s] = true
	}
	for _, s := range b {
		if !in[s] {
			return false
		}
	}
	return true
}

// MaxRestartBurst is the most restarts a sash service block may allow in
// its window: sahinit's own default burst.
const MaxRestartBurst = 5

// lifecycleLimits refuses a service block whose ready or stop timeout or
// restart delay passes sahinit's unit timeout limit, whose restart burst
// passes MaxRestartBurst, or whose restart window is shorter than its delay
// (sash_lifecycle_limit). Nothing is clamped: the
// script's author sees the refusal.
//
// Threats: describe output is the script's; without these bounds a service
// file alone could make sahinit hold a start, a stop or a restart for a day.
func lifecycleLimits(d *sash.Description) error {
	bad := fail.E("sash_lifecycle_limit")
	if d.Ready != nil && d.Ready.Timeout > maxTimeout {
		return bad
	}
	if d.Stop != nil && d.Stop.Timeout > maxTimeout {
		return bad
	}
	if r := d.Restart; r != nil && (r.Delay > maxTimeout || r.Burst > MaxRestartBurst) {
		return bad
	}
	// A window shorter than the delay could never hold a burst: the
	// window alone would let the unit restart forever.
	if r := d.Restart; r != nil && r.Within > 0 && r.Within < r.Delay {
		return bad
	}
	return nil
}
