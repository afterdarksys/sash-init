// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func capsUnit(t *testing.T, sandbox map[string]any) []byte {
	t.Helper()
	return unitJSON(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   sandbox,
	})
}

func capsToken(t *testing.T, sandbox map[string]any) string {
	t.Helper()
	_, err := Parse(capsUnit(t, sandbox), "a")
	return fail.Token(err)
}

// Only net_bind_service, setuid and setgid are grantable. Every other real
// capability is sandbox_cap_denied at load and anything else is sandbox_cap.
func TestCapAllowlist(t *testing.T) {
	if len(linuxCaps) != 41 {
		t.Fatalf("%d capability names, want 41 (bits 0 to 40)", len(linuxCaps))
	}
	for name := range capByName {
		if !linuxCaps[name] {
			t.Fatalf("allowlisted %s is not a capability", name)
		}
	}
	if len(capByName) != 3 || capByName["net_bind_service"] != 10 || capByName["setuid"] != 7 || capByName["setgid"] != 6 {
		t.Fatalf("allowlist %v", capByName)
	}
	for name := range linuxCaps {
		if _, ok := capByName[name]; ok {
			continue
		}
		if tok := capsToken(t, map[string]any{"caps": []string{name}}); tok != "sandbox_cap_denied" {
			t.Errorf("%s: %s", name, tok)
		}
		// A denied name next to a granted one is still refused.
		if tok := capsToken(t, map[string]any{"caps": []string{"net_bind_service", name}}); tok != "sandbox_cap_denied" {
			t.Errorf("net_bind_service+%s: %s", name, tok)
		}
	}
	for _, name := range []string{"", "CAP_NET_BIND_SERVICE", "Net_bind_service", "net_bind", "all", "cap_setuid", "setuid "} {
		if tok := capsToken(t, map[string]any{"caps": []string{name}}); tok != "sandbox_cap" {
			t.Errorf("%q: %s", name, tok)
		}
	}
	if tok := capsToken(t, map[string]any{"caps": []string{"net_bind_service", "net_bind_service"}}); tok != "duplicate_field" {
		t.Errorf("repeated: %s", tok)
	}
	if tok := capsToken(t, map[string]any{"caps": "net_bind_service"}); tok != "failed" {
		t.Errorf("string: %s", tok)
	}
	// The helper decodes the spec through FinishSandbox too.
	if err := FinishSandbox(&Sandbox{Caps: []string{"sys_admin"}}, false, true); fail.Token(err) != "sandbox_cap_denied" {
		t.Fatal(err)
	}
	if err := FinishSandbox(&Sandbox{Caps: []string{"setuid"}}, false, true); fail.Token(err) != "sandbox_ids" {
		t.Fatal(err)
	}
}

// setuid and setgid need their target lists, and the lists need the cap.
func TestCapTargetIDs(t *testing.T) {
	many := make([]int, MaxIDs+1)
	for i := range many {
		many[i] = 70000 + i
	}
	refused := []map[string]any{
		{"caps": []string{"setuid"}},
		{"caps": []string{"setgid"}},
		{"caps": []string{"setuid", "setgid"}, "setuid_to": []int{70001}},
		{"caps": []string{"setuid", "setgid"}, "setgid_to": []int{70001}},
		{"caps": []string{"net_bind_service"}, "setuid_to": []int{70001}},
		{"setgid_to": []int{70001}},
		{"caps": []string{"setuid"}, "setuid_to": []int{}},
		{"caps": []string{"setuid"}, "setuid_to": []int{0}},
		{"caps": []string{"setuid"}, "setuid_to": []int{70001, 0}},
		{"caps": []string{"setgid"}, "setgid_to": []int{0}},
		{"caps": []string{"setuid"}, "setuid_to": []int64{4294967295}},
		{"caps": []string{"setuid"}, "setuid_to": []int{70001, 70001}},
		{"caps": []string{"setuid"}, "setuid_to": many},
		{"caps": []string{"setgid"}, "setgid_to": many},
		// The supervisor's own ids are trusted principals.
		{"caps": []string{"setuid"}, "setuid_to": []int{70001, os.Geteuid()}},
		{"caps": []string{"setgid"}, "setgid_to": []int{os.Getegid()}},
	}
	for _, sb := range refused {
		if tok := capsToken(t, sb); tok != "sandbox_ids" {
			raw, _ := json.Marshal(sb)
			t.Errorf("%s: %s", raw, tok)
		}
	}
	for _, sb := range []map[string]any{
		{"caps": []string{"setuid"}, "setuid_to": "70001"},
		{"caps": []string{"setuid"}, "setuid_to": []int{-1}},
		{"caps": []string{"setuid"}, "setuid_to": []int64{4294967296}},
	} {
		if tok := capsToken(t, sb); tok != "failed" {
			raw, _ := json.Marshal(sb)
			t.Errorf("%s: %s", raw, tok)
		}
	}
	svc, err := Parse(capsUnit(t, map[string]any{"caps": []string{"setuid", "setgid", "net_bind_service"}, "setuid_to": many[:MaxIDs], "setgid_to": []int{70001}}), "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Sandbox.SetuidTo) != MaxIDs || len(svc.Sandbox.SetgidTo) != 1 || svc.Sandbox.SetgidTo[0] != 70001 {
		t.Fatalf("%+v", svc.Sandbox)
	}
	svc, err = Parse(capsUnit(t, map[string]any{"caps": []string{"net_bind_service"}}), "a")
	if err != nil || svc.Sandbox.SetuidTo != nil || svc.Sandbox.SetgidTo != nil {
		t.Fatalf("%v %+v", err, svc)
	}
}

// The sinetd unit as shipped in the sahinetd repository loads; with the
// three caps it also needs the target lists.
func TestSinetdUnitLoads(t *testing.T) {
	raw, err := os.ReadFile("testdata/sinetd.json")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := Parse(raw, "sinetd")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Sandbox == nil || len(svc.Sandbox.Caps) != 1 || svc.Sandbox.Caps[0] != "net_bind_service" || *svc.Execution.UID != 65532 {
		t.Fatalf("%+v", svc.Sandbox)
	}
	three := strings.Replace(string(raw), `"caps": ["net_bind_service"]`, `"caps": ["net_bind_service", "setuid", "setgid"]`, 1)
	if three == string(raw) {
		t.Fatal("edit did not apply")
	}
	if _, err := Parse([]byte(three), "sinetd"); fail.Token(err) != "sandbox_ids" {
		t.Fatalf("three caps without targets: %v", err)
	}
	listed := strings.Replace(three, `"setgid"]`, `"setgid"], "setuid_to": [70001, 70002], "setgid_to": [70001, 70002]`, 1)
	svc, err = Parse([]byte(listed), "sinetd")
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Sandbox.Caps) != 3 || len(svc.Sandbox.SetuidTo) != 2 {
		t.Fatalf("%+v", svc.Sandbox)
	}
}
