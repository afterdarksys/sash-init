package unit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
)

func TestParseDefaults(t *testing.T) {
	simple := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`, "a")
	if !simple.Boot || simple.Timeout != DefaultTimeout || simple.Restart != "no" || simple.Sandbox != nil {
		t.Fatalf("%+v", simple)
	}
	oneshot := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"oneshot","ready":"exit"}`, "a")
	if oneshot.Boot || oneshot.Ready != "exit" {
		t.Fatalf("%+v", oneshot)
	}
	boxed := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","execution":{"uid":65534,"gid":65534},"sandbox":{}}`, "a")
	if boxed.Sandbox == nil || !boxed.Sandbox.NoNewPrivs {
		t.Fatalf("%+v", boxed.Sandbox)
	}
	capped := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","execution":{"uid":65534,"gid":65534},"sandbox":{"caps":["kill"]}}`, "a")
	if len(capped.Sandbox.Caps) != 1 || capped.Sandbox.Caps[0] != "kill" || !capped.Sandbox.NoNewPrivs {
		t.Fatalf("%+v", capped.Sandbox)
	}
	timed := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":"5m"}`, "a")
	if timed.Timeout != 5*time.Minute {
		t.Fatal(timed.Timeout)
	}
	missing := mustParse(t, `{"name":"a","exec":["/tmp/sahinit-not-a-file"],"type":"simple","ready":"exec"}`, "a")
	if missing.Exec[0] != "/tmp/sahinit-not-a-file" {
		t.Fatal(missing.Exec)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		raw   string
		stem  string
		token string
	}{
		{`{"name":"a","exec":["/bin/sh"],"type":"oneshot","ready":"exit","restart":"always"}`, "a", "restart_invalid"},
		{`{"name":"a","exec":["/bin/sh"],"type":"oneshot","ready":"exec"}`, "a", "ready_invalid"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exit"}`, "a", "ready_invalid"},
		{`{"name":"a","exec":["/bin/sh"],"type":"fork","ready":"exec"}`, "a", "type_invalid"},
		{`{"name":"A","exec":["/bin/sh"],"type":"simple","ready":"exec"}`, "A", "name_invalid"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`, "b", "name_mismatch"},
		{`{"name":"a","exec":["sh"],"type":"simple","ready":"exec"}`, "a", "exec_relative"},
		{`{"name":"a","exec":["/tmp/../bin/sh"],"type":"simple","ready":"exec"}`, "a", "exec_relative"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","needs":[""]}`, "a", "edge_empty"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","needs":["b","b"]}`, "a", "duplicate_field"},
		{`{"name":"a","name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`, "a", "duplicate_field"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","nope":1}`, "a", "unknown_field"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":5}`, "a", "timeout_range"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":"0s"}`, "a", "timeout_range"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":"-1s"}`, "a", "timeout_range"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":"5m1s"}`, "a", "timeout_range"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":"nope"}`, "a", "timeout_range"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{"no_new_privs":false}}`, "a", "sandbox_privs"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{"caps":["net_raw"]}}`, "a", "sandbox_cap"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{"read_only_paths":["tmp"]}}`, "a", "sandbox_path"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{"read_only_paths":["/tmp/a"],"read_write_paths":["/tmp/a"]}}`, "a", "sandbox_overlap"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{"read_only_paths":["/tmp/a","/tmp/a"]}}`, "a", "duplicate_field"},
		{`{"name":"a","exec":[],"type":"simple","ready":"exec"}`, "a", "failed"},
		{`{"exec":["/bin/sh"],"type":"simple","ready":"exec"}`, "a", "failed"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","boot":null}`, "a", "failed"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","restart":null}`, "a", "restart_invalid"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","timeout":null}`, "a", "timeout_range"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","wants":[""]}`, "a", "edge_empty"},
		{`{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","after":[""]}`, "a", "edge_empty"},
		{`{"name":"1a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`, "1a", "name_invalid"},
		{`{"name":"` + strings.Repeat("a", 64) + `","exec":["/bin/sh"],"type":"simple","ready":"exec"}`, strings.Repeat("a", 64), "name_invalid"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.raw), tc.stem)
		if !errors.Is(err, fail.E(tc.token)) {
			t.Fatalf("%s: got %v", tc.raw, err)
		}
	}
}

func TestFinishSandboxNil(t *testing.T) {
	if err := FinishSandbox(nil, false, true); !errors.Is(err, fail.E("failed")) {
		t.Fatal(err)
	}
}

func TestLoadEmpty(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Load(dir)
	if !errors.Is(err, fail.E("empty")) {
		t.Fatal(err)
	}
}

func TestLoadStray(t *testing.T) {
	hidden := t.TempDir()
	writeRaw(t, hidden, ".a.json", `{}`)
	wantLoad(t, hidden, "stray_file")

	nested := t.TempDir()
	if err := os.Mkdir(nested+"/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	wantLoad(t, nested, "stray_file")

	text := t.TempDir()
	writeRaw(t, text, "a.txt", "x")
	wantLoad(t, text, "stray_file")
}

func TestLoadStrayBeforeTooMany(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 257; i++ {
		writeRaw(t, dir, fmt.Sprintf("u%03d.json", i), "")
	}
	writeRaw(t, dir, "note.txt", "x")
	wantLoad(t, dir, "stray_file")
}

func TestLoadTooMany(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 257; i++ {
		writeRaw(t, dir, fmt.Sprintf("u%03d.json", i), "")
	}
	wantLoad(t, dir, "too_many")
}

func TestLoadNameMismatch(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "b.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	wantLoad(t, dir, "name_mismatch")
}

func TestLoadSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/etc/passwd", dir+"/a.json"); err != nil {
		t.Fatal(err)
	}
	wantLoad(t, dir, "symlink")

	parent := t.TempDir()
	real := parent + "/real"
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := parent + "/link"
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	wantLoad(t, link, "symlink")
}

func TestLoadFileSize(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", string(bytes.Repeat([]byte("x"), 64*1024+1)))
	wantLoad(t, dir, "file_size")
}

func mustParse(t *testing.T, raw, stem string) *Service {
	t.Helper()
	svc, err := Parse([]byte(raw), stem)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func wantLoad(t *testing.T, dir, token string) {
	t.Helper()
	_, _, err := Load(dir)
	if !errors.Is(err, fail.E(token)) {
		t.Fatalf("%s: got %v", token, err)
	}
}

func writeRaw(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(dir+"/"+name, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadNotDirectory(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/unit.json"
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantLoad(t, file, "failed")
	wantLoad(t, dir+"/missing", "failed")
}

func TestExecFileAndPath(t *testing.T) {
	if err := ExecFile("/bin/sh"); err != nil {
		t.Fatal(err)
	}
	if err := ExecFile(t.TempDir() + "/missing"); !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ExecFile(dir); !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatal(err)
	}
	plain := dir + "/plain"
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ExecFile(plain); !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatal(err)
	}
	link := dir + "/link"
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	// A link is followed once; the target is what is checked and returned.
	want, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveExec(link); err != nil || got != want {
		t.Fatalf("%q %v", got, err)
	}
	if err := CheckExec(link); !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatal(err)
	}
	exe := dir + "/exe"
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ExecFile(exe); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", "sh", "/tmp/../bin/sh", "a\x00b"} {
		if err := ExecPath(p); !errors.Is(err, fail.E("exec_relative")) {
			t.Fatalf("%q %v", p, err)
		}
	}
	if err := ExecPath("/bin/sh"); err != nil {
		t.Fatal(err)
	}
}

func TestNameAndCap(t *testing.T) {
	for _, name := range []string{"", "1a", "A", "-a", strings.Repeat("a", 64)} {
		if NameOK(name) {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, name := range []string{"a", "a-b", "a-", strings.Repeat("a", 63)} {
		if !NameOK(name) {
			t.Fatalf("rejected %q", name)
		}
	}
	caps := map[string]uint32{
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
	for name, id := range caps {
		got, ok := LookupCap(name)
		if !ok || got != id {
			t.Fatalf("%s %d %v", name, got, ok)
		}
	}
	if _, ok := LookupCap("net_raw"); ok {
		t.Fatal("net_raw")
	}
}

func TestParseAccepted(t *testing.T) {
	simple := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","boot":false}`, "a")
	if simple.Boot {
		t.Fatal(simple.Boot)
	}
	oneshot := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"oneshot","ready":"exit","boot":true}`, "a")
	if !oneshot.Boot || oneshot.Type != "oneshot" {
		t.Fatalf("%+v", oneshot)
	}
	notify := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"notify"}`, "a")
	if notify.Ready != "notify" {
		t.Fatal(notify.Ready)
	}
	always := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","restart":"always"}`, "a")
	if always.Restart != "always" {
		t.Fatal(always.Restart)
	}
	onFail := mustParse(t, `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","restart":"on-failure"}`, "a")
	if onFail.Restart != "on-failure" {
		t.Fatal(onFail.Restart)
	}
}

func TestParseArgvAndPaths(t *testing.T) {
	okArg := strings.Repeat("b", 256)
	raw := unitJSON(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh", okArg}, "type": "simple", "ready": "exec",
	})
	svc := mustParse(t, string(raw), "a")
	if svc.Exec[1] != okArg {
		t.Fatal(len(svc.Exec[1]))
	}
	wantParse(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh", strings.Repeat("b", 257)}, "type": "simple", "ready": "exec",
	}, "failed")
	exec32 := make([]string, 32)
	exec32[0] = "/bin/sh"
	for i := 1; i < len(exec32); i++ {
		exec32[i] = fmt.Sprintf("x%d", i)
	}
	raw = unitJSON(t, map[string]any{
		"name": "a", "exec": exec32, "type": "simple", "ready": "exec",
	})
	if got := mustParse(t, string(raw), "a"); len(got.Exec) != 32 {
		t.Fatal(len(got.Exec))
	}
	exec33 := append(append([]string{}, exec32...), "y")
	wantParse(t, map[string]any{
		"name": "a", "exec": exec33, "type": "simple", "ready": "exec",
	}, "failed")
	wantParse(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh", "a\x00b"}, "type": "simple", "ready": "exec",
	}, "failed")

	caps := []string{"chown", "dac_override", "fowner", "kill", "setgid", "setuid", "net_bind_service", "net_admin", "sys_admin"}
	raw = unitJSON(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"caps": caps},
	})
	boxed := mustParse(t, string(raw), "a")
	if boxed.Sandbox == nil || !boxed.Sandbox.NoNewPrivs || len(boxed.Sandbox.Caps) != len(caps) {
		t.Fatalf("%+v", boxed.Sandbox)
	}

	ro := make([]string, 32)
	rw := make([]string, 32)
	for i := 0; i < 32; i++ {
		ro[i] = fmt.Sprintf("/ro/%d", i)
		rw[i] = fmt.Sprintf("/rw/%d", i)
	}
	raw = unitJSON(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": ro, "read_write_paths": rw},
	})
	both := mustParse(t, string(raw), "a")
	if len(both.Sandbox.ReadOnly) != 32 || len(both.Sandbox.ReadWrite) != 32 {
		t.Fatalf("%d %d", len(both.Sandbox.ReadOnly), len(both.Sandbox.ReadWrite))
	}
	ro33 := append(append([]string{}, ro...), "/ro/extra")
	wantParse(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": ro33, "read_write_paths": rw},
	}, "failed")
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("/many/%d", i)
	}
	wantParse(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": tooMany},
	}, "failed")
	okPath := "/" + strings.Repeat("a", 4095)
	raw = unitJSON(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": []string{okPath}},
	})
	long := mustParse(t, string(raw), "a")
	if long.Sandbox.ReadOnly[0] != okPath {
		t.Fatal(len(long.Sandbox.ReadOnly[0]))
	}
	wantParse(t, map[string]any{
		"name": "a", "exec": []string{"/bin/sh"}, "type": "simple", "ready": "exec",
		"execution": map[string]any{"uid": 65534, "gid": 65534},
		"sandbox":   map[string]any{"read_only_paths": []string{"/" + strings.Repeat("a", 4096)}},
	}, "sandbox_path")
}

func unitJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	buf, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func wantParse(t *testing.T, fields map[string]any, token string) {
	t.Helper()
	_, err := Parse(unitJSON(t, fields), "a")
	if !errors.Is(err, fail.E(token)) {
		t.Fatalf("%s: %v", token, err)
	}
}

func TestRepeatedExecArguments(t *testing.T) {
	svc, err := Parse([]byte(`{"name":"repeat","exec":["/usr/bin/printf","%s","%s"],"type":"simple","ready":"exec"}`), "repeat")
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Exec) != 3 || svc.Exec[1] != svc.Exec[2] {
		t.Fatalf("argv changed: %q", svc.Exec)
	}
}

func TestLoadUnitPermRefusesOnlyThatFile(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	writeRaw(t, dir, "b.json", `{"name":"b","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		if err := os.Chmod(dir+"/b.json", mode); err != nil {
			t.Fatal(err)
		}
		svcs, refused, err := Load(dir)
		if err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
		if _, ok := svcs["a"]; !ok || len(svcs) != 1 {
			t.Fatalf("mode %o: loaded %v", mode, svcs)
		}
		if len(refused) != 1 || refused["b.json"] != "unit_perm" {
			t.Fatalf("mode %o: refused %v", mode, refused)
		}
	}
	if err := os.Chmod(dir+"/b.json", 0o644); err != nil {
		t.Fatal(err)
	}
	svcs, refused, err := Load(dir)
	if err != nil || len(svcs) != 2 || len(refused) != 0 {
		t.Fatalf("%v %v %v", svcs, refused, err)
	}
}

func TestLoadUnitPermAllRefusedIsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	if err := os.Chmod(dir+"/a.json", 0o666); err != nil {
		t.Fatal(err)
	}
	svcs, refused, err := Load(dir)
	if svcs != nil || refused["a.json"] != "unit_perm" || !errors.Is(err, fail.E("empty")) {
		t.Fatalf("%v %v %v", svcs, refused, err)
	}
}

func TestLoadUnitPermDirectory(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		wantLoad(t, dir, "unit_perm")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
}

func TestLoadUnitPermOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown")
	}
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	writeRaw(t, dir, "b.json", `{"name":"b","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	if err := os.Chown(dir+"/b.json", 65534, 65534); err != nil {
		t.Fatal(err)
	}
	svcs, refused, err := Load(dir)
	if err != nil || len(svcs) != 1 || svcs["a"] == nil || refused["b.json"] != "unit_perm" {
		t.Fatalf("%v %v %v", svcs, refused, err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	wantLoad(t, dir, "unit_perm")
}

func TestCheckExecOwnerAndMode(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckExec(base + "/../" + filepath.Base(base)); !errors.Is(err, fail.E("exec_relative")) {
		t.Fatal(err)
	}
	dir := base + "/bin"
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := dir + "/exe"
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckExec(exe); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		if err := os.Chmod(exe, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckExec(exe); !errors.Is(err, fail.E("exec_perm")) {
			t.Fatalf("file %o: %v", mode, err)
		}
		if _, err := ResolveExec(exe); !errors.Is(err, fail.E("exec_perm")) {
			t.Fatalf("file %o: %v", mode, err)
		}
	}
	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckExec(exe); !errors.Is(err, fail.E("exec_perm")) {
			t.Fatalf("dir %o: %v", mode, err)
		}
	}
	// A sticky directory, like /tmp, cannot have entries swapped by others.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := CheckExec(exe); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A writable directory above the link target is refused too.
	link := base + "/link"
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveExec(link); !errors.Is(err, fail.E("exec_perm")) {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveExec(link); err != nil || got != exe {
		t.Fatalf("%q %v", got, err)
	}
}

func TestCheckExecOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exe := base + "/exe"
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(exe, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := CheckExec(exe); !errors.Is(err, fail.E("exec_perm")) {
		t.Fatal(err)
	}
	if err := os.Chown(exe, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(base, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := CheckExec(exe); !errors.Is(err, fail.E("exec_perm")) {
		t.Fatal(err)
	}
}

func TestLoadResolvesExec(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh","-c","true"],"type":"simple","ready":"exec"}`)
	writeRaw(t, dir, "b.json", `{"name":"b","exec":["/tmp/sahinit-not-a-file"],"type":"simple","ready":"exec"}`)
	svcs, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if svcs["a"].Path != want || svcs["a"].Exec[0] != "/bin/sh" {
		t.Fatalf("%q %q", svcs["a"].Path, svcs["a"].Exec)
	}
	if svcs["b"].Path != "" {
		t.Fatalf("%q", svcs["b"].Path)
	}
}

func TestLoadResolvesSandboxPaths(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := base + "/real"
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, base+"/link"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","execution":{"uid":65534,"gid":65534},"sandbox":{"read_only_paths":["`+base+`/link","`+real+`","`+base+`/missing"]}}`)
	svcs, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := svcs["a"].Sandbox.ReadOnly
	if len(got) != 2 || got[0] != real || got[1] != base+"/missing" {
		t.Fatalf("%q", got)
	}
	writeRaw(t, dir, "a.json", `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","execution":{"uid":65534,"gid":65534},"sandbox":{"read_only_paths":["`+base+`/link"],"read_write_paths":["`+real+`"]}}`)
	wantLoad(t, dir, "sandbox_overlap")
}

func TestParseSandboxRoot(t *testing.T) {
	for _, exe := range []string{``, `,"execution":{"uid":0,"gid":0}`, `,"execution":{"uid":0,"gid":65534}`} {
		raw := `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{}` + exe + `}`
		if _, err := Parse([]byte(raw), "a"); !errors.Is(err, fail.E("sandbox_root")) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	raw := `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","sandbox":{},"execution":{"uid":1,"gid":0}}`
	if _, err := Parse([]byte(raw), "a"); err != nil {
		t.Fatal(err)
	}
	// Without a sandbox, root is still allowed.
	raw = `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec","execution":{"uid":0,"gid":0}}`
	if _, err := Parse([]byte(raw), "a"); err != nil {
		t.Fatal(err)
	}
}
