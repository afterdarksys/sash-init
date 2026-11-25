// SPDX-License-Identifier: GPL-3.0-or-later

package unit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/sash"
)

const sashUnit = `{"name":"app","sash":{"file":"/etc/sahinit/services/app.sash","grant":"/etc/sahinit/grants/app.grant"},"execution":{"uid":990,"gid":990},"sandbox":{}}`

func TestParseSashUnit(t *testing.T) {
	svc := mustParse(t, sashUnit, "app")
	if svc.Sash == nil || svc.Sash.File != "/etc/sahinit/services/app.sash" || svc.Exec != nil || svc.Type != "simple" || !svc.Boot || svc.Restart != "" {
		t.Fatalf("%+v", svc)
	}
	for _, c := range []struct{ edit, token string }{
		{`"exec":["/bin/sh"],`, "sash_unit_field"},
		{`"type":"simple",`, "sash_unit_field"},
		{`"ready":"exec",`, "sash_unit_field"},
		{`"essential":false,`, "sash_unit_field"},
		{`"watchdog":"1s",`, "sash_unit_field"},
		{`"timeout":"5s",`, "sash_unit_field"},
	} {
		raw := strings.Replace(sashUnit, `"name":"app",`, `"name":"app",`+c.edit, 1)
		if _, err := Parse([]byte(raw), "app"); fail.Token(err) != c.token {
			t.Errorf("%s: %v", c.edit, err)
		}
	}
	for _, c := range []struct{ from, to, token string }{
		{`"execution":{"uid":990,"gid":990}`, `"execution":{"uid":0,"gid":990}`, "sash_root"},
		{`"execution":{"uid":990,"gid":990}`, `"execution":{"uid":990,"gid":0}`, "sash_root"},
		{`,"execution":{"uid":990,"gid":990}`, ``, "sash_root"},
		{`,"sandbox":{}`, ``, "sash_sandbox"},
		{`"sandbox":{}`, `"sandbox":{"read_write_paths":["/sys/fs/cgroup"]}`, "sash_cgroup_trusted"},
		{`"sandbox":{}`, `"sandbox":{"caps":["sys_admin"]}`, "sash_cgroup_trusted"},
		{`"gid":990}`, `"gid":990,"environment":["A=b"]}`, "sash_unit_field"},
		{`/services/app.sash"`, `/services/../app.sash"`, "sash_file_perm"},
		{`"/etc/sahinit/grants/app.grant"`, `"grants/app.grant"`, "sash_grant_perm"},
		{`"grant":"/etc/sahinit/grants/app.grant"`, `"grant":"/g","extra":"x"`, "unknown_field"},
	} {
		raw := strings.Replace(sashUnit, c.from, c.to, 1)
		if raw == sashUnit {
			t.Fatalf("%s: edit did not apply", c.to)
		}
		if _, err := Parse([]byte(raw), "app"); fail.Token(err) != c.token {
			t.Errorf("%s: %v, want %s", c.to, err, c.token)
		}
	}
}

// writeSashUnit writes a unit naming file and grant under dir/etc.
func writeSashUnit(t *testing.T, units, file, grant string) {
	t.Helper()
	raw := strings.NewReplacer("/etc/sahinit/services/app.sash", file, "/etc/sahinit/grants/app.grant", grant).Replace(sashUnit)
	writeRaw(t, units, "app.json", raw)
}

func TestLoadSashFilePerms(t *testing.T) {
	root := t.TempDir()
	units := filepath.Join(root, "units")
	etc := filepath.Join(root, "etc")
	for _, d := range []string{units, etc} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file, grant := filepath.Join(etc, "app.sash"), filepath.Join(etc, "app.grant")
	if err := os.WriteFile(file, []byte("service {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grant, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSashUnit(t, units, file, grant)
	writeRaw(t, units, "b.json", `{"name":"b","exec":["/bin/sh"],"type":"simple","ready":"exec"}`)
	load := func() map[string]string {
		t.Helper()
		svcs, refused, err := Load(units)
		if err != nil {
			t.Fatal(err)
		}
		if svcs["b"] == nil {
			t.Fatal("the rest of the catalog did not load")
		}
		return refused
	}
	if r := load(); len(r) != 0 {
		t.Fatalf("refused %v", r)
	}
	for _, c := range []struct {
		path  string
		mode  os.FileMode
		token string
	}{
		{file, 0o664, "sash_file_perm"},
		{file, 0o646, "sash_file_perm"},
		{grant, 0o640, "sash_grant_perm"},
		{grant, 0o644, "sash_grant_perm"},
		{grant, 0o400, "sash_grant_perm"},
		{etc, 0o775, "sash_file_perm"},
	} {
		if err := os.Chmod(c.path, c.mode); err != nil {
			t.Fatal(err)
		}
		if r := load(); r["app.json"] != c.token {
			t.Errorf("%s %o: %v, want %s", filepath.Base(c.path), c.mode, r, c.token)
		}
		orig := os.FileMode(0o644)
		if c.path == grant {
			orig = 0o600
		} else if c.path == etc {
			orig = 0o755
		}
		if err := os.Chmod(c.path, orig); err != nil {
			t.Fatal(err)
		}
	}
	// A link to the file in a directory others can write is refused.
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(open, "app.sash")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	writeSashUnit(t, units, link, grant)
	if r := load(); r["app.json"] != "sash_file_perm" {
		t.Fatalf("link in an open directory: %v", r)
	}
	writeSashUnit(t, units, file, grant)
	if err := os.Remove(grant); err != nil {
		t.Fatal(err)
	}
	if r := load(); r["app.json"] != "sash_grant_perm" {
		t.Fatalf("missing grant: %v", r)
	}
}

func describeOf(t *testing.T, edit func(*sash.Description)) *sash.Description {
	t.Helper()
	d := &sash.Description{Name: "app", User: "app", Group: "app", Requires: []string{"db"}, After: []string{"db", "net"}, Wants: []string{},
		Run: []string{}, Entries: []string{"start", "stop"}, Restart: &sash.Restart{Policy: "on-failure"}}
	if edit != nil {
		edit(d)
	}
	return d
}

func TestApplyDescribe(t *testing.T) {
	ids := map[string]uint32{"app": 990, "other": 991}
	look := func(n string) (uint32, error) {
		if id, ok := ids[n]; ok {
			return id, nil
		}
		return 0, errors.New("no such name")
	}
	svc := mustParse(t, sashUnit, "app")
	if err := ApplyDescribe(svc, describeOf(t, nil), look, look); err != nil {
		t.Fatal(err)
	}
	if strings.Join(svc.Needs, ",") != "db" || strings.Join(svc.After, ",") != "db,net" || len(svc.Wants) != 0 || svc.Restart != "on-failure" || svc.Sash.Desc == nil {
		t.Fatalf("derived %+v", svc)
	}
	// A unit that names its own ordering and restart must agree.
	agree := strings.Replace(sashUnit, `"name":"app",`, `"name":"app","needs":["db"],"after":["net","db"],"restart":"on-failure",`, 1)
	if err := ApplyDescribe(mustParse(t, agree, "app"), describeOf(t, nil), look, look); err != nil {
		t.Fatalf("agreeing unit: %v", err)
	}
	for name, c := range map[string]struct {
		unit string
		edit func(*sash.Description)
		want string
	}{
		"name":               {sashUnit, func(d *sash.Description) { d.Name = "web" }, "sash_name_mismatch"},
		"user":               {sashUnit, func(d *sash.Description) { d.User = "other" }, "sash_identity_mismatch"},
		"group":              {sashUnit, func(d *sash.Description) { d.Group = "other" }, "sash_identity_mismatch"},
		"no user":            {sashUnit, func(d *sash.Description) { d.User = "" }, "sash_identity_mismatch"},
		"unknown":            {sashUnit, func(d *sash.Description) { d.User = "nobody-here" }, "sash_identity_mismatch"},
		"no entry":           {sashUnit, func(d *sash.Description) { d.Entries = []string{"stop"} }, "sash_describe"},
		"needs":              {strings.Replace(sashUnit, `"name":"app",`, `"name":"app","needs":["web"],`, 1), nil, "sash_order_mismatch"},
		"after":              {strings.Replace(sashUnit, `"name":"app",`, `"name":"app","after":["db"],`, 1), nil, "sash_order_mismatch"},
		"wants":              {strings.Replace(sashUnit, `"name":"app",`, `"name":"app","wants":["db"],`, 1), nil, "sash_order_mismatch"},
		"bad dep":            {sashUnit, func(d *sash.Description) { d.Requires = []string{"a_b"} }, "sash_order_mismatch"},
		"restart":            {strings.Replace(sashUnit, `"name":"app",`, `"name":"app","restart":"always",`, 1), nil, "sash_lifecycle_mismatch"},
		"ready limit":        {sashUnit, func(d *sash.Description) { d.Ready = &sash.Ready{Kind: "none", Timeout: 6 * time.Minute} }, "sash_lifecycle_limit"},
		"stop limit":         {sashUnit, func(d *sash.Description) { d.Stop = &sash.Stop{Signal: "TERM", Timeout: 6 * time.Minute} }, "sash_lifecycle_limit"},
		"delay limit":        {sashUnit, func(d *sash.Description) { d.Restart.Delay, d.Restart.Within = 6*time.Minute, 0 }, "sash_lifecycle_limit"},
		"burst limit":        {sashUnit, func(d *sash.Description) { d.Restart.Burst = MaxRestartBurst + 1 }, "sash_lifecycle_limit"},
		"window below delay": {sashUnit, func(d *sash.Description) { d.Restart.Delay, d.Restart.Within = 2*time.Second, time.Second }, "sash_lifecycle_limit"},
		"never vs no":        {strings.Replace(sashUnit, `"name":"app",`, `"name":"app","restart":"on-failure",`, 1), func(d *sash.Description) { d.Restart.Policy = "never" }, "sash_lifecycle_mismatch"},
	} {
		if err := ApplyDescribe(mustParse(t, c.unit, "app"), describeOf(t, c.edit), look, look); fail.Token(err) != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
	atLimit := mustParse(t, sashUnit, "app")
	if err := ApplyDescribe(atLimit, describeOf(t, func(d *sash.Description) {
		d.Ready = &sash.Ready{Kind: "none", Timeout: 5 * time.Minute}
		d.Stop = &sash.Stop{Signal: "TERM", Timeout: 5 * time.Minute}
		d.Restart.Burst, d.Restart.Delay = MaxRestartBurst, 5*time.Minute
	}), look, look); err != nil {
		t.Fatalf("at the limits: %v", err)
	}
	noRestart := mustParse(t, strings.Replace(sashUnit, `"name":"app",`, `"name":"app","restart":"no",`, 1), "app")
	if err := ApplyDescribe(noRestart, describeOf(t, func(d *sash.Description) { d.Restart = nil }), look, look); err != nil || noRestart.Restart != "no" {
		t.Fatalf("never is no: %v %s", err, noRestart.Restart)
	}
}

const bootOpsUnit = `{"name":"app","sash":{"file":"/etc/sahinit/services/app.sash","grant":"/etc/sahinit/grants/app.grant","boot_ops":true},"execution":{"uid":990,"gid":990},"sandbox":{}}`

func TestBootOpsUnit(t *testing.T) {
	svc := mustParse(t, bootOpsUnit, "app")
	if !svc.Sash.BootOps || !svc.Boot || !svc.Essential {
		t.Fatalf("%+v", svc.Sash)
	}
	if mustParse(t, sashUnit, "app").Sash.BootOps {
		t.Fatal("opt-in by default")
	}
	if _, err := Parse([]byte(strings.Replace(bootOpsUnit, `"name":"app",`, `"name":"app","boot":false,`, 1)), "app"); fail.Token(err) != "sash_boot_ops" {
		t.Fatalf("boot false: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(bootOpsUnit, `"boot_ops":true`, `"boot_ops":"yes"`, 1)), "app"); err == nil {
		t.Fatal("boot_ops not a bool")
	}
	look := func(string) (uint32, error) { return 990, nil }
	oneshot := func(d *sash.Description) { d.Restart, d.Entries = nil, []string{"start"} }
	if err := ApplyDescribe(mustParse(t, bootOpsUnit, "app"), describeOf(t, oneshot), look, look); err != nil {
		t.Fatalf("oneshot: %v", err)
	}
	for name, edit := range map[string]func(*sash.Description){
		"never":      func(d *sash.Description) { oneshot(d); d.Restart = &sash.Restart{Policy: "never"} },
		"ready none": func(d *sash.Description) { oneshot(d); d.Ready = &sash.Ready{Kind: "none"} },
	} {
		if err := ApplyDescribe(mustParse(t, bootOpsUnit, "app"), describeOf(t, edit), look, look); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, edit := range map[string]func(*sash.Description){
		"restart on-failure": func(d *sash.Description) { oneshot(d); d.Restart = &sash.Restart{Policy: "on-failure"} },
		"restart always":     func(d *sash.Description) { oneshot(d); d.Restart = &sash.Restart{Policy: "always"} },
		"no start":           func(d *sash.Description) { oneshot(d); d.Entries, d.Run = []string{}, []string{"x"} },
		"run as well":        func(d *sash.Description) { oneshot(d); d.Run = []string{"x"} },
		"run entry":          func(d *sash.Description) { oneshot(d); d.Entries = []string{"start", "run"} },
		"ready notify":       func(d *sash.Description) { oneshot(d); d.Ready = &sash.Ready{Kind: "notify"} },
		"ready tcp":          func(d *sash.Description) { oneshot(d); d.Ready = &sash.Ready{Kind: "tcp", Target: "127.0.0.1:1"} },
	} {
		if err := ApplyDescribe(mustParse(t, bootOpsUnit, "app"), describeOf(t, edit), look, look); fail.Token(err) != "sash_boot_ops" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
