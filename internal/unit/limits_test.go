package unit

import (
	"os"
	"reflect"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

const limitsBase = `{"name":"a","exec":["/bin/sh"],"type":"simple","ready":"exec"`

func TestParseLimits(t *testing.T) {
	none := mustParse(t, limitsBase+`}`, "a")
	if none.Limits.Any() || none.Limits.Controllers() != nil || none.Limits.CPUMax() != "" {
		t.Fatalf("%+v", none.Limits)
	}
	all := mustParse(t, limitsBase+`,"memory_max":"64M","pids_max":32,"cpu_max":"50000 100000"}`, "a")
	want := Limits{MemoryMax: 64 << 20, PidsMax: 32, CPUQuota: 50000, CPUPeriod: 100000}
	if all.Limits != want || !all.Limits.Any() || all.Limits.CPUMax() != "50000 100000" {
		t.Fatalf("%+v", all.Limits)
	}
	if got := all.Limits.Controllers(); !reflect.DeepEqual(got, []string{"cpu", "memory", "pids"}) {
		t.Fatal(got)
	}
	for raw, bytes := range map[string]uint64{`"1048576"`: 1 << 20, `"1024K"`: 1 << 20, `"2G"`: 2 << 30} {
		svc := mustParse(t, limitsBase+`,"memory_max":`+raw+`}`, "a")
		if svc.Limits.MemoryMax != bytes {
			t.Fatalf("%s: %d", raw, svc.Limits.MemoryMax)
		}
	}
}

func TestParseLimitsRejects(t *testing.T) {
	for _, field := range []string{
		`"memory_max":64`, `"memory_max":"64m"`, `"memory_max":"0"`, `"memory_max":"1023K"`,
		`"memory_max":"max"`, `"memory_max":"-1M"`, `"memory_max":"9999999999999999G"`, `"memory_max":""`,
		`"pids_max":0`, `"pids_max":-1`, `"pids_max":4194305`, `"pids_max":"8"`, `"pids_max":1.5`, `"pids_max":null`,
		`"cpu_max":"50000"`, `"cpu_max":"999 100000"`, `"cpu_max":"50000 999"`, `"cpu_max":"50000 1000001"`,
		`"cpu_max":"max 100000"`, `"cpu_max":"50000  100000"`, `"cpu_max":"1024001 1000"`, `"cpu_max":50000`,
	} {
		_, err := Parse([]byte(limitsBase+`,`+field+`}`), "a")
		if fail.Token(err) != "limit_invalid" {
			t.Errorf("%s: %v", field, err)
		}
	}
	_, err := Parse([]byte(limitsBase+`,"io_max":"1"}`), "a")
	if fail.Token(err) != "unknown_field" {
		t.Fatal(err)
	}
}

// A sandboxed unit is cgroup-trusted when it can write cgroupfs anyway:
// a read_write path covering /sys/fs/cgroup, or a capability that bypasses
// file permissions there.
func TestCgroupTrustedSandboxed(t *testing.T) {
	uid := uint32(65534)
	boxed := func(rw []string, caps []string) *Service {
		return &Service{Execution: Execution{UID: &uid, GID: &uid}, Sandbox: &Sandbox{NoNewPrivs: true, ReadWrite: rw, Caps: caps}}
	}
	for _, rw := range []string{"/", "/sys", "/sys/fs", "/sys/fs/cgroup", "/sys/fs/cgroup/x"} {
		if !CgroupTrusted(boxed([]string{"/var/lib/x", rw}, nil)) {
			t.Errorf("rw %s untrusted", rw)
		}
	}
	for _, c := range []string{"dac_override", "fowner", "chown", "setuid", "sys_admin"} {
		if !CgroupTrusted(boxed(nil, []string{"kill", c})) {
			t.Errorf("cap %s untrusted", c)
		}
	}
	for _, sb := range []*Service{boxed([]string{"/var/lib/x", "/sys/fs/cgroupx", "/sysx"}, []string{"kill", "net_bind_service"}), boxed(nil, nil)} {
		if CgroupTrusted(sb) {
			t.Errorf("%+v trusted", sb.Sandbox)
		}
	}
	other := &Service{Execution: Execution{UID: &uid, GID: &uid}}
	if CgroupTrusted(other) != (os.Geteuid() == 65534) || !CgroupTrusted(&Service{}) {
		t.Fatal("unsandboxed rule")
	}
}
