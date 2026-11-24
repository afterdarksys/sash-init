// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
)

// Without a cgroup root, status and diagnostics say why: disabled by
// default (--no-cgroups) or unsupported off Linux. Never silently.
func TestCgroupModeReported(t *testing.T) {
	sup := mustSup(t, map[string]*unit.Service{"idle": newSvc("idle", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})})
	for _, mode := range []string{"", CgroupsUnsupported} {
		sup.CgroupMode = mode
		want := mode
		if want == "" {
			want = CgroupsDisabled
		}
		row := rowOf(t, sup, "idle")
		d, err := sup.Diagnostics("idle")
		if err != nil || row.Cgroups != want || d.Cgroups != want || row.Cgroup != "" || row.Usage != nil {
			t.Fatalf("%+v %+v %v", row, d, err)
		}
	}
}

// Status flags a service the cgroup guarantees are not promised for: no
// sandbox, and root or the supervisor's uid.
func TestCgroupTrustedReported(t *testing.T) {
	own := newSvc("own", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})
	boxed := newSvc("boxed", "simple", "exec", "no", false, time.Second, []string{"/bin/sleep", "30"})
	uid := uint32(65534)
	boxed.Execution = unit.Execution{UID: &uid, GID: &uid}
	boxed.Sandbox = &unit.Sandbox{NoNewPrivs: true}
	sup := mustSup(t, map[string]*unit.Service{"own": own, "boxed": boxed})
	if !rowOf(t, sup, "own").CgroupTrusted || rowOf(t, sup, "boxed").CgroupTrusted {
		t.Fatalf("%+v %+v", rowOf(t, sup, "own"), rowOf(t, sup, "boxed"))
	}
}
