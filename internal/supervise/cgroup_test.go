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
