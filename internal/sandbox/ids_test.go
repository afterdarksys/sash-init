// SPDX-License-Identifier: GPL-3.0-or-later

package sandbox

import (
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestSupervisorIDs(t *testing.T) {
	const euid, egid = 900, 901
	g := func(v uint32) *uint32 { return &v }
	for _, tc := range []struct {
		sb *unit.Sandbox
		e  unit.Execution
		ok bool
	}{
		{&unit.Sandbox{SetuidTo: []uint32{5, euid}}, unit.Execution{GID: g(7)}, false},
		{&unit.Sandbox{SetgidTo: []uint32{egid}}, unit.Execution{GID: g(7)}, false},
		{&unit.Sandbox{}, unit.Execution{GID: g(egid)}, false},
		{&unit.Sandbox{}, unit.Execution{GID: g(7), Groups: []uint32{8, egid}}, false},
		// The supervisor's uid as a gid, or its gid as a uid, is no match.
		{&unit.Sandbox{SetuidTo: []uint32{egid}, SetgidTo: []uint32{euid}}, unit.Execution{GID: g(euid), Groups: []uint32{euid}}, true},
		{&unit.Sandbox{SetuidTo: []uint32{5}, SetgidTo: []uint32{6}}, unit.Execution{GID: g(7), Groups: []uint32{8}}, true},
	} {
		err := supervisorIDs(tc.sb, tc.e, euid, egid)
		if (err == nil) != tc.ok || err != nil && fail.Token(err) != "sandbox_ids" {
			t.Errorf("%+v %+v: %v", tc.sb, tc.e, err)
		}
	}
}
