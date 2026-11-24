// SPDX-License-Identifier: GPL-3.0-or-later

package supervise

import (
	"os"
	"testing"
)

// diff, apply, rollback and activate need a peer whose effective uid is
// root, even when --uid allows the peer for status, start and stop.
func TestCatalogOpsRootOnly(t *testing.T) {
	euid := uint32(os.Geteuid())
	sup := idleSup(t)
	sup.Allow = map[uint32]struct{}{euid: {}}
	path := tmpPath("sah")
	t.Cleanup(func() { removeFile(t, path) })
	if err := sup.Listen(path); err != nil {
		t.Fatal(err)
	}
	go sup.Serve()
	t.Cleanup(func() { sup.Close() })
	defer func(old uint32) { rootUID = old }(rootUID)
	rootUID = euid + 1
	for _, op := range []string{"diff", "apply", "rollback", "activate"} {
		if resp, raw := rpc(t, path, `{"op":"`+op+`","arg":"/nonexistent"}`); resp.OK || resp.Error != "root_required" {
			t.Fatalf("%s as non-root: %s", op, raw)
		}
	}
	if resp, raw := rpc(t, path, `{"op":"status"}`); !resp.OK {
		t.Fatalf("status: %s", raw)
	}
	rootUID = euid
	for op, want := range map[string]string{"diff": "", "apply": "", "rollback": "no_previous_catalog", "activate": "deployment_not_configured"} {
		resp, raw := rpc(t, path, `{"op":"`+op+`","arg":"/nonexistent"}`)
		if resp.Error == "root_required" || (want != "" && resp.Error != want) {
			t.Fatalf("%s as root: %s", op, raw)
		}
	}
}
