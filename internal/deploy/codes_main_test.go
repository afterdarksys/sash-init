// SPDX-License-Identifier: GPL-3.0-or-later

package deploy

import (
	"fmt"
	"os"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
)

// Every code the tests made this package emit, built at run time or not,
// is in the catalog.
func TestMain(m *testing.M) {
	fail.Record()
	code := m.Run()
	if bad := fail.Uncatalogued(); len(bad) > 0 {
		fmt.Fprintln(os.Stderr, "codes emitted but not in the catalog:", bad)
		code = 1
	}
	os.Exit(code)
}
