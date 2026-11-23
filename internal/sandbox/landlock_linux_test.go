//go:build linux

package sandbox

import (
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
	"golang.org/x/sys/unix"
)

// Only the rights an ABI knows are handled; the kernel rejects a ruleset
// naming rights it does not know, which made every kernel before 6.10 fail.
func TestLandlockAccessByABI(t *testing.T) {
	if _, _, err := landlockAccess(0, accessRead); fail.Token(err) != "landlock_unavailable" {
		t.Fatal(err)
	}
	cases := []struct {
		abi, applied int
		has, lacks   uint64
	}{
		{1, 1, accessV1, unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV},
		{2, 2, accessV1 | unix.LANDLOCK_ACCESS_FS_REFER, unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV},
		{3, 3, accessV1 | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE, unix.LANDLOCK_ACCESS_FS_IOCTL_DEV},
		{4, 4, accessV1 | unix.LANDLOCK_ACCESS_FS_TRUNCATE, unix.LANDLOCK_ACCESS_FS_IOCTL_DEV},
		{5, 5, accessHandled, 0},
		{9, 5, accessHandled, 0},
	}
	for _, tc := range cases {
		handled, applied, err := landlockAccess(tc.abi, accessRead, accessWrite&^accessOptional)
		if err != nil || applied != tc.applied || handled&tc.has != tc.has || handled&tc.lacks != 0 {
			t.Fatalf("abi %d: handled %#x applied %d err %v", tc.abi, handled, applied, err)
		}
	}
	// A grant needing a right the ABI lacks is refused, not weakened.
	if _, _, err := landlockAccess(4, accessRead|unix.LANDLOCK_ACCESS_FS_IOCTL_DEV); fail.Token(err) != "landlock_abi" {
		t.Fatal(err)
	}
	if _, _, err := landlockAccess(2, unix.LANDLOCK_ACCESS_FS_TRUNCATE); fail.Token(err) != "landlock_abi" {
		t.Fatal(err)
	}
}

func TestSandboxClaim(t *testing.T) {
	if SandboxClaim(3) != "no_new_privs,landlock_v3,caps" || !IsSandboxClaim(SandboxClaim(1)) || !IsSandboxClaim(SandboxClaim(MaxLandlockABI)) {
		t.Fatal("claim")
	}
	for _, c := range []string{"", "none", "no_new_privs,landlock,caps", SandboxClaim(0), SandboxClaim(MaxLandlockABI + 1)} {
		if IsSandboxClaim(c) {
			t.Fatalf("%q accepted", c)
		}
	}
	if _, err := parseStatus(okLine(MaxLandlockABI+1), true); err == nil {
		t.Fatal("unknown ABI claim accepted")
	}
}
