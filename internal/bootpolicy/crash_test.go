package bootpolicy

import (
	"os"
	"os/exec"
	"testing"
)

func TestStoreCrashHelper(t *testing.T) {
	stage := os.Getenv("SAHINIT_TEST_CRASH_STAGE")
	if stage == "" {
		return
	}
	trust, p, key := fixture()
	p.Sequence = 2
	store, err := OpenStore(os.Getenv("SAHINIT_TEST_CACHE"), trust, fixed(p.IssuedAt))
	if err != nil {
		t.Fatal(err)
	}
	store.checkpoint = func(s string) error {
		if s == stage {
			os.Exit(77)
		}
		return nil
	}
	if _, err := store.Install(signed(p, key)); err != nil {
		t.Fatal(err)
	}
	t.Fatal("checkpoint not reached")
}
func TestStoreProcessCrash(t *testing.T) {
	trust, p, key := fixture()
	for _, stage := range []string{"created", "written", "file_synced", "renamed", "directory_synced"} {
		t.Run(stage, func(t *testing.T) {
			s, path := newStore(t, trust, fixed(p.IssuedAt))
			if _, err := s.Install(signed(p, key)); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestStoreCrashHelper$")
			cmd.Env = append(os.Environ(), "SAHINIT_TEST_CRASH_STAGE="+stage, "SAHINIT_TEST_CACHE="+path)
			out, err := cmd.CombinedOutput()
			if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 77 {
				t.Fatalf("helper: %v %s", err, out)
			}
			d, err := s.Load()
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(1)
			if stage == "renamed" || stage == "directory_synced" {
				want = 2
			}
			if d.Policy().Sequence != want {
				t.Fatalf("got sequence %d want %d", d.Policy().Sequence, want)
			}
		})
	}
}
