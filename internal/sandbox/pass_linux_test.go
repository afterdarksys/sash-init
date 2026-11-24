//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// A sandboxed target receives Options.Pass as fds 3 to 6 (sash's wire:
// grant, fleet key, emergency key, verb socket) and nothing else; the
// helper's own exec and status fds are gone, and the umask and rlimits are
// set before exec.
func TestPassFDsUmaskRlimits(t *testing.T) {
	self, ident := helperSelf(t)
	var files []*os.File
	for _, body := range []string{"grant", "fleet", ""} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.WriteString(body)
		w.Close()
		files = append(files, r)
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(pair[0]), "verb"), os.NewFile(uintptr(pair[1]), "verb-child")
	defer mine.Close()
	files = append(files, theirs)
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	script := `ls -1 /proc/$$/fd | tr '\n' ' '; printf '|%s|%s|%s|' "$(cat <&3)" "$(cat <&4)" "$(cat <&5)"; ` +
		`[ -S /proc/self/fd/6 ] && printf sock; printf 'hello' >&6; printf '|%s|%s' "$(umask)" "$(ulimit -n)"`
	mask := 0o027
	opts := Options{Execution: ident, Pass: files, Umask: &mask, Rlimits: map[string]uint64{"nofile": 77}}
	var out, errb bytes.Buffer
	opts.Stdout, opts.Stderr = &out, &errb
	sb := &unit.Sandbox{NoNewPrivs: true, ReadOnly: []string{"/"}}
	cmd, claim, _, err := Launch(context.Background(), self, []string{"/bin/sh", "-c", script}, sb, false, 5*time.Second, opts)
	if err != nil {
		if tok := fail.Token(err); tok == "landlock_unavailable" || tok == "openat2_unavailable" {
			t.Skipf("kernel lacks sandbox: %v", err)
		}
		t.Fatal(err)
	}
	if !IsSandboxClaim(claim) {
		t.Fatalf("claim %q", claim)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err, errb.String())
	}
	got := out.String()
	if want := "0 1 2 3 4 5 6 |grant|fleet||sock|0027|77"; got != want {
		t.Fatalf("got %q, want %q (stderr %q)", got, want, errb.String())
	}
	buf := make([]byte, 5)
	mine.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := mine.Read(buf); string(buf[:n]) != "hello" {
		t.Fatalf("verb socket: %q", buf[:n])
	}
}

// Passing fds needs a sandbox and no notify, and at most MaxPass of them.
func TestPassRefusals(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	sb := &unit.Sandbox{NoNewPrivs: true}
	for name, c := range map[string]struct {
		sb     *unit.Sandbox
		notify bool
		n      int
	}{"no sandbox": {nil, false, 1}, "notify": {sb, true, 1}, "too many": {sb, false, MaxPass + 1}} {
		pass := make([]*os.File, c.n)
		for i := range pass {
			pass[i] = r
		}
		if _, _, _, err := Launch(context.Background(), "/bin/sh", []string{"/bin/true"}, c.sb, c.notify, time.Second, Options{Pass: pass}); err == nil {
			t.Errorf("%s: launched", name)
		}
	}
	if _, _, _, err := Launch(context.Background(), "/bin/sh", []string{"/bin/true"}, nil, false, time.Second, Options{Rlimits: map[string]uint64{"core": 0}}); err == nil {
		t.Error("rlimits without a sandbox launched")
	}
	if !strings.Contains(string(mustSpec(t)), `"pass":2`) {
		t.Fatal("spec")
	}
}

func mustSpec(t *testing.T) []byte {
	t.Helper()
	b, err := marshalSpecPass(&unit.Sandbox{NoNewPrivs: true}, false, false, 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
