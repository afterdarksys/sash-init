package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestLaunchRelative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"sh"}, nil, false, time.Second)
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("exec_relative")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
}

func TestLaunchMissingIsExecNotFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/tmp/sahinit-missing-exec"}, &unit.Sandbox{}, false, time.Second)
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
}

func TestLaunchSymlinkIsExecNotFile(t *testing.T) {
	link := "/tmp/sahinit-exec-link"
	os.Remove(link)
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{link}, &unit.Sandbox{}, false, time.Second)
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
}

func TestLaunchNonExecIsExecNotFile(t *testing.T) {
	path := "/tmp/sahinit-nonexec"
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{path}, &unit.Sandbox{}, false, time.Second)
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("exec_not_file")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
}

func TestLaunchDirect(t *testing.T) {
	marker := "/tmp/sahinit-direct-marker"
	os.Remove(marker)
	t.Cleanup(func() { os.Remove(marker) })
	script := "/tmp/sahinit-direct-script"
	body := "printf 'ok\\n' > \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(script) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script, marker}, nil, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if nf != nil {
		nf.Close()
		t.Fatal("notify file")
	}
	if claim != "none" || cmd == nil {
		t.Fatalf("claim=%q cmd=%v", claim, cmd)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "ok\n" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestLaunchEmptySandboxUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("landlock probe covers enforcement")
	}
	marker := "/tmp/sahinit-unsandboxed-marker"
	os.Remove(marker)
	t.Cleanup(func() { os.Remove(marker) })
	script := "/tmp/sahinit-unsandboxed-script"
	if err := os.WriteFile(script, []byte("printf 'ran\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(script) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script, marker}, &unit.Sandbox{}, false, time.Second)
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("sandbox_unsupported")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestApplyCLIWithoutHandshake(t *testing.T) {
	if ApplyCLI([]string{"apply"}) != 2 {
		t.Fatal("exit")
	}
}

func sahp(t *testing.T, name string) string {
	t.Helper()
	p := fmt.Sprintf("/tmp/sahp-%d-%s", os.Getpid(), name)
	t.Cleanup(func() {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s: %v", p, err)
		}
	})
	return p
}

func writeSahp(t *testing.T, name, body string) string {
	t.Helper()
	p := sahp(t, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func absentSahp(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s: %v", path, err)
	}
}

func launchCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func TestLaunchCanceled(t *testing.T) {
	mark := sahp(t, "cancel-mark")
	script := writeSahp(t, "cancel-script", "printf 'ran\\n' > \"$1\"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script, mark}, nil, false, time.Second)
	if cmd != nil {
		if werr := cmd.Wait(); werr != nil {
			t.Error(werr)
		}
	}
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("failed")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	absentSahp(t, mark)
}

func TestLaunchEmptyArgv(t *testing.T) {
	ctx, cancel := launchCtx(t)
	defer cancel()
	for _, argv := range [][]string{nil, {}} {
		cmd, claim, nf, err := Launch(ctx, "/bin/sh", argv, nil, false, time.Second)
		if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("failed")) {
			t.Fatalf("argv %q cmd=%v nf=%v claim=%q err=%v", argv, cmd, nf, claim, err)
		}
	}
}

func TestLaunchArgLength(t *testing.T) {
	ctx, cancel := launchCtx(t)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", strings.Repeat("a", 257)}, nil, false, time.Second)
	if cmd != nil {
		if werr := cmd.Wait(); werr != nil {
			t.Error(werr)
		}
	}
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("failed")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}

	mark := sahp(t, "arglen-mark")
	script := writeSahp(t, "arglen-script", "printf '%s\\n' \"$1\" > \"$2\"\n")
	arg := strings.Repeat("b", 256)
	cmd, claim, nf, err = Launch(ctx, "/bin/sh", []string{"/bin/sh", script, arg, mark}, nil, false, time.Second)
	if err != nil || claim != "none" || nf != nil || cmd == nil {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			if werr := cmd.Wait(); werr != nil {
				t.Error(werr)
			}
		}
	}()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(mark)
	if err != nil || string(got) != arg+"\n" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestLaunchNUL(t *testing.T) {
	mark := sahp(t, "nul-mark")
	script := writeSahp(t, "nul-script", "printf 'ran\\n' > \"$1\"\n")
	ctx, cancel := launchCtx(t)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script, "a\x00b", mark}, nil, false, time.Second)
	if cmd != nil {
		if werr := cmd.Wait(); werr != nil {
			t.Error(werr)
		}
	}
	if cmd != nil || nf != nil || claim != "" || !errors.Is(err, fail.E("failed")) {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	absentSahp(t, mark)
}

func TestLaunchArgvCount(t *testing.T) {
	ctx, cancel := launchCtx(t)
	defer cancel()
	tooMany := make([]string, 33)
	tooMany[0] = "/bin/sh"
	for i := 1; i < len(tooMany); i++ {
		tooMany[i] = "x"
	}
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", tooMany, nil, false, time.Second)
	if cmd != nil {
		if werr := cmd.Wait(); werr != nil {
			t.Error(werr)
		}
		t.Fatal("cmd")
	}
	if nf != nil || claim != "" || !errors.Is(err, fail.E("failed")) {
		t.Fatalf("nf=%v claim=%q err=%v", nf, claim, err)
	}

	script := writeSahp(t, "argc-script", "exit 0\n")
	argv := []string{"/bin/sh", script}
	for len(argv) < 32 {
		argv = append(argv, "x")
	}
	cmd, claim, nf, err = Launch(ctx, "/bin/sh", argv, nil, false, time.Second)
	if err != nil || claim != "none" || nf != nil || cmd == nil {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchNotifyByte(t *testing.T) {
	script := writeSahp(t, "notify-script", "printf 'Z' >&3\n")
	ctx, cancel := launchCtx(t)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script}, nil, true, time.Second)
	if err != nil || claim != "none" || cmd == nil || nf == nil {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			if werr := cmd.Wait(); werr != nil {
				t.Error(werr)
			}
		}
	}()
	if err := nf.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	n, err := nf.Read(buf[:])
	if err != nil || n != 1 || buf[0] != 'Z' {
		t.Fatalf("n=%d buf=%q err=%v", n, buf[:n], err)
	}
	if err := nf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchEnvIsolated(t *testing.T) {
	t.Setenv("SAHINIT_SENTINEL", "leak")
	mark := sahp(t, "env-mark")
	script := writeSahp(t, "env-script", "printf '%s\\n' \"$PATH\" > \"$1\"\nprintf '%s\\n' \"$SAHINIT_SENTINEL\" >> \"$1\"\npwd >> \"$1\"\n")
	ctx, cancel := launchCtx(t)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script, mark}, nil, false, time.Second)
	if err != nil || claim != "none" || nf != nil || cmd == nil {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			if werr := cmd.Wait(); werr != nil {
				t.Error(werr)
			}
		}
	}()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(mark)
	if err != nil || string(got) != "/usr/bin:/bin:/usr/sbin:/sbin\n\n/\n" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestLaunchRelativeArg(t *testing.T) {
	mark := sahp(t, "rel-mark")
	script := writeSahp(t, "rel-script", "printf '%s\\n' \"$1\" > \"$2\"\n")
	ctx, cancel := launchCtx(t)
	defer cancel()
	cmd, claim, nf, err := Launch(ctx, "/bin/sh", []string{"/bin/sh", script, "rel/ative", mark}, nil, false, time.Second)
	if err != nil || claim != "none" || nf != nil || cmd == nil {
		t.Fatalf("cmd=%v nf=%v claim=%q err=%v", cmd, nf, claim, err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			if werr := cmd.Wait(); werr != nil {
				t.Error(werr)
			}
		}
	}()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(mark)
	if err != nil || string(got) != "rel/ative\n" {
		t.Fatalf("%q %v", got, err)
	}
}
