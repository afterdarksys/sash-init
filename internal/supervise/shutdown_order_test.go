package supervise

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahinit/internal/unit"
)

func TestShutdownWaitsForDependent(t *testing.T) {
	order, appReady, dbReady := marker(t), marker(t), marker(t)
	script := writeScript(t, `trap 'printf "%s\n" "$1" >> "$2"; exit 0' TERM
: > "$3"
while :; do /bin/sleep 1; done
`)
	db := newSvc("db", "simple", "exec", "no", true, 3*time.Second, shExec(script, "db", order, dbReady))
	app := newSvc("app", "simple", "exec", "no", false, 3*time.Second, shExec(script, "app", order, appReady))
	app.Needs = []string{"db"}
	sup := mustSup(t, map[string]*unit.Service{"db": db, "app": app})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, name := range []string{"db", "app"} {
		if err := sup.Start(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{dbReady, appReady} {
		for {
			if _, err := os.Stat(path); err == nil {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("trap not installed")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := sup.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(order)
	if err != nil || strings.TrimSpace(string(raw)) != "app\ndb" {
		t.Fatalf("order %q: %v", raw, err)
	}
}
