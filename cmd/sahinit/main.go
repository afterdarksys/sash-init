package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/supervise"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const usageText = policyUsage +
	"usage: sahinit ctl --socket PATH status|diagnostics|start|stop|restart [NAME]\n" +
	"usage: sahinit plan --dir DIR\n" +
	"usage: sahinit supervise --dir DIR --socket PATH [--uid UID]\n" +
	"usage: sahinit migrate --from FORMAT --source DIR [--out NEW_DIR] [--boot]\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if args[0] == "apply" {
		return sandbox.ApplyCLI(args)
	}
	switch args[0] {
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "ctl":
		return runCtl(args[1:], stdout, stderr)
	case "migrate":
		return runMigrate(args[1:], stdout, stderr)
	case "plan":
		return runPlan(args[1:], stdout, stderr)
	case "supervise":
		return runSupervise(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	svcs, err := loadUnits(*dir, stderr)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	waves, err := graph.Plan(svcs)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	for _, wave := range waves {
		fmt.Fprintln(stdout, strings.Join(wave, " "))
	}
	return 0
}

// loadUnits loads the catalog and names each refused unit file on stderr as
// "TOKEN FILE". A refused unit is left out; the rest of the catalog loads.
func loadUnits(dir string, stderr io.Writer) (map[string]*unit.Service, error) {
	svcs, refused, err := unit.Load(dir)
	files := make([]string, 0, len(refused))
	for file := range refused {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		fmt.Fprintln(stderr, refused[file], file)
	}
	return svcs, err
}

func runSupervise(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("supervise", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	sock := fs.String("socket", "", "")
	var uids []uint32
	passed := false
	fs.Func("uid", "", func(s string) error {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return err
		}
		passed = true
		uids = append(uids, uint32(n))
		return nil
	})
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" || *sock == "" {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	svcs, err := loadUnits(*dir, stderr)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	waves, err := graph.Plan(svcs)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "failed")
		return 2
	}
	sup, err := supervise.New(svcs, self)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	if passed {
		sup.Allow = map[uint32]struct{}{}
		for _, uid := range uids {
			sup.Allow[uid] = struct{}{}
		}
	}
	if err := sup.Listen(*sock); err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	signal.Ignore(syscall.SIGHUP)
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- sup.Serve()
		cancel()
	}()
	if err := sup.Boot(ctx, waves); err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, fail.Token(err))
	}
	<-ctx.Done()
	var serveErr error
	select {
	case serveErr = <-errc:
	default:
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, fail.Token(serveErr))
	}
	if err := sup.Shutdown(context.Background()); err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
	}
	if err := sup.Close(); err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
	}
	return 0
}
