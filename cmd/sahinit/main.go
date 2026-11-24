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
	"time"

	"github.com/afterdarksys/sahinit/internal/cgroup"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/hostinit"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/supervise"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const usageText = policyUsage + sashUsage +
	"usage: sahinit init [--dir DIR] [--socket PATH] [--recovery EXECUTABLE] [--shutdown-timeout DURATION]\n" +
	"usage: sahinit ctl --socket PATH status|diagnostics|start|stop|restart|reload|check [NAME]\n" +
	"usage: sahinit plan --dir DIR\n" +
	"usage: sahinit supervise --dir DIR --socket PATH [--uid UID]... [--gid GID] [--no-cgroups] [--cgroup-sweep DURATION] [--boot-strict] [--sash PATH] [--sash-fleet-pub PATH] [--sash-floor-dir DIR]\n" +
	"usage: sahinit migrate --from FORMAT --source DIR [--out NEW_DIR] [--boot]\n"

func main() {
	if os.Getpid() == 1 {
		args := os.Args[1:]
		if len(args) > 0 && args[0] == "init" {
			args = args[1:]
		}
		if err := hostinit.Run(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
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
	case "init":
		if err := hostinit.Run(args[1:]); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "sash":
		return runSash(args[1:], stdout, stderr)
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
	flagTrusted(svcs, stderr)
	return 0
}

// flagTrusted names, as "cgroup_trusted FILE", each unit that runs without a
// sandbox as root or as the supervisor's uid: it can leave its cgroup, so
// the cgroup guarantees are not promised for it.
func flagTrusted(svcs map[string]*unit.Service, stderr io.Writer) {
	names := make([]string, 0, len(svcs))
	for name, svc := range svcs {
		if unit.CgroupTrusted(svc) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintln(stderr, "cgroup_trusted", name+".json")
	}
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

// openCgroups opens the supervisor's own cgroup as the root for service
// cgroups. Without a usable delegated cgroup v2 it is cgroup_unavailable,
// unless noCgroups keeps process groups (mode disabled). Off Linux there
// are no cgroups (mode unsupported). The mode is reported in status and
// diagnostics.
func openCgroups(noCgroups bool) (*cgroup.Root, string, error) {
	if noCgroups {
		return nil, supervise.CgroupsDisabled, nil
	}
	if !cgroup.Supported() {
		return nil, supervise.CgroupsUnsupported, nil
	}
	root, err := cgroup.Open("")
	if err != nil {
		return nil, "", err
	}
	return root, supervise.CgroupsEnabled, nil
}

// refuseLimits leaves out each unit whose limits need a controller the root
// does not offer, or any limit when there is no root, naming it on stderr
// as "cgroup_controller FILE". It is empty when nothing is left.
func refuseLimits(svcs map[string]*unit.Service, root *cgroup.Root, stderr io.Writer) error {
	names := make([]string, 0, len(svcs))
	for name := range svcs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		l := svcs[name].Limits
		if !l.Any() {
			continue
		}
		if root != nil && root.Supports(l) == nil {
			continue
		}
		fmt.Fprintln(stderr, "cgroup_controller", name+".json")
		delete(svcs, name)
	}
	if len(svcs) == 0 {
		return fail.E("empty")
	}
	return nil
}

func runSupervise(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("supervise", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	sock := fs.String("socket", "", "")
	noCgroups := fs.Bool("no-cgroups", false, "")
	strict := fs.Bool("boot-strict", false, "exit to the PID 1 recovery loop if boot fails")
	sweep := fs.Duration("cgroup-sweep", 30*time.Second, "")
	var sf sashFlags
	fs.StringVar(&sf.binary, "sash", "/usr/bin/sash", "")
	fs.StringVar(&sf.fleetPub, "sash-fleet-pub", "", "")
	fs.StringVar(&sf.floorDir, "sash-floor-dir", "", "")
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
	var gid *uint32
	fs.Func("gid", "", func(s string) error {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || gid != nil {
			return fail.E("failed")
		}
		g := uint32(n)
		gid = &g
		return nil
	})
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" || *sock == "" || *sweep < 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	var svcs map[string]*unit.Service
	var err error
	if *strict {
		var refused map[string]string
		svcs, refused, err = unit.Load(*dir)
		if len(refused) > 0 && err == nil {
			err = fail.E("boot_refused")
		}
	} else {
		svcs, err = loadUnits(*dir, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	root, mode, err := openCgroups(*noCgroups)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	defer root.Close()
	beforeLimits := len(svcs)
	if err := refuseLimits(svcs, root, stderr); err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	if *strict && len(svcs) != beforeLimits {
		fmt.Fprintln(stderr, "boot_refused")
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "failed")
		return 2
	}
	sashCfg, sashRefused := setupSash(sf, svcs, root, self, stderr)
	if *strict && sashRefused > 0 {
		fmt.Fprintln(stderr, "boot_refused")
		return 2
	}
	if len(svcs) == 0 {
		fmt.Fprintln(stderr, "empty")
		return 2
	}
	if sashCfg != nil {
		defer sashCfg.Floors.Close()
	}
	waves, err := graph.Plan(svcs)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	sup, err := supervise.New(svcs, self)
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		return 2
	}
	sup.SocketGID = gid
	sup.Sash = sashCfg
	if sashCfg != nil {
		// Mounts a previous sahinit made for sash services and left.
		sup.CleanSashMounts()
	}
	sup.Cgroups, sup.CgroupMode = root, mode
	sup.Log = stderr
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
	// Leftover service cgroups are cleaned only with both the cgroup root's
	// lock (openCgroups) and the socket's lock held, in that order, so a
	// second supervisor that fails either one has touched nothing.
	if root != nil {
		if !root.Protected() {
			// No controller is enabled below the root, so the kernel lets
			// anything move into it: root members are refused as peers.
			fmt.Fprintln(stderr, "cgroup_root_unprotected", root.Rel())
		}
		names, err := root.CleanLeftovers()
		for _, name := range names {
			fmt.Fprintln(stderr, "cgroup_leftover", name)
		}
		if err != nil {
			fmt.Fprintln(stderr, fail.Token(err))
			sup.Close()
			return 2
		}
	}
	signal.Ignore(syscall.SIGHUP)
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go sup.SweepEvery(ctx, *sweep)
	errc := make(chan error, 1)
	go func() {
		errc <- sup.Serve()
		cancel()
	}()
	bootFailed := false
	if err := sup.Boot(ctx, waves); err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, fail.Token(err))
		if *strict {
			bootFailed = true
			cancel()
		}
	}
	if *strict && !bootFailed {
		// In host boot mode every boot unit is essential. A failed unit or
		// an unexpectedly exited long-running unit returns control to PID 1.
		tick := time.NewTicker(200 * time.Millisecond)
	monitor:
		for {
			select {
			case <-ctx.Done():
				break monitor
			case <-tick.C:
				rows, _ := sup.Status("")
				for _, row := range rows {
					svc := svcs[row.Name]
					if svc != nil && svc.Boot && (row.State == "failed" || (row.State == "exited" && svc.Type != "oneshot")) {
						fmt.Fprintln(stderr, "boot_service_failed", row.Name)
						bootFailed = true
						cancel()
						break monitor
					}
				}
			}
		}
		tick.Stop()
	} else {
		<-ctx.Done()
	}
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
	if bootFailed || serveErr != nil {
		return 1
	}
	return 0
}
