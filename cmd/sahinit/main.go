// SPDX-License-Identifier: GPL-3.0-or-later

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
	"github.com/afterdarksys/sahinit/internal/deploy"
	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/graph"
	"github.com/afterdarksys/sahinit/internal/hostinit"
	"github.com/afterdarksys/sahinit/internal/journal"
	"github.com/afterdarksys/sahinit/internal/sandbox"
	"github.com/afterdarksys/sahinit/internal/supervise"
	"github.com/afterdarksys/sahinit/internal/unit"
)

const usageText = policyUsage + sashUsage +
	"usage: sahinit init [--dir DIR] [--socket PATH] [--recovery EXECUTABLE] [--shutdown-timeout DURATION] [--log-dir DIR] [--deployment-root DIR --trust FILE [--trust-system-clock]] [--sash PATH] [--sash-fleet-pub PATH] [--sash-floor-dir DIR]\n" +
	"usage: sahinit ctl --socket PATH status|diagnostics|explain|start|stop|restart|reload|check|rollback|activate [NAME]\n" +
	"usage: sahinit ctl --socket PATH --dir DIR diff|apply\n" +
	"usage: sahinit plan --dir DIR\n" +
	"usage: sahinit validate --dir DIR\n" +
	"usage: sahinit supervise --dir DIR --socket PATH [--deployment-root DIR --trust FILE [--trust-system-clock]] [--uid UID]... [--gid GID] [--no-cgroups] [--cgroup-sweep DURATION] [--boot-strict] [--log-dir DIR] [--sash PATH] [--sash-fleet-pub PATH] [--sash-floor-dir DIR]\n" +
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
	if args[0] == "--skill" {
		return runSkill(args[1:], stdout, stderr)
	}
	switch args[0] {
	case "codes":
		return runCodes(args[1:], stdout, stderr)
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "deploy":
		return runDeploy(args[1:], stdout, stderr)
	case "host":
		return runHost(args[1:], stdout, stderr)
	case "logs", "events":
		return runLogs(args[0], args[1:], stdout, stderr)
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
	case "validate":
		return runValidate(args[1:], stdout, stderr)
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
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" {
		return usage(args, usageText, stdout, stderr)
	}
	svcs, refused, err := loadUnits(*dir, stderr)
	var waves [][]string
	if err == nil {
		waves, err = graph.Plan(svcs)
	}
	if err != nil {
		fmt.Fprintln(stderr, fail.Token(err))
		if *asJSON {
			writeJSON(stdout, catalogJSON(err, waves, refused, svcs))
		}
		return 2
	}
	if *asJSON {
		if !writeJSON(stdout, catalogJSON(nil, waves, refused, svcs)) {
			return 1
		}
	} else {
		for _, wave := range waves {
			fmt.Fprintln(stdout, strings.Join(wave, " "))
		}
	}
	for _, file := range trustedFiles(svcs) {
		fmt.Fprintln(stderr, "cgroup_trusted", file)
	}
	return 0
}

// trustedFiles names, as FILE, each unit that runs without a sandbox as
// root or as the supervisor's uid: it can leave its cgroup, so the cgroup
// guarantees are not promised for it (plan prints "cgroup_trusted FILE").
func trustedFiles(svcs map[string]*unit.Service) []string {
	names := []string{}
	for name, svc := range svcs {
		if unit.CgroupTrusted(svc) {
			names = append(names, name+".json")
		}
	}
	sort.Strings(names)
	return names
}

// loadUnits loads the catalog and names each refused unit file on stderr as
// "TOKEN FILE". A refused unit is left out; the rest of the catalog loads.
func loadUnits(dir string, stderr io.Writer) (map[string]*unit.Service, map[string]string, error) {
	svcs, refused, err := unit.Load(dir)
	files := make([]string, 0, len(refused))
	for file := range refused {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		fmt.Fprintln(stderr, refused[file], file)
	}
	return svcs, refused, err
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
	logDir := fs.String("log-dir", "", "bounded persistent journal directory")
	deploymentRoot := fs.String("deployment-root", "", "")
	trustPath := fs.String("trust", "", "")
	trustClock := fs.Bool("trust-system-clock", false, "")
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
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*dir == "") == (*deploymentRoot == "") || (*deploymentRoot == "" && (*trustPath != "" || *trustClock)) || *sock == "" || *sweep < 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	var svcs map[string]*unit.Service
	var err error
	var manager *deploy.Manager
	var active *deploy.Catalog
	if *deploymentRoot != "" {
		manager, err = deployment(*deploymentRoot, *trustPath, *trustClock)
		if err == nil {
			var state deploy.State
			state, err = manager.State()
			if err == nil {
				active, err = manager.Load(state.Active)
			}
		}
		if err == nil {
			svcs = active.Units
		}
	} else if *strict {
		var refused map[string]string
		svcs, refused, err = unit.Load(*dir)
		if len(refused) > 0 && err == nil {
			err = fail.E("boot_refused")
		}
	} else {
		svcs, _, err = loadUnits(*dir, stderr)
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
	if (*strict || manager != nil) && len(svcs) != beforeLimits {
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
	if manager != nil {
		sup.SetAdmission(func(name string, restart bool) error { return manager.Admit(active, name, restart) })
		sup.OnActivate = activator(manager, sup)
	}
	if *logDir != "" {
		// The journal is optional: a read-only or unusable directory is
		// reported and the supervisor runs with the in-memory tails only,
		// so a bad log disk never fails the boot.
		if j, err := journal.Open(*logDir, 1024*1024, 4); err != nil {
			fmt.Fprintln(stderr, "journal_unavailable", fail.Token(err))
		} else {
			defer j.Close()
			sup.SetJournal(j)
			j.Emit(journal.Record{Unit: "sahinit", Stream: "event", Event: []byte(`{"kind":"supervisor_started"}`)})
		}
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
	}
	// In host boot mode a boot unit is essential unless its unit says
	// "essential": false. An essential unit that failed, stopped on its own
	// or was never ready, or that needs one that did, returns control to
	// PID 1; an optional unit's failure stays its own.
	if *strict && ctx.Err() == nil {
		if name := sup.EssentialFailure(true); name != "" {
			fmt.Fprintln(stderr, "boot_service_failed", name)
			bootFailed = true
			cancel()
		}
	}
	if !bootFailed && ctx.Err() == nil {
		sup.SetBooted(true)
	}
	tick := time.NewTicker(200 * time.Millisecond)
monitor:
	for {
		select {
		case <-ctx.Done():
			break monitor
		case <-tick.C:
			if err := sup.Reconcile(ctx); err != nil {
				fmt.Fprintln(stderr, fail.Token(err))
			}
			if *strict {
				if name := sup.EssentialFailure(false); name != "" {
					fmt.Fprintln(stderr, "boot_service_failed", name)
					bootFailed = true
					cancel()
					break monitor
				}
			}
		}
	}
	tick.Stop()
	var serveErr error
	select {
	case serveErr = <-errc:
	default:
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, fail.Token(serveErr))
	}
	sup.SetBooted(false)
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
