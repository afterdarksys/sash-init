# Migrating service catalogs to SAHINIT

The executable is currently named `sahinit` (module `github.com/afterdarksys/sahinit`).
The migration command handles **standalone service definitions**, not replacement
of a running machine's PID 1. Never uninstall the existing init system based only
on a successful conversion. SAHINIT is a userspace supervisor with an experimental
PID 1 mode ([host init](host-init.md)).

```sh
go build -o /tmp/sahinit ./cmd/sahinit
/tmp/sahinit migrate --from systemd --source ./exported-services
/tmp/sahinit migrate --from daemontools --source ./service-directories
/tmp/sahinit migrate --from openrc --source ./exported-init.d

# Write a NEW directory after reviewing the JSON report:
/tmp/sahinit migrate --from systemd --source ./exported-services --out ./converted --boot
/tmp/sahinit plan --dir ./converted
/tmp/sahinit supervise --dir ./converted --socket /run/sahinit/sahinit.sock
```

Omitting `--out` produces a JSON preview only. Exit codes: 0 = conversion succeeded,
1 = compatibility blockers, 2 = invocation or I/O failure. Reports contain candidate
units and diagnostics with source paths, line numbers where available, and severity.
Candidates in a blocked report are **not a complete deployable catalog**. Any blocker
prevents all output. Existing output directories are never overwritten.

Boot is disabled by default. `--boot` selects all converted services, except
those with a daemontools `down` entry. `[Install]` is not evidence that a systemd
unit is enabled; OpenRC runlevels are not inferred. No source script is executed,
no existing service is stopped, and no source files are edited.

## Current compatibility

| Source | Converted | Explicit blockers |
| --- | --- | --- |
| systemd | `Type=simple/exec`, single literal `ExecStart`, supported `Restart` policies, service-only `After`, oneshot with `RemainAfterExit=yes` | Drop-ins, templates, aliases/masked files represented as symlinks, targets, timers, socket/D-Bus activation, notify protocol, forking, users/groups, environment, working directories, security/resource directives, lifecycle hooks, Requires/Wants/Before, unknown directives |
| daemontools | Service directory with a `/bin/sh` or `/bin/bash` `run` script consisting of comments and one literal `exec /absolute/program ...`, restart always, `down`; ignores `supervise` runtime state | Shell setup, relative executables, log pipelines, env directories, finish scripts and other extra content |
| OpenRC | `openrc-run` scripts with literal command/argument assignments, optional `supervisor=supervise-daemon`, `command_args_foreground`, literal `depend() { after ... }` | Shell expansion, custom start/stop hooks, identity/directory settings, background/PID-file options, need/use/provide/before, unsupported supervisors/settings |

Commands support whitespace-separated literal arguments and single/double quotes.
Escapes, expansions, specifiers, shell operators and globs require manual conversion.
Repeated arguments are preserved. Names must already satisfy SAHINIT's lowercase
name grammar; the converter does not invent potentially colliding renames.
All generated units pass the actual unit parser and dependency planner before write.
Executables are validated at service launch on the destination, not against the
migration host's filesystem.

## Differences that still require review

This is a conservative first converter, **not a claim of behavioral equivalence**.
Even supported units use SAHINIT's clean PATH-only environment, `/` working directory,
bounded in-memory service output tails, five-second default timeout, and bounded restart policy.
Systemd simple readiness becomes exec readiness. SAHINIT `After` orders boot, and
shutdown stops units in the reverse order; runtime dependency propagation (stopping
a dependent when its provider fails) is not implemented.
Daemontools originally runs in its service directory and retries indefinitely.
OpenRC can load `conf.d`, `rc.conf`, multiplexed settings and runlevel configuration;
these external files are not discovered or evaluated. Export self-contained scripts
and review their effective configuration first. A foreground command is required.
Warnings are always included in the report for these differences.

Do not export a bare systemd base unit while omitting its drop-ins: this offline
converter cannot detect files outside the selected directory. Flatten/review the
full effective unit configuration before conversion. Unresolved service dependencies
and cycles block output; no stub services are fabricated.

## Tests

```sh
go test ./internal/migrate ./cmd/sahinit
./scripts/test-migration-docker.sh
```

The Docker test builds the actual CLI, converts one fixture from each source format,
validates the catalog, then verifies boot, status, restart, stop, start and graceful
shutdown on Linux. It also checks that unsupported identity settings prevent output.
It runs with Docker's init reaper and no network access at runtime. It does **not**
boot systemd/OpenRC/daemontools or establish equivalence with their native runtime;
that requires a subsequent source-versus-target compatibility matrix.

Source semantics: [systemd.service](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html),
[daemontools supervise](https://cr.yp.to/daemontools/supervise.html),
[OpenRC openrc-run](https://github.com/OpenRC/openrc/blob/master/man/openrc-run.8).
