# Command-line reference

This page lists every `sahinit` command and flag. It is derived from
`cmd/sahinit/*.go` and `internal/hostinit/config.go`. `internal/fail/docs_test.go`
fails the build if a flag defined there is missing from this page.

Conventions:

- Flags use Go's `flag` syntax: `--name value`, `--name=value` or `-name value`.
  A boolean flag is set by naming it (`--boot`); `--boot=false` also works.
- Unless a section says otherwise, exit status is **0** for success, **1** for a
  refusal or failure after the arguments were accepted, and **2** for a usage
  error. A usage error prints the usage text on stderr.
- Refusals are printed as one stable token (see [codes](codes.md)), sometimes
  followed by a file or service name. Error text never carries paths, OS error
  strings or request contents, except for `migrate` and `init` (noted below).

Top-level dispatch (`cmd/sahinit/main.go`):

| First argument | Command |
| --- | --- |
| `init` | [PID 1 host init](#sahinit-init) |
| `supervise` | [the supervisor](#sahinit-supervise) |
| `plan` | [print boot waves](#sahinit-plan) |
| `validate` | [check a candidate catalog](#sahinit-validate) |
| `ctl` | [control a running supervisor](#sahinit-ctl) |
| `policy` | [boot-policy metadata](#sahinit-policy) |
| `sash` | [sash floors](#sahinit-sash) |
| `deploy` | [stage verified deployment generations](#sahinit-deploy) |
| `logs`, `events` | [read the journal](#sahinit-logs) |
| `host` | [host helpers: device wait, sd_notify adapter](#sahinit-host) |
| `migrate` | [convert systemd, daemontools or OpenRC catalogs](#sahinit-migrate) |
| `apply` | internal sandbox helper; see [below](#sahinit-apply-internal) |
| anything else, or nothing | usage text, exit 2 |

**When the process is PID 1**, every argument goes to init mode. A leading
`init` is removed first, so the kernel can run `/sahinit` or `/sahinit init`
with the init flags below. No other command can run as PID 1.

## sahinit init

```text
sahinit init [--dir DIR] [--socket PATH] [--recovery EXECUTABLE]
             [--shutdown-timeout DURATION] [--log-dir DIR]
             [--deployment-root DIR --trust FILE [--trust-system-clock]]
             [--sash PATH] [--sash-fleet-pub PATH] [--sash-floor-dir DIR]
```

Experimental Linux PID 1 parent. It refuses unless it is PID 1 and runs as
root: as an ordinary process it prints `init requires root Linux PID 1` (off
Linux, `init requires Linux PID 1`) and exits 1. As PID 1 it never exits. See
[operations](operations.md#first-boot-as-pid-1) and [host init](../host-init.md).

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--dir` | path | `/etc/sahinit/units` | Absolute. The unit directory passed to the supervisor. |
| `--socket` | path | `/run/sahinit/control.sock` | Absolute. The control socket passed to the supervisor. |
| `--recovery` | path | empty (disabled) | Absolute when set. A local console program PID 1 starts, as root, on the console, whenever the supervisor is not running. |
| `--shutdown-timeout` | duration | `30s` | From `1s` to `10m`. How long PID 1 waits for the supervisor to stop before it terminates every remaining process. |
| `--log-dir` | path | empty (no journal) | Absolute when set. Passed on as `supervise --log-dir`. |
| `--deployment-root` | path | empty | Absolute when set; needs `--trust`. The supervisor runs the active [deployment](../deployments.md) generation instead of `--dir`. |
| `--trust` | path | empty | Absolute; only with `--deployment-root`. The boot-policy trust file. |
| `--trust-system-clock` | bool | false | Only with `--deployment-root`. Passed on; see `supervise`. |
| `--sash` | path | empty | Absolute when set. Passed on as `supervise --sash`; when empty the supervisor's default `/usr/bin/sash` applies. |
| `--sash-fleet-pub` | path | empty | Absolute when set. Passed on as `supervise --sash-fleet-pub`. |
| `--sash-floor-dir` | path | empty | Absolute when set. Passed on as `supervise --sash-floor-dir`. |

The supervisor is always started as
`sahinit supervise --dir DIR --socket PATH --boot-strict [--log-dir ...] [--sash ...] [--sash-fleet-pub ...] [--sash-floor-dir ...]`,
or with `--deployment-root DIR --trust FILE [--trust-system-clock]` in place
of `--dir DIR`.

Errors: an extra argument, a relative path, `--trust` or
`--trust-system-clock` without `--deployment-root` (or the reverse), or a
timeout outside the range is
`invalid init configuration`; an unknown flag or a value that does not parse
is Go's flag error text (for example `flag provided but not defined: -x`). As
PID 1 either is logged as `sahinit-init: recovery: setup: ERROR` and PID 1
enters recovery (it does not exit). Signals to PID 1 are listed in
[operations](operations.md#power-and-signals).

## sahinit supervise

```text
sahinit supervise --dir DIR --socket PATH [--uid UID]... [--gid GID]
                  [--no-cgroups] [--cgroup-sweep DURATION] [--boot-strict]
                  [--log-dir DIR] [--sash PATH] [--sash-fleet-pub PATH]
                  [--sash-floor-dir DIR]
sahinit supervise --deployment-root DIR --trust FILE [--trust-system-clock]
                  --socket PATH [the other flags above]
```

Loads the unit catalog, opens the delegated cgroup root, prepares sash units,
binds the control socket, boots the boot units in dependency waves and serves
control requests until SIGINT or SIGTERM. SIGHUP is ignored. On exit it stops
every service in reverse dependency order.

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--dir` | path | required unless `--deployment-root` | The unit directory. See [units](units.md#the-unit-directory). Exactly one of `--dir` and `--deployment-root` is given. |
| `--deployment-root` | path | none | The [deployment](../deployments.md) root: the units are the active generation's, each start is admitted by its signed policy, and `ctl activate` is enabled. Units the cgroup root cannot limit refuse the start (`boot_refused`), as in strict boot. |
| `--trust` | path | none | Required with, and only with, `--deployment-root`: the boot-policy trust file (as `policy --trust`). |
| `--trust-system-clock` | bool | false | Only with `--deployment-root`. Accept the system clock as the time anchor for expiring (`renew`) policies; without it their admission fails closed (`policy_clock_uncertain`). `never` policies do not read the clock. |
| `--log-dir` | path | none | Absolute. The [journal](operations.md#journal) directory. If it cannot be opened (read-only, wrong owner or mode, held by another supervisor) the supervisor prints `journal_unavailable TOKEN` and runs without a journal; it never refuses the start for it. |
| `--socket` | path | required | Absolute and clean. Its directory must be private (see [files](config-files.md#control-socket-and-lock)). |
| `--uid` | uint32 | none | Repeatable. When given at least once, **only** the listed uids may use the socket; include the supervisor's own uid if it should still be allowed. Without it only the supervisor's effective uid is allowed. |
| `--gid` | uint32 | none | At most once. Required (`socket_group`) when `--uid` names a uid other than the supervisor's: the socket is then mode 0660 with this group. Otherwise it is ignored. |
| `--no-cgroups` | bool | false | Use process groups instead of cgroup v2. Units with limits are refused (`cgroup_controller`); sash units are refused (`sash_cgroups`). Status reports `"cgroups":"disabled"`. |
| `--cgroup-sweep` | duration | `30s` | At least 0. Interval of the stray-cgroup sweep; `0` turns the timer off (the sweep still runs when a service ends, on every control request and at shutdown). |
| `--boot-strict` | bool | false | Host-boot mode, used by `init`. Any refused unit file, refused limit or refused sash unit refuses the whole start (`boot_refused`). Every boot unit is **essential** unless its unit says `"essential": false`: when the boot waves end, an essential unit that is not ready (failed, never ready, crashed and waiting out a restart delay, blocked on a failed provider) stops the supervisor with exit 1 (`boot_service_failed NAME`); afterwards, one that becomes `failed` (a non-zero exit, a signal, `restart_limit`, `watchdog`), becomes `stopped` on its own (a `simple` unit that exits 0 without restart), or whose `needs` provider failed for good, does the same. After boot an automatic restart in progress is not a failure, but a crash loop ends in `restart_limit` (see [restart](units.md#types-readiness-and-restart)). Units marked `"essential": false` fail alone. |
| `--sash` | path | `/usr/bin/sash` | The sash binary, resolved and checked like a unit executable (`sash_binary`). Only used when a unit has `sash`. |
| `--sash-fleet-pub` | path | empty | The fleet public key file. Required by sash units (`sash_fleet_key`). |
| `--sash-floor-dir` | path | empty | The sash state directory: floors and the mount table. Required by sash units (`sash_floor_store`). |

Startup order and what each step can print on stderr:

1. Parse flags. Missing `--dir` or `--socket`, a bad `--uid`/`--gid`, a
   second `--gid`, a negative `--cgroup-sweep` or an extra argument: usage, exit 2.
2. Load units. A catalog-level refusal (`unit_perm`, `symlink`, `stray_file`,
   `too_many`, `empty`, `failed`, and any parse token such as `unknown_field`)
   is printed and exits 2. Each refused unit file is printed as `TOKEN FILE`
   and left out. With `--boot-strict` only `boot_refused` is printed (exit 2);
   run `plan` to see which file.
3. Open cgroups (`cgroup_unavailable`, `cgroup_busy`; exit 2), unless
   `--no-cgroups` or not Linux.
4. Refuse units whose limits cannot be applied: `cgroup_controller FILE`.
5. Prepare sash units: `TOKEN FILE` per refused sash unit (see
   [operations](operations.md#sash-services)).
6. Plan the graph (`cycle`, `missing_needs`, `missing_after`, `boot_needs`,
   `edge_empty`; exit 2), clean sash mounts left by an earlier instance
   (`sash_mount_leftover SERVICE DIR`), bind the socket (`socket_perm`,
   `socket_busy`, `socket_exists`, `socket_group`; exit 2).
7. With cgroups: `cgroup_root_unprotected ROOT` when no controller is enabled
   below the root; `cgroup_leftover NAME.service` for each cgroup an earlier
   instance left (a cgroup that will not empty is `cgroup_stuck`, exit 2).
8. Open the journal when `--log-dir` is given (`journal_unavailable TOKEN`
   when it cannot be; the start goes on).
9. Boot. A boot error is printed as its token; without `--boot-strict` the
   supervisor keeps running. Every 200 ms afterwards it reconciles
   dependencies: a running unit whose `needs` provider is no longer ready is
   stopped and marked `blocked`, and is started again when the provider is
   ready (in dependency order). A unit an operator stopped is not desired and
   stays stopped.

Exit status: 0 after a normal stop by signal; 1 when strict boot failed or the
socket server failed; 2 when startup was refused.

## sahinit plan

```text
sahinit plan --dir DIR
```

Loads the catalog exactly as `supervise` does (without opening cgroups,
reading sash keys or running `sash --describe`), plans the boot waves and
prints one wave per line on stdout: the unit names of that wave, sorted,
separated by spaces. Units with `"boot": false` are not printed.

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--dir` | path | required | The unit directory. |

stderr: `TOKEN FILE` for each refused unit file, then `cgroup_trusted FILE`
for each unit that is [cgroup-trusted](security.md#the-cgroup_trusted-boundary).
Exit 0 with a plan; exit 2 with a usage error or a catalog or graph refusal
(the token is printed).

## sahinit ctl

```text
sahinit ctl --socket PATH status [NAME]
sahinit ctl --socket PATH diagnostics|explain|start|stop|restart|reload|check NAME
sahinit ctl --socket PATH --dir DIR diff|apply
sahinit ctl --socket PATH rollback|activate
```

Sends one framed JSON request (`{"op":OP,"name":NAME}`, with `"arg":DIR` for
`diff` and `apply`) to a running supervisor and prints the JSON response on
stdout.

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--socket` | path | required | The supervisor's control socket. |
| `--dir` | path | none | Required by `diff` and `apply`, refused by every other operation. An absolute unit directory, read by the supervisor (`catalog_path` when relative). |

| Operation | Name | Effect |
| --- | --- | --- |
| `status` | optional | Status rows for every service, or one. |
| `diagnostics` | required | Output tails, recent events and the last exit of one service. |
| `start` | required | Start a stopped, failed or exited service. A oneshot answers `arg_required` (see below). |
| `stop` | required | Stop a service: SIGTERM, then SIGKILL after `timeout`. A stopped or exited service stays as it is; a failed one with no process becomes `stopped`. |
| `restart` | required | Stop, then start. |
| `reload` | required | Run a sash unit's `reload` entry. |
| `check` | required | Run a sash unit's `check` entry, read-only. |
| `explain` | required | `{name, desired, state, reason, blocked_by}`: why a unit is not running. `blocked_by` lists `needs` providers that are not ready; `reason` is the last error, or `administratively_stopped` for a unit an operator stopped. |
| `diff` | none (`--dir`) | **Root only.** Load and plan the catalog in DIR exactly as `validate` does and answer `{added, removed, changed, affected}` against the running catalog; changes nothing. `affected` adds every unit that transitively `needs` a changed one. |
| `apply` | none (`--dir`) | **Root only.** Replace the running catalog with DIR's: stop the affected units (dependents first), start the affected units that are desired (in dependency order). Unaffected units keep their processes, output and restart budgets. A failed replacement restores the old catalog (`apply_rolled_back`, or `rollback_failed`). Refused with a deployment (`signed_activation_required`), with sash units in either catalog (`catalog_sash`), while another change runs (`busy`), and before the boot waves end
(`boot_in_progress`). Not written to disk: a restarted supervisor reads `--dir` again. |
| `rollback` | none | **Root only.** Apply the catalog that the last `apply` replaced (`no_previous_catalog` when none), with its desired states. Refused with a deployment (`new_policy_required`) and before the boot waves end (`boot_in_progress`). |
| `activate` | none | **Root only.** With `--deployment-root`: verify the pending generation, check it is fresh, admit every unit, apply it as `apply` does, then make it active on disk (see [deployments](../deployments.md)). `deployment_not_configured` without a deployment; `boot_in_progress` until the boot waves end. |

`diff`, `apply`, `rollback` and `activate` are refused with `root_required`
unless the peer's effective uid is 0, even when `--uid` allows that peer
`status`, `start` and `stop`.

Exit status: 0 when the response says `"ok":true`; 1 when it says
`"ok":false` (the response is still printed), or when connecting (5 s
timeout), writing or reading fails (prints `failed`); 2 for usage errors and
`unknown_op` (an operation not in the table). The connection deadline is
11 minutes, enough for the longest stop plus the longest readiness wait.

The socket protocol also has `oneshot` with an `arg` field, which `ctl` does
not expose; see [the control protocol](config-files.md#control-protocol).

Errors in the response (`"error"`): `uid_denied`, `peer_supervised`, `root_required`, `busy`,
`not_found`, `arg_required`, `unknown_op`, `frame_size`, `failed`, and any
start, stop or sash token, for example `needs_failed`, `needs_not_ready`,
`timeout`, `cgroup_stuck`, `sash_grant_revoked`, `not_sash`, `no_entry`,
`not_running`, `unhealthy`. See [codes](codes.md).

## sahinit validate

```text
sahinit validate --dir DIR
```

Loads the catalog in DIR as `supervise` does (without cgroups or sash
`--describe`) and plans it. Prints one JSON line
`{valid, error, refused, waves}`: `refused` maps each refused file to its
token (any refused file makes the catalog invalid, `catalog_refused`), `waves`
are the boot waves. Exit 0 when valid, 1 when not, 2 for a usage error.

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--dir` | path | required | The candidate unit directory. |

## sahinit deploy

```text
sahinit deploy stage --root DIR --trust FILE --bundle DIR --manifest FILE
                     --document FILE [--trust-system-clock]
sahinit deploy status|bootstrap --root DIR --trust FILE [--trust-system-clock]
```

Stages and inspects verified deployment generations; see
[deployments](../deployments.md) for the bundle format.

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--root` | path | required | Absolute and clean (`deployment_path`). Created 0700 when missing; must pass the trusted walk and have no group or other access (`deployment_perm`). |
| `--trust` | path | required | The boot-policy trust file. |
| `--trust-system-clock` | bool | false | Accept the system clock as the time anchor; without it an expiring policy is refused (`policy_clock_uncertain`). |
| `--bundle` | path | `stage` only (required) | The candidate bundle directory. |
| `--manifest` | path | `stage` only (required) | The manifest; its exact bytes must hash to the policy's `catalog_sha256`. At most 256 KiB (`manifest_read`). |
| `--document` | path | `stage` only (required) | The signed policy envelope. |

| Operation | Output | Effect |
| --- | --- | --- |
| `stage` | `{"pending":ID}` | Verify the policy and every file, copy the bundle into a new private generation, cache the policy and make it the pending generation. Staging the same generation again is idempotent. |
| `status` | `{"active","pending","previous"}` | Show the pointers. |
| `bootstrap` | `{"active":ID}` | First installation only: with no active generation, verify and admit the pending one and make it active (`bootstrap_refused` otherwise). Later changes use `ctl activate`. |

Exit 1 with the token on stderr for a refusal; 2 for a usage error.

## sahinit logs

```text
sahinit logs [--dir DIR] [--unit NAME] [--boot ID] [--since SEQUENCE]
             [--contains TEXT] [--follow]
```

Prints journal records (one JSON object per line:
`{sequence, boot_id, time, unit, stream, data}`, with `data` base64 encoded)
of the stdout and stderr streams. See [the journal](operations.md#journal).

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--dir` | path | `/var/log/sahinit` | The journal directory (the supervisor's `--log-dir`). |
| `--unit` | string | all | Only this unit (`sahinit` for the supervisor's own events). |
| `--boot` | string | all | Only this boot ID (`/proc/sys/kernel/random/boot_id` of the writing boot). |
| `--since` | uint64 | 0 | Only records with a larger sequence. |
| `--contains` | string | none | Only records whose data or event contains TEXT. |
| `--follow` | bool | false | Keep polling (every 250 ms) until SIGINT or SIGTERM. |

Exit 1 with `journal_read` when the journal cannot be read (missing, wrong
owner or mode, a malformed complete record); 2 for a usage error. Reading
needs the journal's owner (root under PID 1): the files are 0600.

## sahinit events

```text
sahinit events [--dir DIR] [--unit NAME] [--boot ID] [--since SEQUENCE]
               [--contains TEXT] [--follow]
```

As `logs`, for the `event` stream: the lifecycle events of
`ctl diagnostics` (`{"sequence","time","kind","pid","code","exit"}` in `event`) and the
supervisor's `supervisor_started`.

## sahinit host

```text
sahinit host device-wait --path DEVICE [--timeout DURATION]
sahinit host notify-adapter [--watchdog DURATION] -- PROGRAM [ARG]...
```

Linux-only helpers meant to be a unit's `exec` (off Linux they print
`host helpers require Linux` and exit 1).

`device-wait` polls every 50 ms until DEVICE (absolute) exists as a device
node, then exits 0; after `--timeout` (default `30s`, at most `5m`) it prints
`device_timeout` and exits 1. Use it as a oneshot that other units `need`.

`notify-adapter` runs PROGRAM as its child with `NOTIFY_SOCKET` set to a
private datagram socket and, with `--watchdog` (at most `5m`),
`WATCHDOG_USEC`. It accepts only `READY=1` and `WATCHDOG=1`, and only from its
direct child's credentials (`SO_PASSCRED`); it writes one byte to the unit's
notify pipe (fd 3, `SAHINIT_READY_FD=3`, else `notify_pipe_missing`) for
readiness and one per heartbeat after it. It forwards SIGTERM, SIGINT and
SIGHUP to the child and exits with its status. There is no `MAINPID`,
`FDSTORE`, `EXTEND_TIMEOUT` or barrier support: run the program in the
foreground. Use it with `"ready": "notify"` and a matching unit `watchdog`.

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--path` | path | required (`device-wait`) | Absolute device path. |
| `--timeout` | duration | `30s` | `device-wait`: more than 0, at most `5m`. |
| `--watchdog` | duration | `0` (none) | `notify-adapter`: from 0 to `5m`; the interval exported as `WATCHDOG_USEC`. |

## sahinit policy

```text
sahinit policy verify|cache|status|floor-install|floor-show --trust FILE
               [--document FILE] [--cache DIR] [--trust-system-clock]
sahinit policy refresh --trust FILE --cache DIR --endpoint HTTPS_URL
               --credential FILE [--trust-system-clock] [--once]
```

Verifies, caches and inspects signed boot-policy metadata. **Metadata only:**
nothing here admits or blocks a unit; every report carries
`"enforcement":"metadata_only"`. Formats are in
[files](config-files.md#boot-policy-files) and [boot policy](../boot-policy.md).

| Flag | Type | Default | Used by |
| --- | --- | --- | --- |
| `--trust` | path | required | All. The local trust file: regular, not a symlink, owned by root or the effective uid, not group- or other-writable (`policy_bad_trust`), at most 64 KiB (`policy_read_failed`). |
| `--document` | path | none | Required by `verify`, `cache`, `floor-install`; refused by `status`, `floor-show`, `refresh`. Regular file, not a symlink, at most 384 KiB. |
| `--cache` | dir | none | Required by `cache`, `status`, `floor-install`, `floor-show`, `refresh`; refused by `verify`. Owned by the effective uid with no group or other access (`policy_store_failed`). |
| `--trust-system-clock` | bool | false | All. Asserts that the system clock is already trustworthy. Without it, `renew` policies report `clock_uncertain`. `never` policies and floors do not read the clock. |
| `--endpoint` | URL | none | `refresh` only (required). `https://` with a host and no user info, query or fragment (`policy_refresh_config`). |
| `--credential` | path | none | `refresh` only (required). Bearer credential file (`policy_refresh_credential`). |
| `--once` | bool | false | `refresh` only. One attempt, then exit. |

Any flag combination the "Used by" column does not allow is a usage error (exit 2).

| Operation | Output on stdout (one JSON line) | Exit 1 when |
| --- | --- | --- |
| `verify` | `{verified, enforcement, state, error, sequence, catalog_generation, policy_sha256, expires_at, offline_until, lifetime}` | the document is refused, or is not normally valid now (`policy_expired`, `policy_not_yet_valid`, `policy_clock_uncertain`, ...; the report is still printed with `error`). |
| `cache` | the same report | the document is refused or the store refuses it. |
| `status` | the same report plus `floor_min_sequence` | the cache or floor is refused; a cached policy below the floor prints `{"state":"revoked","error":"policy_revoked",...}` and exits 1. |
| `floor-install` | `{verified, enforcement, min_sequence, issued_at, floor_sha256}` | the floor is refused (`policy_floor_rollback`, `policy_floor_conflict`, ...). |
| `floor-show` | the same floor report | no floor (`policy_floor_missing`) or a refused floor. |
| `refresh` | one JSON event per line | see [the renewal worker](../boot-policy.md#renewal-worker-renew-mode-only). |

`refresh` exits 0 when stopped by SIGINT or SIGTERM and when the host does not
renew (one `not_renewing` event). It exits 1 on a refusal (token on stderr) or
when writing stdout fails. With `--once` it prints one `attempt` event (or
`not_renewing`) and exits 0, or prints the token and exits 1.

## sahinit sash

```text
sahinit sash floor-install --dir DIR --fleet-pub PATH FILE
sahinit sash floor-show --dir DIR --fleet-pub PATH [SERVICE]
```

Installs and shows signed per-service sash floors (`sahinit-sash-floor/1`).

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--dir` | dir | required | The sash state directory, the same as `supervise --sash-floor-dir`. A directory, not a symlink, owned by the **effective uid** with no group or other access (`sash_floor_store_failed`). Run the command as the uid the supervisor runs as (root under PID 1). |
| `--fleet-pub` | path | required | The fleet public key: reached by the trusted walk, a regular file owned by root or the effective uid, not group- or other-writable, holding 32 raw bytes or 64 hex digits with an optional newline (`sash_fleet_key`). |

`floor-install FILE` verifies FILE against the key and installs it. It prints
`{"service","min_serial","issued_at","digest"}`. Refusals:
`sash_floor_bad_shape`, `sash_floor_bad_signature`, `sash_floor_rollback`,
`sash_floor_conflict`, `sash_floor_busy`, `sash_floor_store_failed`, and
`failed` when FILE cannot be read. Installing the same floor again succeeds.

`floor-show [SERVICE]` prints one line per service (all services with a floor
file when SERVICE is omitted). A service without a floor prints
`sash_floor_missing SERVICE` on stderr; a floor that does not verify prints
`sash_floor_store_failed SERVICE`. Exit 1 if any line failed.

A usage error, including an operation other than these two, prints the sash
usage text and exits 2.

## sahinit migrate

```text
sahinit migrate --from FORMAT --source DIR [--out NEW_DIR] [--boot]
```

Converts a standalone, exported service catalog. It never runs source scripts
or touches the running init system. See [migration](../migration.md).

| Flag | Type | Default | Constraints |
| --- | --- | --- | --- |
| `--from` | string | required | `systemd`, `daemontools` or `openrc`. |
| `--source` | dir | required | A real directory (not a symlink) with 1 to 256 entries. Source files are regular files of at most 64 KiB without NUL bytes. |
| `--out` | dir | none (report only) | A **new** directory: it is created with mode 0700 and must not exist. Unit files are written 0600. Nothing is written when the report has a blocker. |
| `--boot` | bool | false | Mark every converted unit `"boot": true`, except daemontools services with a `down` file. |

stdout: the JSON report `{format, units, diagnostics, written}`; each
diagnostic is `{source, line, severity, message}`. Exit 0: converted (and
written with `--out`). Exit 1: at least one diagnostic with severity `error`
(a blocker); nothing written. Exit 2: usage, an unknown format, an unreadable
source or a write failure. Unlike the other commands, `migrate` prints plain
English errors (for example `unknown source format "x"`), which may include
paths.

## sahinit apply (internal)

`apply` is the sandbox helper: the supervisor re-executes its own binary as
`sahinit apply ... -- ARGV` with a spec, a status pipe and the checked
executable on inherited file descriptors. It joins the cgroup, applies the
sandbox and execs the target. It has no flags of its own. Run by hand without
those descriptors it exits 2 and does nothing. Do not call it.
