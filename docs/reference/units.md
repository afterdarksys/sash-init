# Unit reference

A unit is one JSON file in the unit directory. This page is derived from
`internal/unit` (`unit.go`, `execution.go`, `limits.go`, `sash.go`),
`internal/jsonobj` and `internal/graph`. There are two kinds of unit:

- an **exec unit**, which names a program in `exec`;
- a **sash unit**, which names a sash service script in `sash` (see
  [sash units](#sash-units)).

This is unit schema `sahinit-unit/1` (`sahinit version` lists it in
`unit_schemas`). Unit files carry no version field; a change that would make
a valid unit mean something else, or be refused, gets a new name.

## The unit directory

- The directory must not be a symlink (`symlink`), must be a directory
  (`failed`), and must be owned by root or by the supervisor's effective uid
  and not writable by group or other (`unit_perm`). Any of these refuses the
  whole catalog.
- Every entry must be a regular `NAME.json` file. A directory, a dot-file or a
  file without `.json` refuses the catalog (`stray_file`); a symlink refuses
  it (`symlink`). An empty directory is `empty`. More than 256 entries is
  `too_many`.
- Each file must be at most 64 KiB (`file_size`), and owned by root or the
  supervisor's uid and not group- or other-writable. A file failing the owner
  and mode rule is **left out** and reported as `unit_perm FILE`; the rest of
  the catalog loads.
- Any other problem in a file (a parse or validation error below) refuses the
  **whole catalog** with that token. Only `unit_perm`, the file checks of
  `sash_file_perm` and `sash_grant_perm` (a relative `sash.file` or
  `sash.grant` is a parse error and refuses the catalog), and the later per-unit checks (`cgroup_controller` and the
  sash load checks) leave one unit out.
- Two files whose `name` is the same is `duplicate_field`. If every file is
  left out, the result is `empty`.

## Decoding rules

Every JSON object in a unit (the unit, `execution`, `sandbox`, `sash`) is
decoded strictly:

- one object, nothing after it (`failed`);
- an unknown key is `unknown_field`; a repeated key is `duplicate_field`;
- `null` for a value, a wrong JSON type, or a number that does not fit the
  field is `failed`.
  (except `restart`, `timeout` and the limits, which report
  `restart_invalid`, `timeout_range` and `limit_invalid`).

## Exec unit fields

| Field | Type | Required | Default | Rules (token on failure) |
| --- | --- | --- | --- | --- |
| `name` | string | yes | | `^[a-z][a-z0-9-]{0,62}$` (`name_invalid`), and equal to the file name without `.json` (`name_mismatch`). |
| `exec` | array of strings | yes | | 1 to 32 entries, each at most 256 bytes, no NUL (`failed`). `exec[0]` is absolute and clean (`exec_relative`). See [executables](#executables). |
| `type` | string | yes | | `simple` or `oneshot` (`type_invalid`). |
| `ready` | string | yes | | `simple`: `exec` or `notify`. `oneshot`: `exit`. Anything else is `ready_invalid`. |
| `restart` | string | no | `no` | `no`, `on-failure` or `always` (`restart_invalid`). A oneshot must use `no` (`restart_invalid`). |
| `needs` | array of strings | no | none | At most 64, unique (`duplicate_field`), non-empty (`edge_empty`). Each must name a unit in the catalog (`missing_needs`). See [dependencies](#dependencies). |
| `after` | array of strings | no | none | As `needs` (`missing_after` for an absent unit). |
| `wants` | array of strings | no | none | As `needs`, but an absent unit is ignored. |
| `timeout` | string | no | `5s` | A Go duration (`500ms`, `30s`, `2m`), more than 0 and at most `5m` (`timeout_range`). |
| `boot` | bool | no | `true` for `simple`, `false` for `oneshot` | Whether boot starts it. |
| `essential` | bool | no | the value of `boot` | Only meaningful with `supervise --boot-strict` (PID 1): an essential unit's failure sends the host to recovery. `true` needs `"boot": true` (`essential_requires_boot`). Set `false` to let a boot unit fail alone. See [strict boot](cli.md#sahinit-supervise). |
| `restart_delay` | string | no | `100ms` | A Go duration from `10ms` to `5m` (`restart_delay_invalid`): the first automatic restart's delay. |
| `restart_max_delay` | string | no | `30s` | From `10ms` to `5m`, not below `restart_delay` (`restart_delay_invalid`): the cap of the growing delay. |
| `watchdog` | string | no | none | From `100ms` to `5m`; needs `"ready": "notify"` (`watchdog_invalid`). See [watchdog](#watchdog). |
| `execution` | object | no | supervisor identity, `/`, environment with only the default `PATH` | See [execution](#execution). |
| `sandbox` | object | no | no sandbox | See [sandbox](#sandbox). Requires a non-root `execution.uid` (`sandbox_root`). |
| `memory_max` | string | no | no limit | See [limits](#limits). |
| `cpu_max` | string | no | no limit | See [limits](#limits). |
| `pids_max` | integer | no | no limit | See [limits](#limits). |

There are no `stop`, `environment_file`, `user` (by name) or `working_directory`
fields: stop is always SIGTERM to the process group, then SIGKILL (see
[lifecycle](#lifecycle)), and identity and directory live in `execution`.

### Minimal and full examples

```json
{ "name": "web", "exec": ["/usr/local/bin/web", "--port", "8080"], "type": "simple", "ready": "exec" }
```

```json
{
  "name": "worker",
  "exec": ["/usr/local/bin/worker"],
  "type": "simple",
  "ready": "notify",
  "restart": "on-failure",
  "needs": ["db"],
  "after": ["net"],
  "wants": ["metrics"],
  "timeout": "30s",
  "execution": {
    "uid": 1000, "gid": 1000, "groups": [27],
    "directory": "/var/lib/worker",
    "environment": ["APP_MODE=production"]
  },
  "sandbox": {
    "no_new_privs": true,
    "read_only_paths": ["/usr", "/etc/ssl/certs"],
    "read_write_paths": ["/var/lib/worker"],
    "caps": []
  },
  "memory_max": "256M",
  "cpu_max": "50000 100000",
  "pids_max": 64
}
```

```json
{ "name": "migrate-db", "exec": ["/usr/local/bin/migrate"], "type": "oneshot", "ready": "exit", "boot": true }
```

## Types, readiness and restart

| `type` / `ready` | Started when | Ends |
| --- | --- | --- |
| `simple` / `exec` | at once: the process was started | when the main process exits |
| `simple` / `notify` | the process writes at least one byte to fd 3 (`SAHINIT_READY_FD=3`) within `timeout` | when the main process exits |
| `oneshot` / `exit` | the process exits 0 within `timeout`; the state is then `exited` | at exit |

- Not ready in time: the process group is killed, the start fails with
  `timeout`, and it is not restarted.
- A oneshot that exits non-zero is `failed`.
- `restart` applies to a `simple` unit whose process exits after it was
  ready (or at any time with `ready: exec`): `always` restarts after any exit,
  `on-failure` after a non-zero exit or a signal. The n-th consecutive
  crash waits `restart_delay` × 2^(n−1), capped at `restart_max_delay`,
  scaled by a random 80–100 % (so never above the cap); during the wait the
  state is `starting`. Two limits end a crash loop with `failed` and
  `restart_limit`: more than 5 restarts in any 30 s, and more than 5
  consecutive crashes, counting every exit until a run has stayed ready for
  the stable period (10 s, or `timeout` when longer), however long the
  delays. A run that stayed ready that long resets the crash count; a manual
  start resets both. A unit whose `needs` provider is not ready when the
  delay ends becomes `blocked`. In strict boot, an essential unit that has
  crashed and is still waiting out its delay when the boot waves end counts
  as not ready, so the boot fails then rather than waiting.
- A stop is never followed by a restart.

### Watchdog

A `"ready": "notify"` unit with `watchdog` keeps its notify pipe (fd 3) open
after the readiness byte and must write another byte within every interval.
End of file on the pipe or a missed interval kills the process group; the
unit's `last_error` and event are `watchdog`, and its restart policy applies.
For a program that speaks sd_notify, run it through
[`sahinit host notify-adapter`](cli.md#sahinit-host) with the same interval.
This is a service watchdog, not a hardware (`/dev/watchdog`) one.

### Lifecycle

States: `stopped`, `starting`, `running`, `stopping`, `exited` (a finished
oneshot), `failed`, `blocked` (desired, waiting for a `needs` provider). Stop sends SIGTERM to the process group, waits up to
`timeout`, then SIGKILLs. With cgroups, whenever the main process exits for any
reason everything left in the service's cgroup is killed, and the service has
ended only when the cgroup is empty; otherwise it fails with `cgroup_stuck`.
A stop can therefore take up to twice `timeout`.

A oneshot started at boot runs `exec` as written. After boot, a oneshot runs
only through the socket's `oneshot` operation with one argument appended to
`exec` (`[A-Za-z0-9._-]{1,64}` without `..`, else `arg_rejected`); `ctl start`
answers `arg_required`. Arguments are never logged.

## Dependencies

- `needs`: the unit starts only when each named unit is running and ready, or
  has exited successfully (a oneshot). A failed one makes the start fail with
  `needs_failed`, one not yet ready with `needs_not_ready`; either way the
  unit becomes `blocked`. The supervisor checks every 200 ms: a running unit
  whose provider is no longer ready is stopped and `blocked` (dependents
  first), and a `blocked` unit starts once its providers are ready (providers
  first). A unit an operator stopped is not desired and is left alone.
- `after`: ordering only; no requirement.
- `wants`: ordering when the named unit exists; ignored when it does not.
- The whole catalog, including non-boot units, must be acyclic (`cycle`).
- A boot unit may not `needs` a non-boot unit (`boot_needs`).
- Boot runs waves in order; units in one wave start in parallel. A failed
  unit does not stop later waves. In strict host boot an essential unit's
  failure then enters recovery (see `essential`).
- Shutdown stops every unit, including ones started by hand, in reverse wave
  order; units in one wave stop in parallel.

## Executables

`exec[0]` is resolved once at load, following symlinks one component at a time
(for example Debian's `/bin/sh -> dash`), and the resolved file is what runs;
`argv[0]` is passed as written.

- Every directory the walk passes through, from `/`, must be owned by root or
  the supervisor's uid and not group- or other-writable, except a sticky
  directory such as `/tmp` (`exec_perm`). A link inside a directory someone
  else can write is refused.
- The resolved file must be a regular file with an execute bit
  (`exec_not_file`), owned by root or the supervisor's uid and not group- or
  other-writable (`exec_perm`). A missing component or more than 40 links is
  `exec_not_file`.
- If it does not resolve at load the unit still loads; the check is repeated
  at every launch, so a program installed later is still checked.
- On Linux the checked file is opened and executed through that file
  descriptor, so the file checked is the file run.
- A `#!` script's interpreter must be an absolute path that passes the same
  checks and is not itself a script. `#!/usr/bin/env ...`, `#!/bin/busybox
  env ...`, a relative interpreter or a `#!` line longer than 256 bytes is
  `exec_interp`. The script is passed to its interpreter as `/proc/self/fd/4`.

## Execution

```json
"execution": { "uid": 1000, "gid": 1000, "groups": [], "directory": "/srv/app", "environment": ["KEY=value"] }
```

| Field | Type | Default | Rules |
| --- | --- | --- | --- |
| `uid` | integer | the supervisor's uid | 0 to 4294967294. Given together with `gid` or not at all. |
| `gid` | integer | the supervisor's gid | As `uid`. |
| `groups` | array of integers | `[]` with an identity | Only with `uid`/`gid`; at most 64, unique, each below 4294967295. An explicit identity always replaces the supplementary groups. |
| `directory` | string | `/` | Absolute, clean, at most 4096 bytes, no NUL. Must exist and be reachable by the identity at launch. |
| `environment` | array of strings | `[]` | `KEY=value` literals; at most 128 entries and 16 KiB in total; `KEY` matches `^[A-Za-z_][A-Za-z0-9_]*$`, is unique and does not start with `SAHINIT_`. |

Every rule violation is `execution_invalid` (a wrong JSON type or an out-of-range number is `failed`). IDs are numeric only: there is no
name-service lookup for exec units. Without `uid`/`gid` the service runs as
the supervisor (root under PID 1). An unprivileged supervisor that cannot set
the requested credentials fails the start. The environment rules are in
[environment](environment.md).

## Sandbox

```json
"sandbox": { "no_new_privs": true, "read_only_paths": ["/usr"], "read_write_paths": ["/var/lib/app"], "caps": [] }
```

Linux only (`sandbox_unsupported` elsewhere). The presence of the object turns
the sandbox on; every key is optional.

| Field | Type | Default | Rules |
| --- | --- | --- | --- |
| `no_new_privs` | bool | `true` | Always applied; an explicit `false` is `sandbox_privs`. |
| `read_only_paths` | array of strings | `[]` | Paths the service may read beneath. |
| `read_write_paths` | array of strings | `[]` | Paths the service may read and write beneath: create, write, truncate, rename within one directory and remove regular files and directories. Not sockets, FIFOs, device nodes or symlinks, nor a rename or hard link into another directory (below). |
| `socket_paths` | array of strings | `[]` | Directories in which the service may also create (bind) Unix sockets. Each must be at or beneath a `read_write_paths` entry (`sandbox_socket`). |
| `caps` | array of strings | `[]` | Capabilities the service holds, from the allowlist `net_bind_service`, `setuid`, `setgid`. Any other real capability is `sandbox_cap_denied`; an unknown name is `sandbox_cap`. |
| `setuid_to` | array of integers | none | Required with `setuid`, refused without it: the uids the service may switch to besides its own. 1 to 64, unique, from 1 to 4294967294 (`sandbox_ids`, also for any other value or type); not the supervisor's uid (`sandbox_ids` at start). |
| `setgid_to` | array of integers | none | The same for `setgid` and gids. |

- The unit must set a non-root `execution.uid` (`sandbox_root`); the helper
  also refuses to apply a sandbox while it runs as uid 0.
- Paths: absolute, clean, at most 4096 bytes, no NUL (`sandbox_path`); at most
  64 in total across the three lists, unique across the read-only and
  read-write lists (`sandbox_overlap`) and within each list
  (`duplicate_field`). Each is
  resolved once at load through the trusted walk (so `/lib` becomes `/usr/lib`
  on merged-/usr); a path that does not resolve is kept as written. At launch
  each path is opened without following any symlink: a link or a missing path
  is `sandbox_path`.
- Landlock: the ABI is detected (1 to 5 are known) and only the rights it
  knows are handled. No Landlock is `landlock_unavailable`; a right the ABI
  lacks is `landlock_abi`. Everything outside the listed paths is denied for
  file access. Network access is **not** confined.
- Special files: no list grants FIFOs, character or block devices or
  symlinks; they are EACCES everywhere. A rename or hard link into a
  different directory is EXDEV, even inside one read_write path (Landlock
  REFER is not granted); within one directory it works. Device ioctls are
  refused (ABI 5). See [unit sockets](../design/unit-sockets-1.md).
- `socket_paths`: each entry grants only the creation of Unix sockets
  beneath it (Landlock MAKE_SOCK); the read_write path it lies in grants the
  rest (removing a stale socket, for one). The rule is checked by path
  components (`/run/ab` is not beneath `/run/a`), as written, again after
  links are resolved at load, and in the helper (`sandbox_socket`). At launch
  each entry is opened without following links and must be a directory
  (`sandbox_path`). An entry equal to its read_write path is the usual case:
  `"read_write_paths": ["/run/sinetd"], "socket_paths": ["/run/sinetd"]`.
  Allowed for exec, sash and deployment units. It does **not** limit which
  sockets the service may connect to: Landlock does not confine `connect`.
  A shared writable directory such as `/tmp` as a socket path lets the
  service answer for any socket name there before its real server binds it.
- Capabilities (see [unit capabilities](../design/unit-caps-1.md)): with
  `caps` empty the service holds no capability (effective, permitted,
  inheritable and ambient sets empty). With `caps` set, the service holds
  exactly those capabilities in its effective, permitted, inheritable and
  ambient sets, and its bounding set is cut to them, so it can never regain
  another. The supervisor must be root (`sandbox_cap` otherwise). The helper
  checks the whole state before exec; any difference is `sandbox_cap` and
  nothing runs. Exec units from `--dir` only: a sash unit is `sash_caps`, a
  deployment unit `deployment_caps`. Listing `setuid` also makes the unit
  [cgroup-trusted](security.md#the-cgroup_trusted-boundary).
- **The caps are inherited.** They are ambient, so every program the service
  executes gets them too, and keeps them after a `setuid` from one non-zero
  uid to another (the kernel clears capabilities on a uid change only when
  leaving uid 0). Clearing the service's ambient and inheritable sets
  (`prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)` and a `capset` with an
  empty inheritable set, on every thread; in Go `syscall.AllThreadsSyscall`)
  is **not enough on its own**. It stops a program without file capabilities
  from inheriting anything, but the service still holds its permitted set,
  and a program **with file capabilities** (`setcap`; `newuidmap` carries
  `cap_setuid=ep` on some distributions) that the service, or a child that
  still holds the permitted set, execs directly gets every capability it
  names that the parent holds in its permitted set, permitted and, with the
  file's effective bit, effective: no_new_privs limits it to the parent's
  permitted set, not to nothing. A file capability with the effective bit
  (`=ep`) outside the unit's caps makes that exec fail with EPERM; one
  without it (`=p`) runs without it (the bounding set is cut to the caps, in
  every process of the unit). So a child that must hold nothing has to exec with
  an empty permitted set: drop the permitted and effective sets (with
  `capset`) in the forked child before its exec, or exec it through a small
  program without file capabilities, which starts with nothing and so passes
  nothing on. `PR_SET_KEEPCAPS` plays no part: it matters only when leaving
  uid 0, which the id filter refuses. Whatever the service does, its
  children stay under no_new_privs, Landlock and, with `setuid` or `setgid`,
  the id filter.
- **`setuid` and `setgid`** come with the id filter, a seccomp filter
  installed after `no_new_privs`: `setuid`, `setreuid`, `setresuid` and
  `setfsuid` may only name the unit's own uid or a `setuid_to` uid (likewise
  for gids and `setgid_to`), `setgroups` may only clear the list, and
  `unshare` or `clone` with `CLONE_NEWUSER`, and `setns`, are refused
  (EPERM); `clone3` is ENOSYS; a foreign architecture or an x32 syscall kills the process. It is
  inherited by every child and cannot be removed. Linux amd64 and arm64 only
  (`seccomp_unavailable`). Such a unit may not have `/`, `/proc` or a path
  under `/proc` in `read_write_paths` (`sandbox_proc`): it could write the
  id map of a user namespace another process created. A unit with any caps
  may not run with gid 0 or have 0 in its groups, nor the supervisor's gid
  (`sandbox_ids`). Even so the service can act as **every listed
  id**: its files inside the Landlock domain, `chmod` of its files anywhere
  (Landlock does not restrict chmod), its processes, and every Unix socket
  that trusts that id. It can also forge the uid and gid in
  `SCM_CREDENTIALS`, 0 included; the filter cannot see that.
- `net_bind_service` lets the service bind any port below 1024 on any
  address, including one another daemon has not bound yet.
- The status `sandbox` field reports what was applied, for example
  `no_new_privs,landlock_v3,caps`, with `,id_filter` added for a unit
  holding `setuid` or `setgid`, and only while a process runs; an
  unsandboxed unit reports `none`.
- The helper's set-up handshake has a deadline (`sandbox_timeout`); a kernel
  without `openat2` (before Linux 5.6) is `openat2_unavailable`.

## Limits

Written into the service's cgroup before the process starts. Needs cgroups.

| Field | Type | Accepted | Writes |
| --- | --- | --- | --- |
| `memory_max` | string | `^[1-9][0-9]{0,15}[KMG]?$`: bytes, or binary K/M/G; at least `1M`, at most 2^50 bytes | `memory.max`, and `memory.swap.max` = 0 where it exists |
| `cpu_max` | string | `"QUOTA PERIOD"` in microseconds: period 1000 to 1000000, quota from 1000 to 1024 periods | `cpu.max` |
| `pids_max` | integer | 1 to 4194304 | `pids.max` |

A malformed value is `limit_invalid` and refuses the catalog. A limit whose
controller the cgroup root does not offer, or any limit with `--no-cgroups` or
off Linux, leaves the unit out as `cgroup_controller FILE` (in strict boot:
`boot_refused`). I/O limits, slices and delegating a cgroup to a service are
not supported.

## Sash units

A sash unit runs a sash service script through `sash --session`. Its ordering,
readiness, stop and restart come from `sash --describe`, and every privileged
action the script asks for is checked against its signed grant. See
[operations](operations.md#sash-services) for set-up and
[the sash design](../design/sash-services-1.md) for the protocol.

```json
{
  "name": "app",
  "sash": { "file": "/etc/sahinit/services/app.sash", "grant": "/etc/sahinit/grants/app.grant" },
  "execution": { "uid": 990, "gid": 990 },
  "sandbox": { "read_only_paths": ["/usr", "/etc/sahinit/services"], "read_write_paths": ["/srv/app"] }
}
```

| Field | Type | Required | Default | Rules (token) |
| --- | --- | --- | --- | --- |
| `name` | string | yes | | As for exec units; must also equal the describe output's name (`sash_name_mismatch`). |
| `sash.file` | string | yes | | Absolute, clean path to the service script (`sash_file_perm`). At load and before every start: resolved by the trusted walk, a regular file owned by root or the supervisor's uid, not group- or other-writable, no setuid, setgid or sticky bit (`sash_file_perm`). |
| `sash.grant` | string | yes | | Absolute path to the signed `sash/2` grant (`sash_grant_perm`). The same checks, and mode exactly 0600 (`sash_grant_perm`). |
| `execution.uid`, `execution.gid` | integers | yes | | Non-zero (`sash_root`). They must equal what the describe output's `user` and `group` resolve to through the system user and group databases (`sash_identity_mismatch`). |
| `sandbox` | object | yes | | Required (`sash_sandbox`); rules as above, but `caps` must be empty (`sash_caps`). The unit must not be cgroup-trusted (`sash_cgroup_trusted`). |
| `restart` | string | no | from describe | If set, must equal describe's policy (`no` equals sash's `never`) (`sash_lifecycle_mismatch`). |
| `needs`, `after`, `wants` | arrays | no | from describe | If set, must be the same set as describe's `requires`, `after`, `wants` (`sash_order_mismatch`). |
| `boot` | bool | no | `true` | A sash boot unit is always essential in strict boot; it has no `essential` field. |
| `memory_max`, `cpu_max`, `pids_max` | | no | none | As above. |

Refused on a sash unit (`sash_unit_field`): `exec`, `type`, `ready`,
`timeout`, `essential`, `restart_delay`, `restart_max_delay`, `watchdog`,
`execution.groups`, `execution.directory`,
`execution.environment`.

`sash --describe` limits: a ready or stop timeout or a restart delay above 5
minutes, a restart burst above 5, or a restart window (`within`) shorter
than the restart delay, is `sash_lifecycle_limit`. A sash unit's restarts
also stop at `restart_limit` after its burst of consecutive crashes without
a run that stayed ready for the stable period, as for exec units. Ordering names
must be valid unit names (`sash_order_mismatch`). A non-zero exit, malformed
output or no `start`/`run` entry is `sash_describe`. `sahinit plan` does not
run describe; it checks only the unit file and the file permissions.

## Refusal tokens by field

| Token | Cause |
| --- | --- |
| `failed` | malformed JSON, `null`, a wrong type, a missing required field, too many or too long `exec` entries |
| `unknown_field`, `duplicate_field` | unknown or repeated key; repeated edge; two units with one name |
| `name_invalid`, `name_mismatch` | `name` grammar; file name differs |
| `exec_relative` | `exec[0]` not absolute and clean |
| `type_invalid`, `ready_invalid`, `restart_invalid`, `timeout_range` | the fields above |
| `essential_requires_boot`, `restart_delay_invalid`, `watchdog_invalid` | `essential`, the restart delays, `watchdog` |
| `edge_empty` | an empty dependency name |
| `execution_invalid` | any `execution` rule |
| `sandbox_root`, `sandbox_privs`, `sandbox_path`, `sandbox_overlap`, `sandbox_cap`, `sandbox_cap_denied`, `sandbox_ids`, `sandbox_proc`, `sandbox_socket` | sandbox rules |
| `limit_invalid` | a limit value |
| `sash_*` | sash unit rules above |
| `cycle`, `missing_needs`, `missing_after`, `boot_needs` | the dependency graph |

All tokens are explained in [codes](codes.md).
