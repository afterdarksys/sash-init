# Execution context and diagnostics

These features belong to the userspace supervisor. The optional Linux
[PID 1 parent](host-init.md) runs it as a child and supplies host boot/recovery.

## Unit execution context

Units may include an optional `execution` object:

```json
{
  "name": "worker",
  "exec": ["/usr/local/bin/worker"],
  "type": "simple",
  "ready": "exec",
  "restart": "on-failure",
  "execution": {
    "uid": 1000,
    "gid": 1000,
    "groups": [],
    "directory": "/var/lib/worker",
    "environment": ["APP_MODE=production", "PATH=/usr/local/bin:/usr/bin:/bin"]
  }
}
```

UID and GID must appear together and are numeric, with no name-service lookups.
Explicit identity clears inherited supplementary groups; `groups` supplies their
replacement. Groups require an explicit identity. IDs must be below 4294967295;
duplicate groups and more than 64 groups are rejected. Omitting identity preserves
the supervisor identity for compatibility. An unprivileged supervisor may be
unable to set credentials, including supplementary groups; startup then fails.

The directory defaults to `/`. A supplied directory must be an absolute, clean
path, must exist at launch, and must be accessible to the selected identity.
Environment is explicit: the supervisor's environment is never inherited by
services. The default PATH is `/usr/bin:/bin:/usr/sbin:/sbin`; an explicit PATH
replaces it. Entries are literal `KEY=value` strings, without shell expansion,
with at most 128 entries and 16 KiB total. Duplicate names, NULs, invalid names,
and the reserved `SAHINIT_` prefix are rejected. Environment files and account
name resolution are not implemented.

Context is applied before the target starts on both direct and Linux sandbox
launches. The sandbox helper itself runs as the selected identity. Sandbox path
access and requested capabilities must be available to that identity; failures
refuse startup rather than weakening the sandbox. No capability elevation is
provided by this feature. The target still receives `SAHINIT_READY_FD=3` for
notify readiness.

A unit with a `sandbox` must name a non-root `uid` (`sandbox_root`); the helper
also refuses to apply a sandbox while it runs as uid 0. The Landlock ABI is
detected and only the rights it knows are handled; a kernel without Landlock is
`landlock_unavailable`, and a grant needing a right the ABI lacks is
`landlock_abi`. The status claim names the ABI applied, for example
`no_new_privs,landlock_v3,caps`, and is reported only while a process runs.

## Cgroups

Each service runs in its own cgroup v2, `ROOT/NAME.service`. A child that
calls `setsid`, double-forks, or leaves its process group stays in it.
The child joins the cgroup before exec, through `clone3(CLONE_INTO_CGROUP)`.
On kernels without it, the child is the helper: the supervisor writes its
pid to `cgroup.procs` and only then lets it continue.
A child that cannot join does not start (`cgroup_join`).

Whenever a service's main process exits (stop, restart, crash, or a clean
exit), everything left in its cgroup is killed. `cgroup.kill` does this on
Linux 5.14 and later; older kernels freeze the cgroup, kill each member and
thaw it. The service has ended only when `cgroup.events` reports
`populated 0`. If that does not happen within the unit timeout, the service
is failed with `cgroup_stuck`. The cgroup is created fresh at each start
and removed at each end. Stop still sends SIGTERM to the process group
first; SIGKILL goes to the whole cgroup.

`supervise` uses its own cgroup as the root. It must be on the cgroup2
hierarchy at `/sys/fs/cgroup` and delegated to sahinit, which means
writable by its uid. sahinit moves itself into `ROOT/supervisor` and enables
`cpu`, `memory` and `pids` for the services where the root offers them.
When sahinit is restarted from inside such a leaf, the leaf's parent is
the root again. Service cgroups left by an earlier instance are killed,
removed and named on stderr as `cgroup_leftover NAME.service`.

**Trust boundary.** A service is *cgroup-trusted* when it may be able to
write `cgroup.procs` under the root, and so leave its cgroup (it could also
kill sahinit). That is:
- a service with no sandbox that runs as root or as the supervisor's uid;
- a sandboxed service whose `read_write_paths` include `/`, `/sys`,
  `/sys/fs`, `/sys/fs/cgroup`, or a path inside it;
- a sandboxed service that keeps `dac_override`, `fowner`, `chown`,
  `setuid` or `sys_admin`. These bypass file permissions on cgroupfs,
  take a file over, become the supervisor's uid, or mount a cgroupfs of
  their own. `dac_read_search` only bypasses reads and does not count.

Kill-all, limits and `peer_supervised` are promised only for the other
services. Trusted units are allowed, not refused. `plan` names each one on
stderr as `cgroup_trusted FILE`, and status rows carry `cgroup_trusted`.

To limit what a trusted service can do, sahinit sweeps the root. It runs
when a service ends, on each control request, at shutdown, and every
`--cgroup-sweep` (default `30s`; `0` turns the timer off).
- A cgroup under the root that is neither `ROOT/supervisor` nor a running
  service's cgroup is killed and removed (`cgroup_stray_cgroup PATH`). So
  is any cgroup below `ROOT/supervisor`.
- Any process in `ROOT/supervisor` other than sahinit is killed
  (`cgroup_stray PID`).
- A process in the root itself, or in a top-level `ROOT/.control`, is left
  alone and logged once (`cgroup_root_member PID`). The outer manager puts
  processes there. `.control` is never removed: with `Delegate=yes`,
  systemd runs `ExecReload` and similar commands in it.
- A trusted service that moves into another service's cgroup cannot be
  detected.

sahinit takes a lock on the root directory before it changes anything, so a
second supervisor on the same root refuses with `cgroup_busy`. Leftover
service cgroups are cleaned only after both this lock and the control
socket's lock are held.
Without a usable delegated cgroup, `supervise` refuses to start with
`cgroup_unavailable`. `--no-cgroups` keeps the process-group behaviour
instead. Off Linux there are no cgroups, which behaves like
`--no-cgroups`. Status rows and diagnostics report `cgroups` as `enabled`,
`disabled` or `unsupported`; it is never silent.

`supervise` does not mount cgroup2 or enable controllers above its root;
under [PID 1](host-init.md) the init parent does that. Under systemd, run it with
`Delegate=yes`, for example:

```ini
[Service]
ExecStart=/usr/local/bin/sahinit supervise --dir /etc/sahinit/units --socket /run/sahinit/sahinit.sock
Delegate=yes
```

In Docker, use `--privileged --cgroupns=private`, and move other
processes out of the container's root cgroup first, as the test setup in
`internal/cgroup/cgtest` does.

Units may set limits, which are written before the child starts:

```json
{ "memory_max": "256M", "cpu_max": "50000 100000", "pids_max": 64 }
```

| Field | Value | Writes |
| --- | --- | --- |
| `memory_max` | bytes, with an optional `K`, `M` or `G`; at least `1M` | `memory.max`, and `memory.swap.max` set to 0 |
| `cpu_max` | `"QUOTA PERIOD"` in microseconds; period from 1000 to 1000000 | `cpu.max` |
| `pids_max` | an integer from 1 to 4194304 | `pids.max` |

A malformed value is `limit_invalid` at load. A limit whose controller the
root does not offer refuses the unit with `cgroup_controller`. So does any
limit under `--no-cgroups` or off Linux. At startup each refused unit is
named on stderr as `cgroup_controller FILE` and the rest of the catalog
loads. Status rows show `cgroup`, `limits`, and, while the cgroup exists,
`usage`: `memory_current`, `pids_current` and `cpu_usage_usec`, read from
`memory.current`, `pids.current` and `cpu.stat`. I/O limits, slices, and
delegating a cgroup to a service are not supported.

## Unit files and executables

The unit directory and each unit file must be owned by root (or by the
supervisor's own uid) and not writable by group or other. A failing directory
refuses the catalog with `unit_perm`; a failing file is left out, named on
stderr as `unit_perm FILE`, and the rest of the catalog loads.

`exec[0]` is resolved once at load, following links such as Debian's
`/bin/sh -> dash`; argv[0] is passed as written. The resolved file must be a
regular executable, and it and every parent directory must be owned by root
(or the supervisor's uid) and not writable by group or other, except sticky
directories such as `/tmp` (`exec_perm`). On Linux the checked file is opened
and run through that fd, so the file checked is the file run. A binary keeps
no fd from this; a `#!` script keeps it as fd 4 for its interpreter, which must
be an absolute, trusted path that is not `env` or another script
(`exec_interp`). Links are followed only through directories that pass the
same owner and mode rule. Every other fd from 3 up, except the
readiness fd, is closed on exec. Sandbox paths are resolved once at load too.

The migration converters still reject user, group, environment, and working-directory
directives they cannot translate. Native runtime support does not imply automatic
conversion support.

## Local control

```sh
sahinit ctl --socket /run/sahinit.sock status
sahinit ctl --socket /run/sahinit.sock diagnostics worker
sahinit ctl --socket /run/sahinit.sock restart worker
```

`ctl` supports `status`, `diagnostics`, `start`, `stop`, `restart`, and, for sash
units, `reload` and `check`. Only status
allows an omitted service name. It prints the JSON response and exits 0 for success,
1 for transport or operation failure, and 2 for invalid usage. The existing socket
mode and peer UID authorization apply to every operation, including diagnostics.
The socket is 0600 when only the supervisor's uid may connect; when `--uid`
names another uid it is 0660 and `--gid GID` names its group (`socket_group`
otherwise). A request from a process below the cgroup root (a service
cgroup, the supervisor's leaf, or an unknown cgroup) is refused with
`peer_supervised`. A process in the root itself, or in `ROOT/.control`, is
accepted while the root has a controller enabled below it. In that state the
kernel refuses moves into the root, and only the outer manager or a
cgroup-trusted service can write cgroupfs. So `ctl` can run from outside the
root, from the root itself (`docker exec`), or from systemd's `.control`
(`ExecReload=sahinit ctl ...`). When no controller is enabled below the root
(for example, other processes kept it from enabling any), root and
`.control` members are refused as well. sahinit then logs
`cgroup_root_unprotected ROOT` at startup, and `ctl` must run from outside
the root.
So is a request from a process group a service has led. The peer is pinned
when it is accepted:
- through `SO_PEERPIDFD` (Linux 6.5, amd64 and arm64);
- otherwise through `pidfd_open` on its pid;
- otherwise (before Linux 5.3) through its start time.

After the request is read, the peer's cgroup is checked. The request is
refused unless the pinned process still exists, so a pid reused while the
request is read cannot be accepted. Without `SO_PEERPIDFD`, a reuse between
connect and accept remains possible. Without cgroups only the process-group
check applies: a service that called `setsid` is not recognised. A leftover socket from a crash is replaced only when it
is a socket, owned by the supervisor's uid, and refuses a connect. The socket's
directory must pass the owner and mode rule (`socket_perm`), and `PATH.lock`
is held for the supervisor's life (`socket_busy` for a second one).
This is local control; SystemAPI grants and remote transport are not added here.

The framed request `{"op":"diagnostics","name":"worker"}` returns a
`diagnostics` object with:

- `stdout` and `stderr`: each has `data` (base64 bytes) and `dropped` (the number
  of older bytes discarded). Each stream retains its last 8192 bytes.
- `events`: the most recent 64 lifecycle events, each with a per-service sequence,
  UTC time, kind, and PID. Gaps in sequence identify overwritten history.
- `last_exit`, when available: exit code, terminating signal number, and observation
  time. Signal exits have code -1. This remains the previous exit while a new
  instance runs. Exit events also carry this record.

Events cover starting, successful launch, readiness, stopping, exit, launch
failure, readiness timeout, and restart limiting. They do not include arguments
or environment. Process output is raw and can contain secrets printed by the
service; there is no automatic redaction. Logs and events are bounded in memory,
span service restarts, and disappear when the supervisor exits. They are diagnostic
history, not a durable security audit. Streams are separate and have no combined
ordering or per-line timestamp. There is no follow/search or persistent rotation yet.

Output draining is bounded to one second after the main process exits, so a
descendant holding stdout/stderr open cannot block exit collection indefinitely.
The existing status response schema is unchanged. Diagnostics returns one service
per request to keep the response within the 64 KiB framing limit.
