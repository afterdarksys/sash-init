# Execution context and diagnostics

SAHINIT is still a userspace supervisor. These features do not make it a host PID 1.

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
and run through that fd, so the file checked is the file run. A direct launch
keeps that `O_PATH` fd as fd 4, which a script interpreter needs; a sandboxed
launch closes it on exec for binaries. Every other fd from 3 up, except the
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

`ctl` supports `status`, `diagnostics`, `start`, `stop`, and `restart`. Only status
allows an omitted service name. It prints the JSON response and exits 0 for success,
1 for transport or operation failure, and 2 for invalid usage. The existing socket
mode and peer UID authorization apply to every operation, including diagnostics.
The socket is 0600 when only the supervisor's uid may connect; when `--uid`
names another uid it is 0660 and `--gid GID` names its group (`socket_group`
otherwise). A request from inside a running service's process group is refused
with `peer_supervised`. A leftover socket from a crash is replaced only when it
is a socket, owned by the supervisor's uid, and refuses a connect.
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
