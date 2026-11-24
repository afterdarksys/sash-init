# Files and settings reference

Every file sahinit reads or writes, with its owner and mode rules and its
format. sahinit has **no configuration file**: settings are the flags in
[cli](cli.md), and everything below is a path passed by flag. Paths shown as
defaults are real defaults only where marked; the rest are suggestions.

Two rules recur:

- **Trusted walk.** A path is resolved one component at a time from `/`.
  Every directory it passes through must be owned by root or the supervisor's
  effective uid and not group- or other-writable; a sticky directory (such as
  `/tmp`) may be writable by others, but must still have such an owner. Symlinks are followed only inside such
  directories (at most 40). Implemented by `unit.ResolveTrusted`.
- **Owner and mode rule.** The file itself is owned by root or the effective
  uid and is not group- or other-writable.

## Summary

| File | Set by | Read or written by | Owner and mode | Default path |
| --- | --- | --- | --- | --- |
| Unit directory | `--dir` | `supervise`, `plan`, `init` | owner and mode rule; not a symlink | `/etc/sahinit/units` for `init` only |
| `NAME.json` unit | | `supervise`, `plan` | owner and mode rule; regular, not a symlink, at most 64 KiB | |
| Executables and `#!` interpreters | unit `exec` | at load and every launch | trusted walk and owner and mode rule, executable | |
| Control socket | `--socket` | `supervise` (creates), `ctl` | socket 0600, or 0660 with `--gid`; directory owner-only writable | `/run/sahinit/control.sock` for `init` only |
| `SOCKET.lock` | | `supervise` | 0600, regular, one link, owned by the supervisor | beside the socket |
| Cgroup root | the supervisor's own cgroup | `supervise` | cgroup2 at `/sys/fs/cgroup`, writable by the supervisor | `/sys/fs/cgroup/sahinit` under `init` |
| sash binary | `--sash` | `supervise` | as an executable | `/usr/bin/sash` |
| Fleet public key | `--sash-fleet-pub`, `--fleet-pub` | `supervise`, `sahinit sash` | trusted walk; owner and mode rule; 32 raw bytes or 64 hex digits | |
| sash state directory | `--sash-floor-dir`, `--dir` | `supervise`, `sahinit sash` | owned by the effective uid, no group or other access (0700) | |
| `SERVICE.floor`, `lock`, `pending-*` | | sash floor store | 0600, owned by the effective uid, one link | in the state directory |
| `sash-mounts.json` | | `supervise` | written in the state directory | in the state directory |
| Service script | unit `sash.file` | `supervise` | trusted walk; owner and mode rule; no setuid/setgid/sticky | |
| Grant | unit `sash.grant` | `supervise` | trusted walk; owner and mode rule; mode exactly 0600 | |
| Trust file | `--trust` | `sahinit policy` | owner root or effective uid, not group- or other-writable; regular; not a symlink; at most 64 KiB | |
| Policy or floor document | `--document` | `sahinit policy` | regular; not a symlink; at most 384 KiB | |
| Policy cache directory | `--cache` | `sahinit policy` | owned by the effective uid, no group or other access | |
| `policy.json`, `floor.json`, `lock`, `pending-*` | | policy store | 0600, owned by the effective uid, one link | in the cache directory |
| Renewal credential | `--credential` | `policy refresh` | owned by the effective uid, mode 0600 or stricter, one link, not a symlink | |
| Journal directory | `--log-dir` (`supervise`, `init`), `--dir` (`logs`, `events`) | `supervise` writes, `logs` and `events` read | trusted walk; no group or other access (0700); created 0700 when missing | none for `supervise` and `init` (no journal); `/var/log/sahinit` for `logs` and `events` |
| `current.jsonl`, `archive.N.jsonl`, `lock`, `view.lock` | | the journal | 0600, regular, one link, owned by root or the effective uid | in the journal directory |
| Deployment root | `--deployment-root` (`supervise`, `init`), `--root` (`deploy`) | `supervise`, `deploy` | absolute, clean; trusted walk; no group or other access; created 0700 | |
| `state.json`, `lock`, `policy/`, `generations/ID/` | | deployments | 0600 files, 0700 directories; artifacts 0555, unit files 0400 | in the deployment root |
| Bundle, manifest | `--bundle`, `--manifest` | `deploy stage` | each file: owner and mode rule, regular, not a symlink, trusted parent | |
| Recovery program | `init --recovery` | PID 1 | executed by path as root | none (disabled) |
| `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/run`, `/sys/fs/cgroup` | | PID 1 mounts them | | |
| `/tmp` | | PID 1 creates it (sticky, 1777) when missing | | |
| `/proc/swaps` | | PID 1 at shutdown (`swapoff`) | | |
| `/run/sahinit` | | PID 1 creates it, mode 0700 | | |
| `/proc/sys/kernel/random/boot_id` | | read for the sash mount table | | |
| `/proc/self/mountinfo` | | PID 1 (mount checks, shutdown unmounts) | | |

## Unit directory and unit files

See [units](units.md#the-unit-directory). The directory holds only regular
`NAME.json` files; sahinit never writes there. `sahinit migrate --out DIR`
creates a new directory (0700) with 0600 unit files, which meets the rule when
run as the supervisor's uid.

## Control socket and lock

- `--socket PATH` must be absolute and clean. Its directory is resolved with the
  trusted walk and must be writable by its owner only: a sticky directory such
  as `/tmp` is refused (`socket_perm`), because anyone could pre-create the
  socket or its lock. Use a private directory such as `/run/sahinit/`.
- `PATH.lock` is created 0600 and flocked exclusively for the supervisor's
  life (`socket_busy` for a second supervisor). It must be a regular file with
  one link owned by the supervisor (`socket_exists` otherwise). It is removed
  at exit.
- The socket is bound in a fresh private directory, chmodded (and chowned to
  `--gid`) there, and hard-linked into place. Mode 0600 when only the
  supervisor's uid may connect; 0660 with group `--gid` when `--uid` names
  another uid (`socket_group` without `--gid`).
- A leftover socket from a crash is removed only when it is a socket owned by
  the supervisor's uid and refuses a connection; anything else at the path is
  `socket_exists`. The socket is removed at exit.

### Control protocol

One request per connection. A frame is a big-endian `uint32` length and that
many bytes of JSON, 1 to 64 KiB (`frame_size`). The server reads the request
within 5 s and serves at most 32 connections at once (`busy` beyond that).

Request: `{"op": OP, "name": NAME, "arg": ARG}` with only those keys; `op` is
required. Operations: `status`, `diagnostics`, `explain`, `start`, `stop`,
`restart`, `oneshot` (with `arg`), `reload`, `check`; and, for a peer whose
effective uid is 0 only (`root_required`), `diff` and `apply` (with `arg`, an
absolute unit directory), `rollback` and `activate`.

Response: `{"ok": bool, "error": TOKEN, "rows": [...], "diagnostics": {...},
"explanation": {...}, "diff": {...}}`. `rows` is present for status and after
a mutation on a known name; `explanation` for `explain`
(`{name, desired, state, reason, blocked_by}`); `diff` for the catalog
operations (`{added, removed, changed, affected, generation, rolled_back}`).

Status row:

| Key | Meaning |
| --- | --- |
| `name`, `state`, `pid`, `ready`, `restarts` | state is `stopped`, `starting`, `running`, `stopping`, `exited`, `failed` or `blocked` |
| `desired` | whether the unit should run: set by boot and `start`, cleared by `stop` |
| `essential` | the unit's resolved `essential` (strict boot only acts on it) |
| `sandbox` | the applied sandbox claim (`none`, `no_new_privs,landlock_vN,caps`) or empty |
| `last_error` | the token of the last failure, or empty |
| `cgroups` | `enabled`, `disabled` or `unsupported` |
| `cgroup` | the service cgroup path, as `/proc/PID/cgroup` shows it |
| `cgroup_trusted` | see [security](security.md#the-cgroup_trusted-boundary) |
| `limits` | `{memory_max, cpu_max, pids_max}`; zero or empty is no limit |
| `usage` | `{memory_current, pids_current, cpu_usage_usec}`, only while the cgroup exists |
| `sash` | sash units only: `{entry, grant_serial, entries, procs}`; `procs` rows are `{name, pid, state, started_at, exit, signal}`. Never the grant body or env values. |

Diagnostics (`diagnostics` op, one service): `name`, `cgroups`, `stdout` and
`stderr` (each `{data: base64, dropped: N}`, the last 8192 bytes), `events`
(the last 64: `{sequence, time, kind, pid, code, exit}`), `journal`
(`{dropped, error}` of the `--log-dir` journal, zero without one) and `last_exit`
(`{code, signal, time}`; a signal exit has code -1). Event kinds: `starting`,
`started`, `ready`, `stopping`, `exited`, `ended`, `launch_failed`,
`timeout`, `restart_limit`, `cgroup_stuck`, and for sash units
`sash_start`, `sash_run`, `sash_stop`, `sash_reload`, `sash_check`. Output is
raw and may contain whatever the service printed, secrets included; it is kept
in memory only and lost when the supervisor exits.

## Cgroup root

`supervise` uses its own cgroup as the root. It must be on cgroup2 mounted at
`/sys/fs/cgroup`, and the root directory, its `cgroup.procs` and
`cgroup.subtree_control` must be writable by the supervisor
(`cgroup_unavailable`). It flocks the root directory (`cgroup_busy`), moves
itself into `ROOT/supervisor`, enables `cpu`, `memory` and `pids` below the
root where offered, and creates `ROOT/NAME.service` (mode 0755) for each
service start, and `ROOT/NAME.scratch` for each `sash --describe`. Under PID 1
the root is `/sys/fs/cgroup/sahinit`. See [security](security.md) for the sweep.

## sash files

### Fleet public key

32 raw bytes, or 64 hexadecimal digits with an optional trailing newline. Read
at `supervise` start (restart the supervisor to change it). Whoever can replace
it can sign grants and floors for every sash service on the host.

### Service script and grant

The script is the sash service file (`.sash`). The grant is a JSON `sash/2`
document signed by the fleet key over `sash-grant-v2\n` followed by the
canonical body, with `"purpose":"service"`. sahinit reads at most 64 KiB and
checks: the signature (`grant_bad_sig`), the shape (`grant_bad_shape`), no
`"*"` entry (`grant_star`), no `/` root (`grant_root_slash`), `exp` 0 or in the
future (`grant_expired`), `service` equal to the unit name
(`grant_service_mismatch`), `user` and `group` equal to describe's
(`grant_identity_mismatch`) and `serial` at or above the floor
(`sash_grant_revoked`). The grant's `host` is not checked. Fields used by
sahinit: `service`, `user`, `group`, `serial`, `exp`, `exec`, `env_names`,
`file_read`, `file_write`, `mounts`, `mount_sources`, `caps`,
`allow_private`. The fleet signer that produces grants is not part of sahinit.

### sash state directory

`--sash-floor-dir`. A directory, not a symlink, owned by the supervisor's
effective uid with no group or other access. Contents:

- `SERVICE.floor`: the signed floor, `{"payload": base64, "signature": base64}`,
  at most 4 KiB. The payload is exactly
  `{"version":"sahinit-sash-floor/1","service":S,"min_serial":N,"issued_at":T}`,
  `min_serial` 1 to 2^53-1, `issued_at` above 0, signed by the fleet key over
  `sahinit-sash-floor-v1\n` + payload. No floor file means no floor.
- `lock`: flock for installs and reads; an install in progress is waited for
  2 s (`sash_floor_busy`).
- `pending-HEX`: a temporary file during an install (create exclusive 0600,
  write, fsync, rename, directory fsync). A leftover one is ignored.
- `sash-mounts.json`: `{"boot": BOOT_ID, "mounts": [{"service","dir","kind","id"}]}`,
  the mounts sash services made, with their unique mount IDs. At start, a
  table from the same boot is unmounted (`sash_mount_leftover SERVICE DIR`);
  a table that is not valid JSON logs `sash_mount_state_corrupt`; a table
  from another boot is discarded. The table is rewritten as mounts change.

## Boot policy files

Formats are specified in [boot policy](../boot-policy.md); the rules on disk:

- **Trust file** (`--trust`): strict JSON with `tenant_id`, `host_id`,
  `enrollment_id`, `recovery_profile_id` (each
  `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`), `keys` (1 to 16 distinct key IDs
  mapped to standard-base64 32-byte Ed25519 public keys),
  `max_validity_seconds` (1 to 31622400), `max_grace_seconds` (0 to
  31622400), `max_job_seconds` (1 to 86400), `min_refresh_seconds` (at least
  30), `max_refresh_seconds` (at least the minimum, at most the validity) and
  optional `max_lifetime` (`never`, the default, or `renew`). Anything else is
  `policy_bad_trust`.
- **Cache directory** (`--cache`): `policy.json` (the cached signed envelope,
  which is also the anti-rollback high-water mark), `floor.json` (the
  installed revocation floor), `lock` (`policy_store_busy` while held) and
  transient `pending-*` files. Create it yourself before first use, for
  example `install -d -m 700 /var/lib/sahinit-policy`.
- **Credential** (`--credential`): 32 to 4096 printable ASCII characters
  without spaces and at most one trailing newline. Reread on every attempt,
  so it can be replaced in place. Never printed.

## Journal

`supervise --log-dir DIR` keeps a bounded journal: `current.jsonl` (rotated at
1 MiB) and up to four archives `archive.0.jsonl` (newest) to
`archive.3.jsonl`. Each line is one JSON record
`{sequence, boot_id, time, unit, stream, data, event}`: `stream` is `stdout`,
`stderr` or `event`; `data` is the output chunk (at most 8 KiB) base64
encoded by JSON, so binary output and terminal escapes stay inert; `event` is
a lifecycle event object. `sequence` grows across restarts. Records queue in
memory (256) and are written by a background goroutine that syncs every
second and on close; a full queue drops records and counts them in the
`journal` field of `ctl diagnostics` (`{"dropped","error"}`). An unsynced
tail can be lost on power failure; opening repairs a torn final record. It is
bounded operational logging, not an audit log. `lock` makes one writer per
directory; `view.lock` lets readers and rotation exclude each other.

## Deployment root

See [deployments](../deployments.md). `generations/ID/` holds a verified copy
of one bundle (`manifest.json`, `policy.json`, `units/`, `artifacts/`) and is
never changed after it is renamed into place; `ID` is
`SEQUENCE-` and the first 16 hex digits of the manifest digest. `state.json`
is `{"active","pending","previous"}`. `policy/` is a boot-policy store
(`policy.json`, `floor.json`) holding the newest staged policy and the
revocation floor: install a floor there with
`sahinit policy floor-install --trust FILE --document FLOOR --cache ROOT/policy`. Nothing is pruned.

## PID 1 files

PID 1 makes the mount propagation of `/` private, mounts `/proc`, `/sys`,
`/dev` (devtmpfs, `mode=0755`), `/dev/pts` (devpts, `mode=0620,ptmxmode=0666`),
`/dev/shm` (tmpfs, `mode=1777`), `/run` (tmpfs, `mode=0755`) and
`/sys/fs/cgroup` (cgroup2) unless already mounted, creates `/run/sahinit`
(0700), a sticky `/tmp` when missing, and `/sys/fs/cgroup/sahinit/supervisor`, requires
`/sys/fs/cgroup/sahinit/cgroup.kill`, writes `+cpu`, `+memory`, `+pids` to
`/sys/fs/cgroup/cgroup.subtree_control` where available, and opens
`/dev/console` for standard input, output and error. At shutdown it reads
`/proc/self/mountinfo` and unmounts every non-pseudo mount, deepest first,
after `swapoff` of every swap area listed in `/proc/swaps`. It does no
filesystem check and no `switch_root`; `contrib/initramfs/init` (see
[operations](operations.md#persistent-ext4-root)) does both before it execs
sahinit on the new root.
