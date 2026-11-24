# sahinit runs sash services, batch 1: contract

2026-11-23. This is phase 2 of the sash init contract (sash repo, branch `feat/init-phase1`, `docs/plans/2026-11-21-sash-init-contract.md`), from sahinit's side. Ryan approved the order on 2026-11-23: phase 2, then the systemapi agent. Branch: `feat/sash-services`, from `main` (which includes PID 1 mode, cgroups, hardening and the policy lifetime).

The sash contract, including its "Reconciliation with sahinit" section and its "Phase 1 build decisions", is the authority for every rule that the init re-checks. This document says how sahinit meets it. Batch 1 covers process work. Batch 2 adds `mount`, `umount` and the file verbs.

## Unit

A unit may name a sash service instead of `exec`:

```json
{ "name": "app", "sash": { "file": "/etc/sahinit/services/app.sash", "grant": "/etc/sahinit/grants/app.grant" }, "uid": 990, "gid": 990, "sandbox": { ... } }
```

- **`sash` versus `exec`:** a unit has one or the other.
- **The files:** `file` and `grant` must be root-owned and not group- or other-writable, using the same trusted path walk as executables (`ResolveTrusted`). `grant` must be mode 0600. A failure is `sash_file_perm` or `sash_grant_perm`.
- **The sash binary:** sahinit takes it from `--sash PATH` (default `/usr/bin/sash`), resolved and checked like any executable.
- **Identity:** the unit's numeric `uid` and `gid` are the sash process identity. They must not be 0 (`sash_root`), which matches decision B2: sash runs unprivileged. The unit must be sandboxed and not `cgroup_trusted`.

## Load: `sash --describe`

At load, sahinit runs `sash --describe FILE` once per sash unit.
- **How it runs:** as the unit's uid and gid, sandboxed, in a throwaway cgroup, with a 5 s timeout and a 1 MiB output cap. It calls no parent, so it is given no fds.
- **Failure:** a non-zero exit or malformed JSON is `sash_describe` and the unit is refused. The rest of the catalog still loads.

From `sash-describe/1`:
- **Name:** `name` must equal the unit name (`sash_name_mismatch`).
- **Identity:** `user` and `group` must resolve to the unit's uid and gid (`sash_identity_mismatch`), and must also equal the grant's (below).
- **Ordering:** `requires`, `after` and `wants` become the unit's dependencies. If the unit also lists dependencies, they must match (`sash_order_mismatch`). The graph's cycle check applies.
- **Lifecycle:** `ready`, `stop` and `restart` become the unit's readiness, stop and restart policy, with the same rule: a unit value must agree.
- **Entries:** `run` with no `start` means the `run` entry (decision B4; sahinit always uses `--entry run` in this batch). Otherwise the entries are `start`, `stop`, `reload` and `check`, as declared.

## The grant and its floor

Before each start, sahinit verifies the grant file itself.
- **Signature and shape:** `sash/2`, purpose `service`, signed by the fleet key in `--sash-fleet-pub PATH` (a root-owned 0644 file, 32 raw bytes or 64 hex). It must use the exact signed message and field order of the sash contract. A shared golden vector is copied from sash's `internal/grant` testdata and checked in both repositories.
- **Bindings:** `service` must equal the unit name. `user` and `group` must equal the describe output. `exp` must be 0 or in the future.
- **Floor:** `serial` must be at or above the service's floor. Otherwise the start fails with `sash_grant_revoked` and the unit is failed, not restarted.

**The floor.** A signed floor document, `sahinit-sash-floor/1`, carries `{service, min_serial, issued_at}`. It is signed by the fleet key over the domain `sahinit-sash-floor-v1\n`.
- It is installed with `sahinit sash floor-install --dir D FILE` and shown with `floor-show`.
- It is stored per service under the policy store's rules: lock, temp file, fsync, rename, directory fsync, monotonic. A lower floor is `sash_floor_rollback`. A different floor at the same serial is `sash_floor_conflict`. A corrupt floor fails closed.

## Start: the wire

sahinit starts `sash --session --entry ENTRY FILE` as the unit's uid and gid, sandboxed, in the service's cgroup. It uses the existing launch path: the exec through a checked fd, the cgroup join, and close-on-exec for every other fd. The fds are those of the sash design's Wire section:

| fd | Contents |
| --- | --- |
| 3 | grant bytes |
| 4 | fleet public key |
| 5 | emergency public key: empty, because a service has no emergency path |
| 6 | one end of a socketpair: the verb socket |

The frame format is sash's (`internal/proto`). sahinit implements its own reader and writer and does not import sash. Golden frames are copied from sash and tested in both repositories, the same way the systemapi agent does it.

## Verbs (batch 1)

sahinit serves verbs on the socketpair and re-checks every rule itself. It never trusts that sash already checked.

| Verb key | sahinit's checks and actions |
| --- | --- |
| `svc.spawn` | **Program:** absolute, clean, listed in the grant's `exec`, and passing the trusted path walk.<br>**Identity:** exactly the grant's `user` and `group`; root only if the grant says root.<br>**Env:** names on the grant's `env_names` allowlist and off the fixed denylist. sahinit copies sash's table from `internal/grant/policy.go` with a test that compares it to the vector.<br>**cwd:** under a `file_read` or `file_write` root, resolved without symlinks.<br>**caps and limits:** within the grant and within sahinit's ceilings.<br>**Streams:** `journal` means sahinit's bounded tail plus stderr; `null`; `file:` means a path in `file_write`, opened beneath the root, never following symlinks; stderr may also be `stdout`.<br>**Action:** spawn into the same service cgroup and record the process in the service's name table. A name already in use is `name_in_use`. |
| `svc.signal` | Only a name in this service's table; never a pid. Sent through the pidfd. |
| `svc.wait` | Only a name in this service's table, with a timeout. |
| `svc.proc` | Only a name in this service's table. |
| `svc.status` | Any service's state row from the supervisor. |
| `svc.probe` | **tcp:** loopback only unless the grant has `allow_private`.<br>**unix and file:** under `file_read`, without following symlinks.<br>**notify:** the readiness state of a named spawned process. |
| `svc.output` | The captured tail of a named process, bounded, with the stream chosen. |

- **Anything else:** any other key, including `fs.mount` and the file verbs (batch 2), is refused with `unsupported` and does not crash the session.
- **Secrets:** a secret env value from spawn opts is written only to the child's environment. It never appears in logs, diagnostics, status or audit events.

## Lifecycle

- **start:** sahinit runs the `start` (or `run`) entry. An exit of 0 means started, and sahinit then waits on `ready`. Exit 1 means failed, and the restart policy applies. Exit 2 means a configuration or grant error: the unit is failed, not restarted, and the stderr token is logged. Exit 3 means not ready in time. The sash session process stays alive only as long as the entry runs. The service is the set of spawned processes in its cgroup.
- **stop:** sahinit runs the `stop` entry with the unit's stop timeout, then uses the cgroup kill to remove everything left. Without a `stop` entry it signals the spawned processes and then kills the cgroup.
- **check:** the `check` entry is the readiness and health probe when `ready` says so. It runs under sash's read-only await rules, and sahinit refuses mutating verbs from a check session (`check_read_only`).
- **reload:** runs the `reload` entry.
- **Status:** shows the sash unit's entry results, the name table and the grant serial. It never shows the grant body or env values.

## Out of batch 1

- `mount`, `umount`, `mkdir`, `chown`, `chmod`, `touch`, `ln` and `rm`: batch 2, with `openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`, `lchown`, `unlinkat` and the mount allowlists.
- A fleet signer for grants and floors: a systemapi.io job.
- The research item on containers and VMs.

## Tests

- **Golden vectors:** shared frames, grant and floor vectors.
- **Load:** describe success, and each mismatch refusal.
- **Grant:** a bad signature, wrong purpose, wrong service, wrong identity, below-floor serial, floor rollback and conflict.
- **End to end:** on Linux as root in Docker with cgroups, a real `sash` binary (built from the sash repo at `feat/init-phase1`) runs a service file. It spawns a sleep-like test program and waits on readiness; stop kills the cgroup; and refusals cover an unlisted program, a root spawn, a refused env name and a cwd outside the roots.
- **Reverts:** every check has a test that fails when the check is reverted.
