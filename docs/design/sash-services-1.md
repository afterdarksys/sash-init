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

## Decisions made during the build

Where the contract left a choice, or where sash's code differs from this document's text, batch 1 settled it as follows.

1. **Golden grant vector.** sash has no grant testdata, and its repository is not changed here. `internal/sash/testdata/sash-grant-vectors.json` was generated by sash's own `internal/grant` (`Sign`, `Message`, `Verify`, `EnvDenied`, `EnvName`, at `f28285b` on `feat/init-phase1`), copied into a scratch module. It holds a valid grant, the other key, the v1 domain, a tampered serial, purpose open, expired and serial 0, the exact signed message, and sash's answer for every denylisted name. The same file belongs in sash's testdata. sahinit's env table is compared with it both ways.
2. **Frames.** sahinit speaks only the serial wire. A mux hello gets sash's own "old agent" reply, `{"error":"frame body"}`, so sash stays serial. sahinit reads at most 1 MiB a frame (sash allows 8 MiB). A longer frame ends the session.
3. **fd 5 is not empty.** sash refuses an empty emergency key: `session.Open` needs 32 bytes, distinct from the fleet key, or `grant_bad_sig`. sahinit passes a fresh random ed25519 public key per session and discards its private half, so nothing can sign as it.
4. **The unit.** Identity uses the existing `execution.uid`/`gid`; `groups`, `directory` and `environment` are refused on a sash unit. `exec`, `type`, `ready` and `timeout` are refused too (`sash_unit_field`): the service block owns them.
5. **File checks.** Ownership follows the unit-file rule: owner root or the supervisor's uid, not group- or other-writable. A grant must be exactly 0600. Links are resolved by the trusted walk. The grant check is repeated before each session.
6. **Describe.** Any non-zero exit is `sash_describe`, including sash's exit 1 ("incomplete"). The ordering names must also be valid sahinit unit names (`sash_order_mismatch`). The unit's `restart` `no` equals sash's `never`. A restart that disagrees is `sash_lifecycle_mismatch` (a new token). A block without `user` and `group` is `sash_identity_mismatch`. Names are resolved with the system's user and group databases. `sahinit plan` does not run describe.
7. **What a sash unit needs.** It needs cgroups (`sash_cgroups`), `--sash-fleet-pub` (`sash_fleet_key`), `--sash-floor-dir` (`sash_floor_store`) and a checked `--sash` binary (`sash_binary`). Without one of them every sash unit is refused by file and the rest of the catalog loads. The fleet key file is reached by the trusted walk, owned by root or the supervisor's uid, and not group- or other-writable.
8. **The floor document.** It is `{"payload": base64, "signature": base64}` with no key id (there is one fleet key). The payload is strict `{version, service, min_serial, issued_at}`, with `min_serial` from 1 to 2^53-1. There is one file, `SERVICE.floor`, per service. A floor that is unreadable, unsafe, unverifiable or names another service fails closed: `Admit` refuses every serial. `floor-install` and `floor-show` take `--fleet-pub`. `testdata/sash-floor-vectors.json` is the vector for a future signer.
9. **Grant tokens.** These are sash's (`grant_bad_sig`, `grant_bad_shape`, `grant_expired` and the rest), plus `grant_service_mismatch`, `grant_identity_mismatch` and `sash_grant_revoked`. Every grant failure leaves the unit failed and not restarted, and is logged as `sash_grant SERVICE TOKEN`. The grant's `host` is not checked: sahinit has no host name in batch 1.
10. **Spawned processes** run as the unit's uid and gid, and the grant's names must resolve to exactly those. They run under the unit's own sandbox (no_new_privs, Landlock paths). A cap is checked against the grant and against the unit's sandbox caps (`ceiling` outside them), and is then refused as `caps_unsupported`: sahinit's sandbox sets no ambient caps, so it could not reach an unprivileged child. That is the smaller of the two fixes the review allowed; making caps work is a later batch. The limit ceilings are fixed, and core is always 0 for a spawned child, asked or not, so no dump carries a secret. The sandbox helper sets the limits (soft and hard, so it can only lower them) and the umask before exec. A prlimit from sahinit would need CAP_SYS_RESOURCE.
11. **Readiness pipe.** Every spawned process gets the readiness pipe on fd 3 (`SAHINIT_READY_FD=3`). `probe notify NAME` and `ready notify` use it: notify is ready when `main` is ready, or, with no `main`, any process.
12. **Streams.** `journal` is a per-process tail (64 KiB, 1000 lines) for `svc.output`, within 1 MiB for the whole service: past that a tail drops its own oldest lines, and a line that still does not fit is dropped. An ended process's output is freed once `svc.output` has read it. Journal lines are copied to sahinit's log as `sash_output SERVICE NAME STREAM: LINE`, with control characters replaced, at most 200 at once and 50 a second per service; the rest are counted in `sash_output_dropped SERVICE N`. A `file:` stream is opened by the sandbox helper as the child's uid and gid, beneath its root with no symlinks and before Landlock, `O_APPEND`, created 0640; it must be a regular file with one link. sahinit's own root permissions never reach it (`stream_denied`, answered `denied`).
13. **Verb answers.** `wait` on a process ended by a signal answers exit 0 and the signal name, as sash's init double does. `svc.status` answers state `ready` for a running, ready service, else the supervisor's state, and `since` is its last event. Spawn arguments are at most 256 bytes and 32 words, as for any sahinit launch. A service binds at most 64 process names (`too_many_names`).
14. **Lifecycle.** start, run and reload sessions are bounded by 2 minutes. check is bounded by the ready timeout, and stop by the stop timeout. A service block whose ready or stop timeout or restart delay passes 5 minutes (sahinit's unit timeout limit), or whose burst passes 5, is refused at load (`sash_lifecycle_limit`), not clamped. A session's verb server ends with the session: `wait` returns when sash closes the socket, the session is cancelled, or the entry's time runs out. Stop interrupts a start still in its entry or readiness: the start is marked lost, its sessions end, and the stop proceeds. The exit statuses work like this:
    - **2:** `sash_config`. No restart; logged as `sash_entry_error SERVICE ENTRY TOKEN`, where TOKEN is the leading word of sash's first stderr line.
    - **3:** `sash_not_ready`, and the restart policy applies.
    - **Anything else non-zero:** `failed`, and the restart policy applies.

    Readiness works like this:
    - **tcp, unix, file:** sahinit probes them itself under the grant's rules.
    - **none, or no `ready`:** ready at once, unless the file has `check`, which is then run read-only until it exits 0.
    - **Not ready by the timeout (default 5 s):** `timeout`, with no restart.

    The service ends when no spawned process is left running. The cgroup is then killed. The end is OK when no process exited non-zero or by a signal. The block's `restart` policy, `delay`, `burst` and `within` apply.
15. **Stop.** stop runs the `stop` entry when the file has one and the grant still verifies. Otherwise it sends the block's stop signal (TERM by default) to each running process and waits up to the stop timeout. Either way the cgroup kill follows. Shutdown does the same.
16. **Control.** There are new `ctl` operations: `reload NAME` runs the reload entry and `check NAME` runs the check entry. A failing check is `unhealthy`. Either answers `no_entry` without the entry and `not_running` unless the service is running. sahinit itself refuses a check session's `svc.spawn` and `svc.signal` (`check_read_only`).
17. **Fd passing.** The sandbox helper got `Options.Pass` (at most 4 fds), `Umask` and `Rlimits`. Passed fds sit at the helper's fds 8 and up, and its fds 3 to 7 are always filled, so nothing the Go runtime opens sits where a passed fd will go. Just before exec the exec and status fds move to 64 and up, and the passed fds are put on 3 and up without close-on-exec. Every other fd is still closed at exec.
19. **Floor store busy.** A floor-install holding the store's lock is waited for two seconds. Still busy, the start fails with `sash_floor_busy`, which the restart policy may retry; it is not a grant error.
20. **Describe output cap.** The review's test for it found that the cap did not hold: the capped buffer embedded `bytes.Buffer`, so `io.Copy` read through `ReadFrom` past it. It no longer embeds it.
18. **Cgroups.** Describe runs in a throwaway cgroup, `NAME.scratch`, which the stray sweep also removes. Later sessions and every spawn join the existing service cgroup (`Root.Join`); only a start makes it fresh.

**Not done in batch 1:**
- **Grant host binding:** the grant's `host` is not checked.
- **Capabilities:** a spawn's caps are refused (`caps_unsupported`) until the sandbox can set ambient caps.
- **Batch 2 verbs:** `mount`, `umount` and the file verbs.
- **Signer:** the fleet signer.
- **Plan:** describe in `sahinit plan`.
- **sash side:** the grant vector is not yet copied into sash.
- **Boot test:** a QEMU boot test.
