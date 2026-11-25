# Refusal and diagnostic codes

sahinit reports every failure as one stable token from a closed vocabulary
(`internal/fail`): error text is the token and nothing else, so a path, a
request id or an OS error string never reaches the control socket or a log.
An error that is not a token becomes `failed`.

Tokens appear in four places:

- on **stderr** of a command, alone or as `TOKEN FILE` / `TOKEN NAME`;
- in a control-socket response's `error`;
- in a status row's `last_error`, and in a diagnostics event's `code`;
- in the supervisor's **log lines** (its stderr; the console under PID 1).

`internal/fail/docs_test.go` fails the build when a token defined in the
source (every `fail.E("...")` literal, every log-line and status token) is
missing from this page.

Each group below lists the code, what it means, and what to do.

## General

| Code | Meaning | What to do |
| --- | --- | --- |
| `failed` | A failure with no more specific token: malformed JSON, a missing required field, an I/O error, a credential that cannot be set, a connection that failed. | Check the input against the reference; for `ctl`, check the socket path and that the supervisor runs. Under PID 1 look for the `sahinit-init:` log lines. |
| `empty` | The unit directory has no units, every unit was left out, or the graph is empty. | Add units, or fix the per-file refusals printed before it. |
| `busy` | The service is already starting, running or stopping; another operation holds it; the socket has 32 requests in flight; a sash mount is in use. | Retry after the current operation; for a mount, stop what uses it. |
| `timeout` | A start did not become ready within the unit's `timeout`, a sash start's readiness ran out, or a sash `wait` verb ran out. (A plain stop never times out: it escalates to SIGKILL.) | Raise `timeout` (at most `5m`), or fix the readiness signal (notify writes to fd 3). |
| `not_found` | No unit with that name, or (sash file verbs) a path that does not exist. | Check the name with `ctl status`. |
| `unsupported` | Not implemented here: a sash verb sahinit does not serve, an rbind on a kernel without `open_tree`, a kernel with no mount IDs. | Use a supported verb or a newer kernel. |

## Service states and event kinds

These are not errors, but they are part of the same vocabulary.

| Value | Where | Meaning |
| --- | --- | --- |
| `stopped` | state | Not running; never started, stopped, or a `simple` unit that exited 0 without restart. |
| `starting` | state, event | A start is in progress (waiting for readiness). |
| `running` | state | Started and, for notify, ready. |
| `stopping` | state, event | A stop is in progress. |
| `exited` | state, event | A oneshot that exited 0; as an event, the main process exited (with `exit`). |
| `failed` | state | The last start or run failed; see `last_error`. |
| `blocked` | state, event | Desired, but a `needs` provider is not ready (`last_error` `needs_not_ready`) or failed (`needs_failed`). The supervisor starts it when the provider is ready again. `ctl stop` makes it `stopped`. |
| `started` | event | The process was launched. |
| `ready` | event | Readiness was reached. |
| `ended` | event | A sash service ended: no spawned process is left. |

The other event kinds are `launch_failed`, `timeout`, `restart_limit`,
`cgroup_stuck`, `watchdog` (a notify unit missed its watchdog and was
killed), `admission_denied` (a deployment's policy refused a start; `code`
holds the policy token) and, for sash units, `sash_start`, `sash_run`, `sash_stop`,
`sash_reload` and `sash_check` (the entry's exit code in `exit`, the token in
`code`).

## Unit catalog (load)

| Code | Meaning | What to do |
| --- | --- | --- |
| `unit_perm` | The unit directory or a unit file is owned by someone other than root or the supervisor's uid, or is group- or other-writable. A directory refuses the catalog; a file is left out (`unit_perm FILE`). | `chown root:root` and `chmod go-w` the directory and files. |
| `symlink` | The unit directory or a unit file is a symlink. (Also a sash file verb meeting a symlink.) | Use real files. |
| `stray_file` | A directory, dot-file, non-`.json` file or non-regular file in the unit directory. | Move it out; the directory holds only `NAME.json`. |
| `too_many` | More than 256 unit files. | Split the catalog. |
| `file_size` | A unit file is over 64 KiB. | Shrink it. |
| `unknown_field` | A key the schema does not have. | Remove or correct it ([units](units.md)). |
| `duplicate_field` | A JSON key appears twice, a dependency list repeats a name, or two units share a name. | Remove the duplicate. |
| `name_invalid` | `name` does not match `^[a-z][a-z0-9-]{0,62}$`. | Rename. |
| `name_mismatch` | `name` differs from the file name. | Make `NAME.json` hold `"name": "NAME"`. |
| `exec_relative` | `exec[0]` is not absolute and clean. | Use an absolute, clean path. |
| `type_invalid` | `type` is not `simple` or `oneshot`. | |
| `ready_invalid` | `ready` does not fit the type (`exec`/`notify` for simple, `exit` for oneshot). | |
| `restart_invalid` | `restart` is not `no`, `on-failure` or `always`, or a oneshot restarts. | |
| `timeout_range` | `timeout` is not a duration in (0, 5m]. | |
| `edge_empty` | An empty name in `needs`, `after` or `wants`. | |
| `execution_invalid` | An `execution` rule failed: uid without gid, groups without identity, an ID of 4294967295, duplicate or over 64 groups, a bad directory, a bad or reserved (`SAHINIT_`) environment name, too much environment. | Fix the field ([units](units.md#execution)). |
| `limit_invalid` | A `memory_max`, `cpu_max` or `pids_max` value is malformed or out of range. | See [limits](units.md#limits). |
| `sandbox_root` | A sandboxed unit has no `uid` or uid 0, or the helper found itself running as root with a sandbox. | Give the unit a non-root `execution.uid`. |
| `sandbox_privs` | `no_new_privs` is `false`. | Remove it or set `true`. |
| `sandbox_path` | A sandbox path is not absolute and clean, or at launch is missing or contains a symlink, or a `socket_paths` entry is not a directory. | Use the resolved real path; create the socket directory before the start. |
| `sandbox_overlap` | A path is listed twice, or in both lists after resolution. | |
| `essential_requires_boot` | `"essential": true` on a unit with `"boot": false`. | Remove it; only boot units are essential. |
| `restart_delay_invalid` | `restart_delay` or `restart_max_delay` is not a duration string from `10ms` to `5m`, or the maximum is below the delay. | See [restart](units.md#types-readiness-and-restart). |
| `watchdog_invalid` | `watchdog` is not a duration string from `100ms` to `5m`, or the unit's `ready` is not `notify`. | |
| `sandbox_cap` | At load, an unknown capability name. At start, the supervisor is not root (it has no capability to give), or the sandbox helper could not reach or verify exactly the granted set (see [unit capabilities](../design/unit-caps-1.md)). | Use a name from the allowlist; run the supervisor as root. |
| `sandbox_cap_denied` | A real Linux capability that is not on the allowlist (`net_bind_service`, `setuid`, `setgid`). | Remove it; the others are never grantable. |
| `sandbox_ids` | At load: `setuid` without `setuid_to` (or `setgid` without `setgid_to`), a list without its cap, an empty list, a value that is not an integer from 1 to 4294967294 (wrong type, null, negative, fractional, too large), more than 64 ids, a repeated id, 0, or a unit with caps whose gid or groups include 0. At start: a target, the unit's gid or a group is the supervisor's own uid or gid. | List the non-root ids the service switches to; run it with a non-root group. |
| `sandbox_proc` | A unit with `setuid` or `setgid` has `/`, `/proc` or a path under `/proc` in `read_write_paths` (at load, also after symlinks resolve), or at start an entry that is on a procfs or has a procfs mounted beneath it. A writable procfs would let it write a user namespace's id map. | Keep every procfs out of its writable paths. |
| `sandbox_socket` | A `socket_paths` entry is not at or beneath any `read_write_paths` entry (at load, also after symlinks resolve, and in the helper). | List the directory, or one above it, in `read_write_paths` too. |

## Dependency graph

| Code | Meaning | What to do |
| --- | --- | --- |
| `cycle` | `needs`, `after` and `wants` form a cycle (across the whole catalog). | Break the cycle. |
| `missing_needs` | A `needs` names a unit not in the catalog (or one left out at load). | Add the unit, or fix the refusal that left it out. |
| `missing_after` | An `after` names a unit not in the catalog. | |
| `boot_needs` | A boot unit `needs` a unit with `"boot": false`. | Make the dependency a boot unit, or use `after`/`wants`. |

## Executables and launch

| Code | Meaning | What to do |
| --- | --- | --- |
| `exec_not_file` | The executable (or a path component) is missing, not a regular executable file, or a symlink chain is too long; the helper's exec fd is not a regular executable. | Install the program; check `ls -l` of the resolved path. |
| `exec_perm` | The executable or a directory on its path is owned by someone other than root or the supervisor's uid, or writable by group or other (a sticky directory may be writable by others, but still needs that owner). | Fix ownership and modes along the whole path. |
| `exec_interp` | A `#!` script's interpreter is relative, is `env` (or `busybox env`), is itself a script, or the line is over 256 bytes. | Name the real interpreter, e.g. `#!/usr/bin/python3`. |
| `landlock_unavailable` | The kernel has no Landlock (or refused a ruleset). | Enable Landlock (Linux 5.13+, `lsm=` including `landlock`), or drop the sandbox. |
| `landlock_abi` | The sandbox needs a Landlock right the kernel's ABI lacks. | Use a newer kernel. |
| `openat2_unavailable` | No `openat2` (Linux before 5.6). | Use a newer kernel. |
| `seccomp_unavailable` | A unit holding `setuid` or `setgid` needs the id filter, and this kernel or architecture cannot install it (seccomp filters off, or not amd64 or arm64). | Use a supported kernel and architecture, or drop the caps. |
| `sandbox_timeout` | The sandbox helper did not report within the deadline. | Check system load; see the unit's diagnostics. |
| `sandbox_unsupported` | A sandbox was asked for off Linux. | Run on Linux or drop the sandbox. |
| `launch_failed` | Event kind: a launch failed; its `code` holds the reason. | Read the event's code. |
| `artifact_digest` | A deployment unit's executable does not hash to its signed `sha256` at launch (it is hashed on every start), or a bundle or generation file does not match the manifest. | The generation was changed on disk: stage a fresh one from a trusted bundle. |
| `verified_exec_unavailable` | A deployment unit's executable could not be opened for reading (only an `O_PATH` descriptor), or the platform is not Linux, so it cannot be hashed; the launch is refused. | Run deployments on Linux, as root. |
| `watchdog` | `last_error` and event kind: a notify unit with `watchdog` closed its notify pipe or sent no byte within the interval, and its process group was killed. The restart policy then applies. | Read its diagnostics; with `notify-adapter`, match `--watchdog` to the unit. |

## Lifecycle and control

| Code | Meaning | What to do |
| --- | --- | --- |
| `needs_failed` | A `needs` dependency is failed; the unit is marked failed. | Fix and start the dependency first. |
| `needs_not_ready` | A `needs` dependency is not yet running and ready (or exited OK). | Start it, or wait. |
| `restart_limit` | More than 5 restarts within 30 s; the unit is failed. | Find the crash in `ctl diagnostics NAME`, then `ctl start NAME`. |
| `arg_required` | A oneshot was started without an argument through the socket (`ctl start` on a oneshot). | Oneshots run at boot, or through the `oneshot` socket op with `arg`. |
| `arg_rejected` | The oneshot argument is not `[A-Za-z0-9._-]{1,64}` or contains `..`. | |
| `not_oneshot` | The `oneshot` op on a unit that is not a oneshot. | |
| `unknown_op` | An operation the socket or `ctl` does not know. | |
| `uid_denied` | The peer's uid is not allowed (not the supervisor's uid, or not in `--uid`), or its credentials could not be read. | Run `ctl` as an allowed uid. |
| `peer_supervised` | The peer is a supervised process: inside the cgroup root (a service, the supervisor's leaf, an unknown cgroup), in a process group a service led, or gone before the check. A process in the root itself or `.control` is accepted only while the root is protected. | Run `ctl` from outside the services, e.g. an admin shell or the outer manager. |
| `frame_size` | A control frame is empty or over 64 KiB. | |
| `root_required` | `diff`, `apply`, `rollback` or `activate` from a peer whose effective uid is not 0. | Run `ctl` as root. |

## Live catalog changes (`ctl diff`, `apply`, `rollback`, `validate`)

| Code | Meaning | What to do |
| --- | --- | --- |
| `catalog_path` | The `--dir` sent with `diff` or `apply` is not absolute. | Pass an absolute directory. |
| `catalog_refused` | A unit file in the candidate catalog was refused (`validate` lists them in `refused`). | Fix each refused file. |
| `catalog_sash` | The running or the candidate catalog has a sash unit: live changes replace runtimes, and a sash unit's described script, grant and mounts are not carried across. | Change such a catalog by restarting the supervisor. |
| `apply_rolled_back` | A unit of the new catalog failed to stop or start, and the old catalog and desired states were restored. `rolled_back` is true in the diff. | Read the failing unit's diagnostics; fix and apply again. |
| `rollback_failed` | Restoring the old catalog after a failed apply or activation also failed. The running state is the mix the response's diff describes. | Inspect `ctl status`; restart the supervisor if needed. |
| `no_previous_catalog` | `rollback` with no earlier `apply`. | |
| `shutting_down` | A catalog change while the supervisor is stopping. | |
| `signed_activation_required` | `apply` while running a deployment: unsigned catalogs are refused. | Stage a generation and `ctl activate`. |
| `new_policy_required` | `rollback` while running a deployment. | Restore earlier content with a newly signed, higher-sequence generation. |

## Journal

| Code | Meaning | What to do |
| --- | --- | --- |
| `journal_unavailable` | Log `journal_unavailable TOKEN`: `--log-dir` could not be opened; the supervisor runs without a journal (output stays in the in-memory tails). TOKEN is one of the codes below or `failed` (for example a read-only file system). | Fix the directory, then restart the supervisor. |
| `journal_path` | `--log-dir` is not absolute. | |
| `journal_limits` | Internal size limits out of range. | |
| `journal_perm` | The directory or a journal file fails the trusted walk, has group or other access, is not a regular file with one link, or is owned by someone other than root or the supervisor's uid. | `install -d -m 700 -o root /var/log/sahinit`. |
| `journal_busy` | Another supervisor holds the journal's lock. | One supervisor per journal. |
| `journal_torn_record` | The current file ends in a record larger than the limit without a newline; it is not repaired automatically. | Move the file aside. |
| `journal_size` | A journal file is over 64 MiB. | Move the file aside. |
| `journal_read` | `logs` or `events` could not read the journal. | Check the directory, the owner and that you run as it. |

## Deployments (`deploy`, `ctl activate`, `supervise --deployment-root`)

| Code | Meaning | What to do |
| --- | --- | --- |
| `deployment_path` | `--root` is not absolute and clean. | |
| `deployment_perm` | The root, a pointer or a generation file fails the trusted walk, has the wrong owner, or the root has group or other access. | `chmod 700`, owner root. |
| `deployment_busy` | Another `deploy` or activation holds the deployment lock. | Retry. |
| `deployment_size` | A unit file over 64 KiB, an artifact over 64 MiB, or a bundle over 256 MiB. | |
| `deployment_state` | `state.json` names an invalid generation. | Repair the pointer file from `deploy status` of a good copy. |
| `deployment_durability` | The active pointer was renamed but its directory could not be synced: the candidate runs and is active, but may not survive a crash. | Check the storage before the next change. |
| `deployment_jobs` | The policy has `jobs` or `offline_jobs`, or the manifest has `jobs` or `resources`. Boot jobs are not supported. | Remove them; run setup as oneshot units. |
| `deployment_sash` | A deployment unit is a sash unit. Deployments carry exec units only. | Deploy sash units through `--dir`. |
| `deployment_caps` | A deployment unit's sandbox lists capabilities. The signed policy does not cover them. | Run units that need caps through `--dir`. |
| `deployment_no_pending` | `ctl activate` with no pending generation. | `deploy stage` first. |
| `deployment_not_configured` | `ctl activate` on a supervisor without `--deployment-root`. | |
| `boot_in_progress` | `ctl apply`, `rollback` or `activate` before the boot waves ended, after a strict boot failed, or while the supervisor stops. | Wait for boot. |
| `bootstrap_refused` | `deploy bootstrap` with an active generation already, or no pending one. | Use `ctl activate` for later changes. |
| `manifest_read` | The manifest file could not be read (missing, wrong owner or mode, over 256 KiB). | |
| `manifest_shape` | Wrong `version`, missing arrays, no units, over 256 units or artifacts, or nesting too deep. | See [the bundle format](../deployments.md#bundle-format). |
| `manifest_path` | A manifest path is absolute, unclean, escapes the bundle, repeats, or its digest is not 64 lowercase hex digits. | |
| `manifest_unit` | A unit path is not `units/NAME.json` with a valid name. | |
| `manifest_artifact` | An artifact path is not under `artifacts/`. | |
| `manifest_exec` | A unit's `exec[0]` is not `@/artifacts/...` naming a manifest artifact. | |
| `catalog_digest` | The manifest's bytes do not hash to the policy's `catalog_sha256`. | Sign the manifest you ship, byte for byte. |
| `catalog_units` | The policy's unit list and the manifest's units differ in number. | |
| `catalog_dependencies` | A policy unit is missing from the manifest, or its `needs` differ from the unit file's. | |
| `generation_conflict` | A generation with this ID exists with a different policy, or an ID does not match its content. | |
| `generation_invalid` | A pointer names a malformed generation ID. | |
| `pending_changed` | The pending pointer changed during activation. | Retry `ctl activate`. |
| `activation_commit` | The new generation ran but the active pointer could not be written; the old catalog was restored. | Check the storage, then activate again. |
| `policy_unit_denied` | The policy does not admit this start now: the unit is not in it, or the policy is in grace and the unit is not in `offline_units`, or it is expired and this is not an automatic restart of a `runtime_restart_units` unit. | Renew the policy (stage and activate a newer one). |

## Host helpers (`sahinit host`)

| Code | Meaning | What to do |
| --- | --- | --- |
| `device_timeout` | `device-wait` timed out before the device node appeared. | Check the driver or raise `--timeout`. |
| `notify_pipe_missing` | `notify-adapter` was not given the notify pipe as fd 3: the unit is not `"ready": "notify"`. | Set `"ready": "notify"`. |

## Control socket (supervise start)

| Code | Meaning | What to do |
| --- | --- | --- |
| `socket_perm` | The socket's directory fails the trusted walk, or is writable by group or other (including sticky `/tmp`). | Use a private directory, e.g. `install -d -m 700 /run/sahinit`. |
| `socket_busy` | Another supervisor holds `SOCKET.lock`. | Stop it, or use another socket. |
| `socket_exists` | Something other than our own stale socket is at the path, or the lock file is not ours. | Remove it after checking nothing uses it. |
| `socket_group` | `--uid` allows another uid but no `--gid` was given. | Add `--gid GID`. |

## Cgroups

| Code | Meaning | What to do |
| --- | --- | --- |
| `cgroup_unavailable` | No cgroup2 at `/sys/fs/cgroup`, or the supervisor's cgroup is not writable (not delegated). | Run under `Delegate=yes`, in a private cgroup namespace, or as PID 1; or use `--no-cgroups`. |
| `cgroup_busy` | Another supervisor holds the cgroup root's lock. | One supervisor per root. |
| `cgroup_controller` | A unit's limits need a controller the root does not offer, or limits without cgroups. Printed as `cgroup_controller FILE`. | Enable the controller above the root, or remove the limit. |
| `cgroup_join` | The child could not join its service cgroup. | Check the root is not populated by other processes; see the diagnostics. |
| `cgroup_stuck` | A service cgroup did not empty within the unit timeout after kill-all; the service is failed. | Look for processes in uninterruptible sleep (`D` state); the next start retries. |
| `cgroup_trusted` | Printed by `plan` as `cgroup_trusted FILE`, and a status field: the unit can leave its cgroup, so cgroup guarantees are not promised for it. | Informational; sandbox it with a non-root uid to make it untrusted. |
| `cgroup_leftover` | Log `cgroup_leftover NAME.service`: a service cgroup an earlier instance left was killed and removed. | Informational. |
| `cgroup_root_unprotected` | Log `cgroup_root_unprotected ROOT`: no controller is enabled below the root, so root and `.control` members are refused as peers. | Move other processes out of the root so controllers can be enabled; run `ctl` from outside the root. |
| `cgroup_stray` | Log `cgroup_stray PID`: a process in the supervisor's leaf other than sahinit was killed. | Investigate a cgroup-trusted service. |
| `cgroup_stray_cgroup` | Log `cgroup_stray_cgroup PATH`: an unknown cgroup under the root was killed and removed. | Investigate a cgroup-trusted service. |
| `cgroup_root_member` | Log `cgroup_root_member PID`: a process sits in the root itself or `.control` (left alone, logged once). | Normally the outer manager; informational. |

## Strict boot (PID 1)

| Code | Meaning | What to do |
| --- | --- | --- |
| `boot_refused` | With `--boot-strict`, a unit file, a limit or a sash unit was refused, so the whole boot is refused. | Run `sahinit plan --dir DIR` (and `supervise` without `--boot-strict` in a test) to see each refusal. |
| `boot_service_failed` | Log `boot_service_failed NAME`: in strict boot an essential unit (every boot unit not marked `"essential": false`) was not ready when the boot waves ended, or later became `failed` (a non-zero exit, a signal, a failed start, `restart_limit`, `watchdog`) or `stopped` on its own, or waits on a `needs` provider that did. The supervisor stops and PID 1 enters recovery. | Read `NAME`'s diagnostics in recovery; fix (or mark the unit `"essential": false`) and send SIGHUP to PID 1. |

## sash units: load

| Code | Meaning | What to do |
| --- | --- | --- |
| `sash_unit_field` | A sash unit sets `exec`, `type`, `ready`, `timeout`, `execution.groups`, `execution.directory` or `execution.environment`. | Remove it; the service script owns those. |
| `sash_root` | A sash unit has no uid/gid or uid or gid 0. | Run it as a dedicated service account. |
| `sash_sandbox` | A sash unit has no `sandbox`. | Add one. |
| `sash_cgroup_trusted` | A sash unit is cgroup-trusted (a cgroupfs path in `read_write_paths`). | Remove it. |
| `sash_caps` | A sash unit's sandbox lists capabilities. | Remove them; sash units cannot hold capabilities. |
| `sash_file_perm` | The service script fails the trusted walk or the owner and mode rule, or has a setuid/setgid/sticky bit. | `chown root:root`, `chmod 644`. |
| `sash_grant_perm` | The grant file fails the same checks, or is not mode exactly 0600. | `chown root:root`, `chmod 600`. |
| `sash_binary` | Log `sash_binary FILE`: `--sash` does not resolve to a trusted executable. | Install sash at a root-owned path. |
| `sash_fleet_key` | No `--sash-fleet-pub`, or the key file fails its checks or format. | See [files](config-files.md#fleet-public-key). |
| `sash_floor_store` | Log `sash_floor_store FILE`: no `--sash-floor-dir`, or it cannot be opened. | Create it 0700, owned by the supervisor's uid. |
| `sash_cgroups` | Sash units need cgroups (`--no-cgroups` or no cgroup root). | Run with cgroups. |
| `sash_describe` | `sash --describe` failed, exited non-zero, timed out (5 s), printed over 1 MiB or malformed output, or named no `start`/`run` entry. | Run `sash --describe FILE` as the unit's user and fix the script. |
| `sash_name_mismatch` | describe's `name` differs from the unit name. | |
| `sash_identity_mismatch` | describe's `user`/`group` are missing or do not resolve to the unit's uid/gid. | Create the account, or fix the unit's ids. |
| `sash_order_mismatch` | describe's dependency names are invalid, or differ from the unit's `needs`/`after`/`wants`. | Remove the unit's lists or make them match. |
| `sash_lifecycle_mismatch` | The unit's `restart` disagrees with describe's. | Remove it from the unit. |
| `sash_lifecycle_limit` | A ready or stop timeout or restart delay over 5 minutes, a restart burst over 5, or a restart window shorter than the restart delay. | Lower it in the script. |

## sash units: grant and floor (before every start)

Every grant failure except `sash_floor_busy` fails the unit without restart and is logged as
`sash_grant SERVICE TOKEN`.

| Code | Meaning | What to do |
| --- | --- | --- |
| `sash_grant` | Log prefix: `sash_grant SERVICE TOKEN`. | Read TOKEN below. |
| `sash_unavailable` | The supervisor has no sash configuration (key or floor store) for a start. | Start `supervise` with the sash flags. |
| `grant_missing` | The grant file cannot be read. | |
| `grant_bad_shape` | The grant is not a well-formed `sash/2` document with purpose `service`, or is over 64 KiB, or has a bad root path. | Re-issue it. |
| `grant_bad_sig` | The signature does not verify with the fleet key (also a sash/1 or v1-domain signature). | Re-sign with the current fleet key. |
| `grant_star` | A list holds `"*"`. | Re-issue with explicit entries. |
| `grant_root_slash` | `file_read`/`file_write` names `/`. | |
| `grant_expired` | `exp` is set and in the past. | Re-issue. |
| `grant_service_mismatch` | The grant's `service` is not this unit's name. | |
| `grant_identity_mismatch` | The grant's `user`/`group` differ from describe's. | |
| `sash_grant_revoked` | The grant's `serial` is below the service's floor. | Install a grant with a serial at or above the floor. |
| `sash_floor_busy` | A floor install held the store lock for over 2 s (every grant check takes that lock, so a concurrent `floor-install` can cause it). Transient; the restart policy may retry. | Retry. |
| `sash_floor_missing` | `sash floor-show`: no floor for that service. | Informational. |
| `sash_floor_bad_shape` | A floor document or service name is malformed. | |
| `sash_floor_bad_signature` | A floor does not verify with the fleet key. | Re-sign. |
| `sash_floor_rollback` | A floor lower than the installed one. | Floors only rise. |
| `sash_floor_conflict` | A different floor with the same `min_serial`. | Issue a higher `min_serial`. |
| `sash_floor_store_failed` | The state directory or a floor file fails its owner/mode checks, cannot be read, does not verify with the current key, or a commit failed. Fails closed: starts are refused. | Fix ownership (0700/0600, supervisor uid); after a key rotation see [operations](operations.md#rotating-the-sash-fleet-key). |

## sash units: running

| Code | Meaning | What to do |
| --- | --- | --- |
| `sash_config` | An entry exited 2: a configuration or grant error in sash. No restart. Logged as `sash_entry_error SERVICE ENTRY TOKEN`. | Read TOKEN (sash's first stderr word). |
| `sash_entry_error` | Log prefix: `sash_entry_error SERVICE ENTRY TOKEN`. | |
| `sash_not_ready` | The entry exited 3: not ready in time. Restart policy applies. | |
| `not_sash` | `reload` or `check` on an exec unit. | |
| `no_entry` | The script has no such entry. | |
| `not_running` | `reload`/`check` while the service is not running. | |
| `unhealthy` | The `check` entry did not exit 0. | |
| `check_read_only` | A check session asked for a mutating verb. | Keep `check` read-only. |
| `unknown_service` | `svc.status` named no such service. | |
| `unknown_name` | A verb named a process not in this service's table. | |
| `name_in_use` | `svc.spawn` reused a running process name. | |
| `too_many_names` | More than 64 process names. | |
| `ceiling` | A spawn cap is outside the unit's sandbox caps, or a limit is above sahinit's ceiling or unknown. | |
| `caps_unsupported` | A spawn asked for a capability; the sandbox cannot grant one yet. | Drop the cap. |
| `env_refused` | A spawn env name is not in the grant's `env_names`, malformed, or denylisted. | See [environment](environment.md). |
| `denied` | A verb outside the grant: an unlisted program, identity, cwd, path, probe target or owner; a target the service does not own. | Extend the grant, or fix the script. |
| `stream_denied` | A `file:` stream could not be opened beneath its root as the child. | Check the path is under `file_write` and not a symlink. |
| `exists` | A file verb's target exists as the wrong kind, or a mount point is already mounted by a service. | |
| `not_empty` | `rm` of a non-empty directory. | |
| `hardlink` | A file verb's target has more than one link. | |
| `mount_opt_refused` | A mount type or option outside the allowlist, or a remount option that would change the superblock. | |
| `mount_overlap` | A mount point at, under or above a `file_write` root. | |
| `not_mounted` | An umount or remount of a mount this service did not make (or that has changed). | |
| `sash_mount_leftover` | Log `sash_mount_leftover SERVICE DIR`: a mount from an earlier instance on this boot was removed at start. | Informational. |
| `sash_mount_forgotten` | Log `sash_mount_forgotten SERVICE DIR`: a recorded mount was no longer sahinit's and was dropped. | Investigate who replaced it. |
| `sash_mount_state_corrupt` | Log: `sash-mounts.json` is not valid JSON; it is reset. | Check for leftover mounts by hand. |
| `sash_umount` | Log `sash_umount SERVICE TOKEN`: unmounting a service's mount at its end failed. | Unmount by hand. |
| `sash_output` | Log `sash_output SERVICE NAME STREAM: LINE`: a spawned process's journal line. | |
| `sash_output_dropped` | Log `sash_output_dropped SERVICE N`: N journal lines over the rate limit (200 at once, 50/s) were not logged. | |

## Boot policy (`sahinit policy`)

| Code | Meaning | What to do |
| --- | --- | --- |
| `policy_read_failed` | The trust or document file cannot be opened (missing, a symlink), is not regular, or is too large. | |
| `policy_bad_trust` | The trust file's owner or mode is unsafe, or its contents are invalid. | See [files](config-files.md#boot-policy-files). |
| `policy_bad_shape` | The envelope or payload is not exactly the schema. | Re-issue. |
| `policy_bad_signature` | The signature does not verify with the key the envelope names (or the key is not in the trust file). | Check `keys`; see key rotation in [operations](operations.md#rotating-boot-policy-keys). |
| `policy_host_mismatch` | Tenant, host or enrollment ID differs from the trust file. | |
| `policy_recovery_mismatch` | The recovery profile ID differs from the trust file. | |
| `policy_ceiling` | A validity, grace, refresh or job time is above the trust file's ceiling. | |
| `policy_lifetime_cap` | A `never` policy where the trust file says `max_lifetime: renew`. | |
| `policy_rollback` | A lower sequence than the cache, or a lower catalog generation. | |
| `policy_sequence_conflict` | Different payload bytes at the cached sequence. | Issue a higher sequence. |
| `policy_generation_conflict` | A permission, catalog or lifetime change at the same catalog generation. | Raise `catalog_generation`. |
| `policy_revoked` | The policy's sequence is below the installed floor. | Install a newer policy. |
| `policy_floor_missing` | No floor is installed (`floor-show`). | Informational. |
| `policy_floor_rollback` | A floor lower than the installed one. | |
| `policy_floor_conflict` | A different floor with the same `min_sequence`. | |
| `policy_missing` | No cached policy. | `policy cache` first. |
| `policy_store_failed` | The cache directory or a file in it fails its checks, or a commit failed (the store then fails closed). | Fix ownership (owner-only, effective uid); reopen and retry. |
| `policy_store_busy` | Another process holds the cache lock. | Retry. |
| `policy_expired` | A `renew` policy is in grace or expired. | Renew. |
| `policy_not_yet_valid` | Before `not_before`. | |
| `policy_clock_uncertain` | A `renew` policy needs a trusted clock: no `--trust-system-clock`, not Linux, or trust was lost. | Establish trusted time and pass the flag. |
| `policy_clock_rollback` | Library only: a trusted time correction would move the anchored clock backwards. The CLI never applies corrections. | |
| `policy_not_renewing` | Internal: the host does not renew; `refresh` prints `not_renewing` and exits 0. | |
| `policy_refresh_config` | The endpoint is not a plain `https://` URL with a host. | |
| `policy_refresh_credential` | The credential file fails its owner, mode, link or content rules. | `chmod 600`, owned by the worker uid. |
| `policy_refresh_transport` | Connection, TLS (1.3 only, system roots) or timeout failure. | |
| `policy_refresh_http` | A status other than 200 (401/403 excepted), or a redirect. | |
| `policy_refresh_denied` | 401 or 403. | Check the credential. |
| `policy_refresh_encoding` | A `Content-Encoding` other than `identity`. | |
| `policy_refresh_size` | The response body is over 384 KiB. | |
| `policy_refresh_stale` | The response is identical to the cache. | The issuer must issue a new sequence. |
| `not_renewing` | `refresh` event: this host does not renew; exit 0. | |
| `clock_uncertain` | Report `state`: no trusted clock for a `renew` policy. Other states: `valid`, `grace`, `expired`, `not_yet_valid`, `missing`, `revoked`. | |
| `metadata_only` | The `enforcement` value in every policy report: nothing is enforced. | |
