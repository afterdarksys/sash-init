# sahinit cgroups, batch 1: contract

2026-11-23. Roadmap item 1. Ryan approved the order on 2026-11-22: renew mode, then cgroups, then secsvc batch 2, then sash init phase 1. Branch: `feat/cgroups`.

## Goal

A service is its cgroup, not its process group. Leftover children, processes that called `setsid`, and double forks all stay in the service's cgroup. Stopping, restarting or failing a service kills everything in that cgroup. The control socket identifies a supervised peer by its cgroup, not by its process group. This closes the residuals left by hardening batch 1:
- `setsid` escapes;
- a pid reused between a peer's request and the check;
- the pre-6.9 `kill(-pid)` race.

## Rules

1. **cgroup v2 only.** At startup, sahinit uses the unified hierarchy mounted at `/sys/fs/cgroup`. In the userspace (non-PID-1) mode this is sahinit's own cgroup, which must be delegated to it: writable, with the controllers it needs. Without a usable delegated cgroup, `supervise` refuses with `cgroup_unavailable` unless `--no-cgroups` is given. That flag keeps today's process-group behaviour and is reported in status and diagnostics, never silently.
2. **One cgroup per service.** Each service gets `<root>/<service>.service`, created with mode 0755 owned by root, and removed after the service is stopped and empty. The child joins its cgroup before exec. Use `clone3(CLONE_INTO_CGROUP)` through `SysProcAttr.UseCgroupFD`/`CgroupFD` where available. Otherwise the helper writes its own pid to `cgroup.procs` before exec. A child that cannot join fails to start with `cgroup_join`.
3. **Kill-all.** Stop, restart and failure write `1` to `cgroup.kill` (Linux 5.14+). The service counts as stopped only once `cgroup.events` reports `populated 0`, or the stop timeout expires, in which case it is marked failed with `cgroup_stuck`. Without `cgroup.kill`, freeze the cgroup, send SIGKILL to every pid in `cgroup.procs`, then thaw, in a loop until the cgroup is empty.
4. **Peer identification.** The control socket pins the peer when it accepts the connection: through `SO_PEERPIDFD`, otherwise through `pidfd_open` on the `SO_PEERCRED` pid, otherwise through its start time. After the request is read, it reads `/proc/<pid>/cgroup`. A peer whose cgroup is the root or below it is `peer_supervised`. The request is also refused unless the pinned process still exists after that read. A pid reused while the request is read therefore causes a refusal, never an acceptance. Without `SO_PEERPIDFD`, a reuse between connect and accept remains a residual. (Amended after review; the first version read the pid only after the request, which a peer controls the timing of.)
5. **Limits (optional unit fields).** `memory_max`, `cpu_max` and `pids_max` are validated at load and written before the child starts. A controller that is not available refuses the unit with `cgroup_controller`; it is never silently ignored. Status shows the limits and the current usage from `memory.current`, `pids.current` and `cpu.stat`.
6. **Process groups stay** as a secondary mechanism for terminal signals and for `--no-cgroups`. With cgroups enabled, the pidfd and process-group code is no longer what decides a service has stopped.
7. **Not PID 1 yet.** Mounting cgroup2 and enabling controllers in the root cgroup belong to the PID 1 milestone. This batch documents what the operator or the outer manager must delegate. Example: systemd's `Delegate=yes`, for testing sahinit under systemd.

## Tests

Each test runs on Linux as root in Docker (`--cgroupns=private`, with a writable cgroup2 mount), and is skipped elsewhere with a clear message:
- A `setsid` double fork is killed on stop.
- A leftover child is killed on restart.
- A peer that left its process group is still `peer_supervised`.
- `memory_max` and `pids_max` are enforced and an unknown controller is refused.
- `cgroup.events` decides stopped.
- `--no-cgroups` behaves as before.
- The freeze-and-kill fallback, through a test hook that hides `cgroup.kill`.

Each new check needs a test that fails when the check is reverted. Plus `./build.sh` and the full Docker root suite.

## Out of scope

- I/O limits and weights.
- Per-service delegation to the service itself.
- Systemd-style slices.
- The PID 1 root cgroup setup.

## Decisions made during the build (2026-11-23)

1. **The supervisor's leaf.** When the root is the supervisor's own cgroup, sahinit first moves into `ROOT/supervisor`, so the root holds no process and controllers can be enabled for the service cgroups (cgroup v2's "no internal processes" rule). Enabling `cpu`, `memory` and `pids` is best effort: a root that still holds other processes refuses with EBUSY. A missing controller refuses only the units whose limits need it. At startup each one is named on stderr as `cgroup_controller FILE` and left out, as `unit_perm` units are. A launch checks again.
2. **The main process's exit ends the service.** Whenever the main process exits (stop, restart, crash, a clean exit, or a oneshot's exit), everything left in the cgroup is killed before the exit is collected. The service has ended only once `populated 0` is reported and the cgroup is removed. The cgroup is created fresh at every start, and whatever an earlier start left is killed first. It is removed at every end, together with any cgroup a root service made below it.
3. **SIGTERM still goes to the process group only.** A child that left the group gets no SIGTERM; it is killed when the main process exits. A stop can take up to twice the unit timeout: the SIGTERM grace, then emptying the cgroup. `cgroup_stuck` marks the service failed, and `Stop` and `Shutdown` return it. The next start tries again to empty the cgroup.
4. **The SIGTERM race before 6.9 is closed with cgroups:** `kill(-pid)` is sent only while the leader is unreaped. After that, only the pidfd path, or the cgroup, reaches the service. SIGKILL always goes through `cgroup.kill`.
5. **clone3 fallback.** clone3 into the cgroup is always tried first. A Start that fails with ENOSYS or E2BIG is followed by a probe: the supervisor starts itself (`apply` with no handshake, which exits at once) into the cgroup with tiny arguments. Only if the probe fails the same way (Linux before 5.7, or a seccomp filter) does every later launch into a cgroup switch to the helper. An execve E2BIG never switches it. An unsandboxed launch then also goes through the helper: it applies no sandbox and claims `none`. The helper's first act is to wait on a sync pipe, fd 7. Meanwhile the supervisor writes the helper's pid into `cgroup.procs` with its own credentials and then sends one byte; end of file instead is `cgroup_join`. The helper never holds a `cgroup.procs` fd, so another process that ptraces it or calls `pidfd_getfd` on it gains nothing. On clone3, `cgroup_join` covers EBUSY (not a leaf), ENODEV (a removed cgroup) and EOPNOTSUPP. On the helper path it covers a failed write.
6. **The freeze-and-kill fallback** walks the frozen subtree, opens a pidfd for each pid, checks the pid is still in the subtree, and signals through the pidfd.
7. **`peer_supervised`** is the cgroup check, ORed with the old process-group check. Every cgroup below the root counts as supervised: the service cgroups, the supervisor's leaf, and any unknown cgroup. The supervisor never connects to its own socket. A pid whose `/proc/PID/cgroup` cannot be read, or reads ` (deleted)`, is supervised. The root itself does not count (decision 16), so `ctl` runs either outside the root or in the root itself.
8. **Limit formats.**
   - `memory_max`: a string of bytes, with an optional `K`, `M` or `G`, at least `1M`. It also writes `memory.swap.max=0` where that file exists, or a service over the limit would swap instead of being killed.
   - `pids_max`: an integer from 1 to 4194304.
   - `cpu_max`: `"QUOTA PERIOD"` in microseconds; the period runs from 1000 to 1000000, and the quota from 1000 to 1024 periods.
   - Anything else is `limit_invalid` at load.
9. **Status schema.** Rows gain `cgroups` (`enabled`, `disabled`, or `unsupported`), `cgroup`, `limits`, and `usage`. `usage` is present only while the service cgroup exists. Diagnostics gain `cgroups`. Neither `--no-cgroups` nor the `unsupported` mode prints anything; both are reported in status and diagnostics.
10. **Test hook.** `Root.TestHooks` hides `cgroup.kill` and replaces the `cgroup.events` read. It is exported because the supervisor tests use it to make a cgroup that never empties.
11. **Test setup.** `internal/cgroup/cgtest` moves every process of the namespace root into `/init.leaf` and enables the controllers below the root and below `/sahinit-test`. Each test then takes a fresh `/sahinit-test/PID/tN/root`. It refuses to run as non-root, on a read-only cgroup2, or on the host's real root cgroup (detected by the absence of `cgroup.events`), and the tests then skip with that reason. The `supervise` CLI tests that boot services pass `--no-cgroups`. `TestSuperviseCgroupUnavailable` runs where the supervisor's own cgroup is read-only (the plain Docker suite).
12. **Not exercised on a real kernel:** clone3 without CLONE_INTO_CGROUP, and a kernel without `cgroup.kill`. Both run only through hooks, because Docker runs Linux 7.0. The open-time credential check before 5.16 is not exercised either.

## After the adversarial review (2026-11-23)

13. **Escapes through `cgroup.procs`.** A service running as the supervisor's uid, or as root without a sandbox, can write `cgroup.procs` anywhere in the root, since the root is delegated to that uid. Making the files read-only would not stop the owner, who can chmod them back. A root-only file would also break clone3 for a non-root supervisor, which needs write access on the common ancestor. So escapes are detected instead.
    - Moving into the root itself is refused by the kernel while controllers are enabled below it.
    - Superseded by decisions 17 and 18.
    - A process that escapes to a cgroup outside the root is not detected. Reaching one needs write access to `cgroup.procs` above the root, which delegation does not give.
14. **A restart in place.** When the supervisor's own cgroup is named `supervisor`, the root is its parent. A cgroup the operator happened to name `supervisor` is read the same way. Every `*.service` cgroup left under the root is killed and removed, named (`cgroup_leftover`), and is `cgroup_stuck` if one does not empty. This happens only once both locks are held (decision 19).
15. **Tests that inject what Docker cannot produce.**
    - Pid reuse: the pin's pid is pointed at another live process after the pinned one is reaped.
    - No pidfd: `pidfdOpen` returns ENOSYS.
    - An execve E2BIG: a synthetic error is handed to the probe.

## After the re-review (2026-11-23)

16. **Trust boundary (reviewer's decision).** A service with no sandbox, running as root or as the supervisor's uid, is **trusted with respect to its cgroup membership**. Root, or the same uid, can always leave its cgroup or kill sahinit. Kill-all, the limits, and `peer_supervised` are promised only for the other services: sandboxed ones, or ones running as another uid. Those cannot write any `cgroup.procs` under the root. `plan` names each trusted unit on stderr as `cgroup_trusted FILE`, and each status row carries `cgroup_trusted`. As a consequence, a process in the root itself is not `peer_supervised`. Only the outer manager (`docker exec`, systemd's ExecReload/ExecStartPost, an operator's `ctl`) or a trusted service can put a process there.
17. **The sweep walks the whole root.**
    - A cgroup directly under the root that is neither the leaf nor `NAME.service` of a running service is unknown. Everything in it is killed (`cgroup.kill`, or the freeze fallback), it is removed within one second, and it is logged as `cgroup_stray_cgroup PATH`.
    - Every cgroup below the leaf is handled the same way.
    - A process in the leaf other than sahinit is killed (`cgroup_stray PID`).
    - A process in the root itself is not killed, and is logged once per pid as `cgroup_root_member PID`.
    - The sweep runs when a service ends, on each control request, at shutdown, and every `--cgroup-sweep` (default 30s; 0 turns the timer off). It is skipped while a launch may have a helper waiting in the leaf.
    - A trusted service that moves into a sibling service's cgroup cannot be detected (decision 16).
18. **The root's flock.** Open takes `LOCK_EX|LOCK_NB` on the root directory before it changes anything: before moving into the leaf, before enabling controllers, before any sweep. A second supervisor on the same root is `cgroup_busy` and touches nothing. The lock is held until exit.
19. **Lock order.** The cgroup root's lock (Open) comes first, then the control socket's lock (Listen), then the leftover cleanup. A supervisor that fails either lock exits before any cleanup, so two supervisors on one root or one socket cannot kill each other's services.
