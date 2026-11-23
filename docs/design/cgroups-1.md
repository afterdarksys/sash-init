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
4. **Peer identification.** The control socket reads the peer pid's `/proc/<pid>/cgroup`. A peer whose cgroup is a service cgroup, or below one, is `peer_supervised`. The read happens after the request is read, as today. A pid reused between request and check now matches only if the new process is also in a service cgroup, so the race can only cause a refusal, never an acceptance.
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
