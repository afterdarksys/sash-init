# Service-manager roadmap

The [reference documentation](reference/README.md) describes what exists today;
this page is what does not, yet. Current scope, stated plainly:

- `supervise` under an existing init is the supported mode.
- PID 1 mode is experimental: initramfs QEMU boots only, no persistent-disk
  teardown proof, no switch-root, storage discovery or watchdog.
- Boot policy is metadata only: nothing admits or refuses a unit from it,
  and there is no SystemAPI issuer.
- sash services (batches 1 and 2) work against test-made grants and floors;
  there is no fleet signer, the grant's `host` is not checked, and spawned
  processes cannot receive capabilities.
- Sandboxed units cannot hold capabilities, and the network is not confined.

The userspace supervisor now has an experimental Linux PID 1 parent for an
already available local root. See [host init](host-init.md) for scope and VM tests.
Broader machine/storage integration and production qualification remain.

Delivered: numeric UID/GID and supplementary groups, explicit working directory
and environment, bounded in-memory output tails, exit diagnostics, recent lifecycle
events, and a local ctl CLI. See [execution and diagnostics](execution.md).

Also delivered: cgroup v2 membership, with one cgroup per service joined before
exec. Kill-all goes through `cgroup.kill`, or freeze and kill on older kernels.
Memory, CPU and PID limits are enforced and their usage is reported in status,
and control-socket peers are identified by cgroup. `--no-cgroups` is the visible
fallback. See [cgroups](execution.md#cgroups) and
[the batch contract](design/cgroups-1.md).

| Priority | Feature | Why it matters |
| --- | --- | --- |
| 1 | Persistent stdout/stderr retention, bounded rotation, follow/search | In-memory tails and exit diagnostics now exist; durable history is still needed. |
| 1 | Environment files, account-name resolution, execution-context migration | Numeric identities and explicit context now exist; converters still reject unsupported source directives. |
| 1 | Targeted required-service failure propagation and restart transactions | Reverse shutdown is implemented; strict host boot currently recovers the whole supervisor on an essential service failure. |
| 2 | Config validation/diff, atomic reload and rollback, stable desired/observed state | Change live configuration without interrupting unrelated services. |
| 2 | Readiness adapters (including sd_notify), health checks, watchdogs, restart backoff/jitter | Handle stuck or unhealthy processes and prevent restart storms. |
| 2 | Event subscription and explain/why-not-running command | Make routine diagnosis easier than interpreting generic failure tokens. |
| 2 | Socket activation, timers with missed-run policies, path triggers | Needed for common systemd migrations and idle efficiency. |
| 2 | Per-user supervision and scoped control permissions | Delegate administration without giving every client total control. |
| 3 | Versioned migration IR, source exports, drop-in resolution, mapping overrides and native source-vs-target Docker tests | Expand conversion coverage with explicit semantic differences and reproducible evidence. |
| 2 | I/O limits and weights, slices, per-service cgroup delegation | Batch 1 covers memory, CPU and PIDs only. |
| 3 | Persistent-root boot/teardown tests, storage discovery, device hotplug, login/PTY setup and watchdogs | Minimal PID 1 reaping/signals, pseudo mounts, cgroup root setup, recovery and power operations are implemented with an initramfs QEMU harness. |

Migration v1 supports a small static subset and emits blockers rather than silently
dropping unsupported directives. Expand it alongside runtime capabilities, using
the execution identity and environment support now available. See [migration.md](migration.md).

Design proposal: [renewable SystemAPI boot policy](design/renewable-boot-policy.md)
specifies cached boot authorization, periodic renewal, offline grace, sash job
scoping, and recovery behavior. Local metadata verification, durable caching, time states, and CLI inspection are
implemented, with an optional renewal worker for `renew`-mode policies against a
provisioned HTTPS endpoint; see [boot-policy metadata](boot-policy.md). The
SystemAPI issuer, artifact verification, and runtime enforcement remain pending.
