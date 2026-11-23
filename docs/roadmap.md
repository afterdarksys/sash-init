# Service-manager roadmap

The current implementation is a userspace supervisor, not a bootable PID 1.
Prioritize operational correctness and migration coverage before machine boot.

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
| 1 | Dependency-aware reverse shutdown, required-service failure propagation, targeted restart transactions | Startup ordering alone does not preserve application lifecycle contracts. |
| 2 | Config validation/diff, atomic reload and rollback, stable desired/observed state | Change live configuration without interrupting unrelated services. |
| 2 | Readiness adapters (including sd_notify), health checks, watchdogs, restart backoff/jitter | Handle stuck or unhealthy processes and prevent restart storms. |
| 2 | Event subscription and explain/why-not-running command | Make routine diagnosis easier than interpreting generic failure tokens. |
| 2 | Socket activation, timers with missed-run policies, path triggers | Needed for common systemd migrations and idle efficiency. |
| 2 | Per-user supervision and scoped control permissions | Delegate administration without giving every client total control. |
| 3 | Versioned migration IR, source exports, drop-in resolution, mapping overrides and native source-vs-target Docker tests | Expand conversion coverage with explicit semantic differences and reproducible evidence. |
| 2 | I/O limits and weights, slices, per-service cgroup delegation | Batch 1 covers memory, CPU and PIDs only. |
| 3 | PID 1 reaping/signals, mounts/devices, cgroup2 mount and root controller setup, emergency recovery, reboot/poweroff and VM boot tests | Required before offering host init replacement; Docker tests alone cannot prove this. |

Migration v1 supports a small static subset and emits blockers rather than silently
dropping unsupported directives. Expand it alongside runtime capabilities, using
the execution identity and environment support now available. See [migration.md](migration.md).

Design proposal: [renewable SystemAPI boot policy](design/renewable-boot-policy.md)
specifies cached boot authorization, periodic renewal, offline grace, sash job
scoping, and recovery behavior. Local metadata verification, durable caching, time states, and CLI inspection are
implemented, with an optional renewal worker for `renew`-mode policies against a
provisioned HTTPS endpoint; see [boot-policy metadata](boot-policy.md). The
SystemAPI issuer, artifact verification, and runtime enforcement remain pending.
