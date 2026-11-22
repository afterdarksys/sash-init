# Service-manager roadmap

The current implementation is a userspace supervisor, not a bootable PID 1.
Prioritize operational correctness and migration coverage before machine boot.

| Priority | Feature | Why it matters |
| --- | --- | --- |
| 1 | Captured stdout/stderr, bounded rotation, follow/search, exit status and startup diagnostics | Service failures must be explainable; output is currently discarded. |
| 1 | Explicit user/group, supplementary groups, working directory, environment/environment files | Essential for most real services and migration without accidentally running workloads as root. |
| 1 | cgroup v2 membership, kill-all, CPU/memory/PID limits and accounting | Track descendants even after daemonization or process-group changes. |
| 1 | Dependency-aware reverse shutdown, required-service failure propagation, targeted restart transactions | Startup ordering alone does not preserve application lifecycle contracts. |
| 2 | Config validation/diff, atomic reload and rollback, stable desired/observed state | Change live configuration without interrupting unrelated services. |
| 2 | Readiness adapters (including sd_notify), health checks, watchdogs, restart backoff/jitter | Handle stuck or unhealthy processes and prevent restart storms. |
| 2 | Friendly ctl CLI and event subscription, explain/why-not-running command | Make routine diagnosis easier than interpreting generic failure tokens. |
| 2 | Socket activation, timers with missed-run policies, path triggers | Needed for common systemd migrations and idle efficiency. |
| 2 | Per-user supervision and scoped control permissions | Delegate administration without giving every client total control. |
| 3 | Versioned migration IR, source exports, drop-in resolution, mapping overrides and native source-vs-target Docker tests | Expand conversion coverage with explicit semantic differences and reproducible evidence. |
| 3 | PID 1 reaping/signals, mounts/devices, emergency recovery, reboot/poweroff and VM boot tests | Required before offering host init replacement; Docker tests alone cannot prove this. |

Migration v1 supports a small static subset and emits blockers rather than silently
dropping unsupported directives. Expand it alongside runtime capabilities, beginning
with logging and execution identity/environment. See [migration.md](migration.md).
