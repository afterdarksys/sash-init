# sahinit hardening, batch 1: contract

2026-11-22. Source: the independent audit of `main` at `6357537`. Ryan approved this batch on 2026-11-22. Branch: `fix/hardening-1`.

Every fix below comes with:
- a test that fails if the fix is reverted;
- a `Threats:` note in the code it changes;
- a named refusal code, matching the existing `internal/fail` codes.

## Fixes

| # | Problem | Fix |
| --- | --- | --- |
| H1 | A sandboxed unit still runs as uid 0. It can connect to the control socket and stop other services. It can also signal any root process. | **(a)** A unit with a sandbox must name a non-root `uid`. A sandboxed unit with uid 0 is refused at load with `sandbox_root`.<br>**(b)** The control socket refuses a peer whose pid belongs to the process group of any supervised service, with `peer_supervised`. It checks this on every request, not only at connect.<br>**(c)** The status no longer reports a sandbox label the service does not actually have. |
| H2 | File descriptors leak into children. The readiness channel is inferred from whether fd 5 happens to be open, so a stray runtime fd (cgroup `cpu.max`) became `SAHINIT_READY_FD`. | **(a)** The helper is told explicitly whether the service uses notify readiness. Nothing is inferred from which fds are open.<br>**(b)** Before exec, every fd from 3 up is closed (`close_range`, or a loop when it is unavailable). The only exception is the one readiness fd, which is passed deliberately.<br>**(c)** A test lists `/proc/self/fd` from inside a started service. |
| H3 | The sandbox works only on Linux 6.10 or newer, because it always requests Landlock ABI v5. | Detect the Landlock ABI and request only the access rights that ABI knows (best-effort, as the Landlock documentation recommends).<br>Fail closed only on these two conditions:<br>• Landlock is absent entirely: `landlock_unavailable`.<br>• The unit asks for a right the ABI lacks: `landlock_abi`.<br>The status reports the ABI that was applied. |
| H4 | Symlinked executables are refused, including Debian's `/bin/sh` and `/etc/alternatives` links. The same rule rejects sandbox paths such as `/lib` on merged-/usr systems. The check is also a time-of-check/time-of-use gap. | **(a)** Resolve the executable once at load. The resolved target must be a root-owned regular file whose parent directories are not writable by group or other.<br>**(b)** Exec the resolved, checked file through an fd (`execveat`/fexecve on Linux), so the file checked is the file run. Elsewhere, exec the resolved path.<br>**(c)** Sandbox paths are resolved the same way.<br>**(d)** The Linux tests pass on Debian, where `/bin/sh` is a link. |
| H5 | Unit files' owner and permissions are never checked. | Each unit file and the unit directory must be owned by root (or by the supervisor's own uid when it is not root). Neither may be writable by group or other. Any other unit file is refused with `unit_perm`, and the rest of the catalog still loads. |
| H6 | **(a)** The socket is chmod 0600, so the `--uid` allowlist does nothing.<br>**(b)** A socket file left by a crash blocks startup (`socket_exists`). | **(a)** The socket mode follows the allowlist: 0600 when only the owner is allowed, otherwise 0660 with a dedicated group. A uid outside the list is still refused by peer credentials.<br>**(b)** A leftover socket is removed only when it is a socket, owned by us, and nothing answers a connect on it. Anything else still refuses. |
| H7 | A pid is read under the lock and signalled after the lock is released, possibly after the process was reaped and the pid reused. | On Linux, hold a pidfd for each started process and signal through it (`pidfd_send_signal`). Elsewhere, signal under the lock, before reaping. |

## Out of this batch

- **Cgroups:** descendant cleanup, `setsid` escapes, resource limits. This is batch 2.
- **Trusted clock (audit item 9) and trust-key rotation (item 10).** These belong to the boot-policy lifetime work: never-expire by default, renewal as an option (`docs/design/policy-lifetime.md`).
- **PID 1 behaviour:** reaping, console, reboot.

## Verification

- `./build.sh` passes: race tests, vet, gofmt, and Linux cross-compilation.
- Linux tests run as root in `golang:1.26-bookworm`, which uses a Debian `/bin/sh` link.
- An adversarial review of the batch is done before any push.
