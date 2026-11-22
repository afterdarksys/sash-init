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

## Decisions made during the build (2026-11-22)

1. **Sticky parent directories** are accepted for the executable path (as `/tmp`): a sticky directory lets no one replace a file they do not own. Every parent directory is also checked for owner (root or the supervisor's uid), which is stricter than the table above asks. After review, links are resolved one component at a time, and every directory the walk passes through must meet this rule: the directory holding each link, and every directory a link target leads into. A link in a user's `~/bin` is `exec_perm`. Debian's `/bin -> usr/bin` and `/etc/alternatives` pass, because those directories are root-owned. Sandbox paths and the control socket's directory use the same walk.
2. **An executable that cannot be resolved at load time** leaves the unit loaded with an empty `Path`. Launch then resolves and checks it with the same rules, so a binary installed later still works and is still checked.
3. **A direct (unsandboxed) launch on Linux** runs a binary through `/proc/self/fd/N`, where N is a close-on-exec copy of the checked fd, numbered 10 or above. The forked child still holds it at execve, and the kernel closes it at exec, so the binary keeps no fd. Only a `#!` script keeps its fd, as fd 4, because the interpreter opens `/proc/self/fd/4`. A script's interpreter must be an absolute path that passes the same trusted walk and is not itself a script. `#!/usr/bin/env` and relative interpreters are refused with `exec_interp`; this was smaller than resolving against a fixed PATH. Direct launches need `/proc`, which PID 1 mounts before starting any service.
4. **`landlock_abi`** exists, but no unit field asks yet for a right newer than ABI 1. Below ABI 3, TRUNCATE stays unrestricted instead of refusing read-write units.
5. **The H7 fallback on kernels before 6.9 and on macOS** still signals a group with `kill(-pid)` after its leader is reaped, so that leftover children die. A narrow pid-reuse race remains there until the cgroups batch, which closes it.
6. **Not exercised:** the older-kernel fallbacks (no `close_range`, older Landlock ABIs, no group pidfd signal). Docker runs kernel 7.0. A QEMU matrix belongs to the PID 1 harness.
7. **`peer_supervised` after review** matches a peer against every process group a service has led, in this start or an earlier one, until that group is empty. On Linux 6.9+ emptiness is asked through the group's pidfd, so a reused number counts as empty. This catches a leader's leftover children. Two residuals remain until the cgroups batch: a service that leaves its group with `setsid` or `setpgid`, and a peer whose pid is reused between its request and the check. `SO_PEERPIDFD` is not used: x/sys has no constant for it, and its value differs by architecture.
8. **The control socket after review** is bound in a fresh 0700 directory beside the target, then chmodded and chowned there and hard-linked into place, so no chmod follows a link at the public path. Its parent directory must pass the trusted walk (`socket_perm`). An exclusive flock on `PATH.lock` is taken before the stale check and held until Close, so a second supervisor gets `socket_busy`. A lock file that is not ours is `socket_exists`. No test can make the old chmod-through-a-link race fire deterministically. The tests show that a link at the path is never followed and the parent directory is enforced.

## After the re-check (2026-11-22)

9. **The socket's directory** must be writable by its owner only. A sticky directory such as `/tmp` is refused with `socket_perm`, because anyone there could pre-create the socket or its lock and keep the supervisor from starting. Use a private directory, for example `/run/sahinit/`.
10. **`#!` lines** are split on space and tab only, as the kernel splits them. A CR stays part of the interpreter path and is checked that way. `#!/bin/busybox env python` and other multi-call `env` forms are refused with `exec_interp`, like `env` itself.
