# Security model

What sahinit guarantees, what it assumes, and what it does **not** guarantee.
Consolidated from the `Threats:` notes in the code and the design decisions in
[hardening](../design/hardening-1.md), [cgroups](../design/cgroups-1.md),
[sash services 1](../design/sash-services-1.md) and
[2](../design/sash-services-2.md), and
[boot-policy lifetime](../design/policy-lifetime.md). Where this page and the
code disagree, the code is right and this page is a bug.

## Trust assumptions

- **Root and the supervisor's uid are trusted.** Everything sahinit reads
  that decides what runs as whom (unit files, the unit directory, executables
  and every directory above them, sash scripts and grants, the fleet key, the
  trust file) must be owned by root or the supervisor's uid and not be
  writable by anyone else. Anything else is refused rather than trusted.
- **Unit files are untrusted input** in shape: strict JSON, closed key sets,
  no duplicate keys (where `encoding/json` would silently keep the last),
  size limits, no symlinks.
- **The kernel is trusted**: Landlock, cgroup v2, pidfds, `openat2`.
- **The disk is not a security boundary against root.** Whoever is root can
  replace the binary, the catalog or the state directories.

## Guarantees

### What runs is what was checked

- `exec[0]`, `#!` interpreters, the sash binary and sash scripts are resolved
  once with the trusted walk (every directory from `/` owned by root or the
  supervisor's uid, not writable by others, sticky directories may be writable by others), so
  nobody else can swap a component between the check and the exec.
- On Linux the checked file is executed **through its open file
  descriptor**, so the inode checked is the inode run.
- `#!/usr/bin/env` and other PATH lookups are refused (`exec_interp`).
- A [deployment](../deployments.md) unit's executable is also hashed through
  that same descriptor on **every** launch and must match the SHA-256 in the
  signed manifest (`artifact_digest`); off Linux, or without a readable
  descriptor, the launch is refused (`verified_exec_unavailable`).

### A clean start

- Services never inherit the supervisor's environment; `SAHINIT_` names are
  reserved.
- Every file descriptor from 3 up is closed at exec except the deliberate ones
  (the readiness pipe; a script's fd 4; a sash session's fds 3 to 6).
- An explicit identity always replaces the supplementary groups.

### Sandbox (Linux)

- `no_new_privs` is always set; a sandboxed unit must run as a non-root uid
  (`sandbox_root`), checked at load and again in the helper.
- Landlock restricts file access to the listed paths, with the rights the
  kernel's ABI knows; the absence of Landlock, or of a needed right, refuses
  the start rather than weakening it.
- Capabilities: a unit without `caps` holds none (the ambient set is
  cleared). A unit with `caps` holds exactly the listed ones from the
  allowlist `net_bind_service`, `setuid`, `setgid`, in its effective,
  permitted, inheritable and ambient sets, with the bounding set cut to them;
  the helper checks all five sets on entry and just before exec and refuses
  any difference (`sandbox_cap`). Every other capability is refused at load
  (`sandbox_cap_denied`). See [unit capabilities](../design/unit-caps-1.md).
- `setuid` and `setgid` come only with explicit target lists and a seccomp
  id filter: no switch to uid or gid 0, the supervisor's ids or an unlisted
  id, no supplementary groups added, no user namespace created or joined
  (`setns`). A unit with caps never has gid 0 as its gid or groups, nor the
  supervisor's ids (checked at start). The user-namespace guarantee also
  **depends on `/proc` staying read-only** for the unit (`sandbox_proc`):
  with `CAP_SETUID`/`CAP_SETGID` a process may write the id map of a
  namespace that another, unfiltered process created. For a unit holding
  `setuid` or `setgid` sahinit refuses (`sandbox_proc`): a `read_write_paths`
  entry that is `/`, `/proc` or below `/proc`, as written and after
  symlinks are resolved at load; at start, an entry whose open directory is
  on a procfs (a bind mount of `/proc`, or a directory inside one); and an
  entry with a procfs mounted at or beneath it in sahinit's mount namespace
  (`/proc/self/mountinfo`). Not detected: a procfs mounted after the start
  (only root can mount), and procfs reached other than through a
  read_write path (an fd passed in; sahinit passes none to such a unit).
- The status claim (`no_new_privs,landlock_vN,caps`, plus `,id_filter`)
  lists only mechanisms that returned success, and only while a process
  runs.

### The cgroup_trusted boundary

With cgroups, each service is its cgroup: everything it forks starts inside
(`clone3(CLONE_INTO_CGROUP)` or a helper moved in before exec), and when its
main process exits for any reason everything left is killed (`cgroup.kill`)
and the service has ended only once the cgroup is empty.

These guarantees hold only for services that **cannot write cgroupfs**.
A unit is *cgroup-trusted*, and the guarantees are not promised for it, when:

- it has no sandbox and runs as root or as the supervisor's uid; or
- its sandbox's `read_write_paths` include `/`, `/sys`, `/sys/fs`,
  `/sys/fs/cgroup` or a path below it; or
- it keeps `setuid`.

Such units are allowed, and named (`plan` prints `cgroup_trusted FILE`;
status has `cgroup_trusted: true`). A sash unit may never be cgroup-trusted.
To bound what a trusted unit can do, sahinit sweeps the root: unknown
cgroups are killed and removed (`cgroup_stray_cgroup`), strangers in its own
leaf are killed (`cgroup_stray`), and processes in the root itself are logged
(`cgroup_root_member`). A trusted service that moves into **another service's**
cgroup cannot be detected.

Limits (`memory_max`, `cpu_max`, `pids_max`) are applied before the process
starts; a limit that cannot be applied refuses the unit and is never ignored.

### Control socket

- Local only, one request per connection, 64 KiB frames, strict JSON.
- The socket is created with its final mode in a private directory and
  hard-linked into place, so no chmod follows a link; 0600, or 0660 with an
  explicit group. A stale socket is removed only if it is ours and dead.
- **Peer rules**, checked on every request after the frame is read:
  - the peer's uid must be allowed (`uid_denied`);
  - the peer must not be supervised (`peer_supervised`): not in any cgroup
    below the root (a service, the supervisor's leaf, an unknown cgroup), not
    in a process group a service has led while that group has members, and
    still the same process that connected (pinned by `SO_PEERPIDFD`, a pidfd,
    or its start time);
  - a process in the root itself or in systemd's `ROOT/.control` is accepted
    only while a controller is enabled below the root, because the kernel
    then refuses moves into the root; otherwise sahinit logs
    `cgroup_root_unprotected` and refuses them too.
- `diff`, `apply`, `rollback` and `activate` additionally need the peer's
  effective uid to be 0 (`root_required`), whatever `--uid` allows: they
  read a directory as the supervisor and replace what runs.
- So a service, even one running as an allowed uid, cannot stop or restart
  other services through the socket.
- Responses carry tokens, never paths or OS error text.

### Signals

On Linux each service's process is signalled through a pidfd, and a
process-group signal is sent only while the leader is unreaped; SIGKILL goes
through `cgroup.kill`. With cgroups a reused pid is never signalled; without
them, before Linux 6.9, a narrow reuse race remains for the group signal.

### sash services

- sash never runs as root (`sash_root`), always sandboxed, never
  cgroup-trusted, so its cgroup holds everything it spawns.
- The grant is verified by sahinit itself before every start: the fleet key's
  signature over the exact message, the `sash/2` shape, purpose `service`, no
  `"*"`, no `/` root, `exp`, the service name, the identity, and the serial
  against the signed floor. sahinit never trusts that sash checked.
- Every verb sash asks for is re-checked against the grant: programs must be
  listed and pass the trusted walk; spawned processes run as the unit's own
  uid and gid under its sandbox; env names must be listed and not denylisted;
  cwd, probes and `file:` streams must lie under the grant's roots, opened
  without following symlinks; signals go only to processes in the service's
  own name table, never by pid; a check session is read-only.
- File verbs (`mkdir`, `chown`, `chmod`, `touch`, `ln`, `rm`) run as root
  after the checks, with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` from
  the root, on a single final name, never by path. Hard links are refused;
  only targets the service already owns are changed; owners are only the
  service's own identity; modes never include setuid or setgid; creation runs
  with the service's filesystem uid and gid, so a rename race cannot make a
  root-owned file the service's.
- Mounts: types `tmpfs`, `proc`, `sysfs`, `devpts`, or binds from listed
  sources; always `nosuid,nodev`; no overlay or other options; the mount point
  must be listed and may not be at, under or above a writable root; each mount
  is tracked by its unique mount ID so umount and remount act only on
  sahinit's own mount.
- Secret env values reach only the child's environment; spawned children
  never dump core.
- Floors only rise, are signed under their own domain (no grant or policy
  verifies as a floor), and fail closed when unreadable or unverifiable.

### Deployments

A generation is staged only when its policy verifies under the local trust,
the manifest's exact bytes match the signed `catalog_sha256`, every unit and
artifact matches its manifest digest, and the unit set and `needs` match the
policy; it is re-verified on every load. Each start (manual, boot, restart,
dependency resume) is admitted against the active generation's policy and the
revocation floor (`policy_revoked`): grace admits only `offline_units`, an
expired policy only automatic restarts of `runtime_restart_units`. `apply`
and `rollback` are refused in this mode; earlier content returns only as a
newly signed, higher-sequence generation. This binds the declared files, not
the kernel, shared libraries, an interpreter's dependencies or files named in
arguments.

### Boot-policy metadata

Ed25519 over a domain-separated message and the exact payload bytes; strict
schema with no unknown, missing or duplicate fields; host and recovery
binding; local ceilings; renewal ordering (no lower sequence, no silent
change at the same sequence or generation); a monotonic revocation floor;
atomic, fsynced installs under a lock; corrupt state fails closed. The
renewal client uses TLS 1.3 only, the system roots, no proxy, no redirects,
bounded sizes and times, and a credential that is never printed.

## What is NOT guaranteed

- **Boot policy is not enforced for `--dir` catalogs.** Only a deployment
  (`--deployment-root`) admits units by policy. Boot jobs and their script
  hashes are refused (`deployment_jobs`); nothing runs them. There is no
  policy issuer and no artifact downloader.
- **Root on the host** can defeat everything here: replace the binary, edit
  the catalog, delete or restore the policy cache and the floors (the
  anti-rollback guarantee is file-based; there is no TPM or verified boot).
- **Cgroup-trusted units** (above) can leave their cgroup or kill sahinit.
- **Without cgroups** (`--no-cgroups`, or not Linux), a service that calls
  `setsid` escapes kill-all and the peer check, and there are no limits.
- **Network access is not confined** by the sandbox.
- **Capabilities are inherited** by everything a capped service executes,
  across uid changes between non-zero uids, unless the service clears its
  own ambient and inheritable sets.
- **A `setuid`/`setgid` service can act as every id it lists**: files in its
  Landlock domain, `chmod` of their files anywhere (Landlock cannot restrict
  chmod, chown, utime or truncate by path), their processes and every Unix
  socket that trusts them. It can **forge `SCM_CREDENTIALS`** with any uid
  and gid, 0 included. The id filter exists on Linux amd64 and arm64 only.
- **`net_bind_service`** binds any port below 1024 on any address.
- **Landlock does not confine Unix socket connects** (nor the network).
- A sash unit cannot hold capabilities (`sash_caps`), nor can a sash spawn
  (`ceiling`); a deployment unit cannot (`deployment_caps`).
- **Peer pinning before Linux 6.5** leaves a narrow pid-reuse window between
  connect and accept.
- **The grant's `host` is not checked**: sahinit has no host name.
- **A legitimate mount is visible host-wide**: mounts are made in sahinit's
  own mount namespace.
- **Output tails, events and the journal are not an audit log**: tails are
  in memory and lost on exit; the journal (`--log-dir`) is bounded, drops
  records when its queue is full, may lose its unsynced tail on power loss,
  and is not tamper-evident. Both contain whatever the service printed,
  secrets included; journal files are 0600 to the supervisor's uid.
- **Live catalog changes cannot undo side effects**: a failed `apply`
  restores the old catalog's configuration and processes, not what the
  programs did.
- **The service watchdog is not a hardware watchdog**: a hung kernel or PID 1
  is not reset.
- **`--trust-system-clock` is an assertion, not authentication**: time is
  never established from a policy or from disk.
- **The recovery program runs as root on the console** with no
  authentication added by sahinit; provision an authenticated one.
- **PID 1 mode is experimental**: storage discovery beyond
  `sahinit.root=/dev/...` and a hardware watchdog are not provided; the
  filesystem check and switch-root are done by the separate initramfs script
  (`contrib/initramfs/init`), proven only on a disposable ext4 disk in QEMU.
- **Old-kernel fallbacks** (no `close_range`, older Landlock ABIs, no
  `cgroup.kill`, no `clone3` into a cgroup) are tested only through hooks,
  not on real kernels.

## Reporting

Report a way past any of these rules privately to the maintainers rather than
in a public issue.
