# Unit capabilities, batch 1: contract

2026-11-25. Branch `feat/unit-caps`, from `origin/feat/host-ops`. Requirement:
sinetd (sahinetd repo, `units/sinetd.json`) runs as uid 65532 and needs
`CAP_NET_BIND_SERVICE` to bind ports below 1024 and `CAP_SETUID` and
`CAP_SETGID` to drop each exec child to its service's own user (sinetd review
1, finding H1, batch P, option (a)). Today a non-empty `sandbox.caps` fails the
start with `sandbox_cap`, because the sandbox helper runs as the unit's uid
and has nothing to keep.

This contract makes a closed set of capabilities work for a sandboxed,
non-root exec unit, and says exactly what that does and does not limit.

## Summary of decisions

1. **Allowlist:** `net_bind_service`, `setuid`, `setgid`. Nothing else.
   Every other Linux capability name is `sandbox_cap_denied` at load; an
   unknown name is `sandbox_cap`.
2. **`setuid` and `setgid` need a target list.** A unit that asks for
   `setuid` must list the uids it may switch to (`sandbox.setuid_to`), and
   `setgid` the gids (`sandbox.setgid_to`). A seccomp filter installed by the
   helper enforces the lists: no uid or gid outside them (and never 0), no
   supplementary groups, no new user namespace. Without the lists the grant is
   root-equivalent on an ordinary host (see "Why setuid and setgid need
   targets"), so it is refused (`sandbox_ids`). This goes beyond the brief,
   which asked for the three names alone.
3. **Mechanism:** sahinit (root) starts the helper as the unit's uid with
   the granted set plus `CAP_SETPCAP` in the permitted, effective,
   inheritable and ambient sets (Go's `SysProcAttr.AmbientCaps`). The helper
   checks that it holds exactly that, cuts the bounding set to the granted
   set, drops `CAP_SETPCAP`, checks again, then sets no_new_privs, Landlock
   and (for setuid/setgid) the id filter, checks a last time, and execs. The
   service starts with exactly the granted set in CapPrm, CapEff, CapInh,
   CapAmb and CapBnd.
4. **No caps, no change:** a unit with an empty `caps` goes through exactly
   the code it goes through today: CapInh, CapPrm, CapEff and CapAmb are 0,
   CapBnd is the supervisor's (unchanged, as today), no seccomp filter.
5. **Who may use it:** exec units from a root-owned unit file in `--dir`
   (the existing file checks; the unit file is the opt-in, and the target
   lists are the extra opt-in for setuid/setgid). Refused for sash units
   (`sash_caps`) and for deployment units (`deployment_caps`).
6. **Inheritance:** granted caps are ambient, so every child the service
   execs inherits them, including across a uid change between non-zero uids.
   A service that must not pass them on has to clear its own ambient and
   inheritable sets (or drop everything) itself. The unit reference says so.

## Kernel facts this relies on

Verified on 2026-11-25 against the man pages in Debian bookworm's
`manpages` package (Linux man-pages 6.03, 2023-02-05), and by experiment in
a privileged container on kernel 7.0.12-linuxkit, Go 1.26, as root:

- capabilities(7), "Transformation of capabilities during execve()": for a
  file that is not set-user-ID and has no file capabilities,
  `P'(ambient) = P(ambient)`, `P'(permitted) = (P(inheritable) &
  F(inheritable)) | (F(permitted) & P(bounding)) | P'(ambient)`,
  `P'(effective) = P'(ambient)` (F(effective) clear), `P'(inheritable) =
  P(inheritable)`, `P'(bounding) = P(bounding)`. So the ambient set is the
  only way a non-root exec of an ordinary binary keeps a capability.
- capabilities(7), "Ambient": a capability can be ambient only if it is
  both permitted and inheritable; it is lowered automatically when either is
  lowered; executing a set-user-ID or file-capability program clears the
  ambient set.
- prctl(2) `PR_CAP_AMBIENT_RAISE`: the capability must already be in the
  permitted and inheritable sets. `PR_CAPBSET_DROP`: needs `CAP_SETPCAP`,
  EPERM otherwise. `PR_SET_KEEPCAPS`: reset to 0 on execve.
- capabilities(7), "Programmatically adjusting capability sets": without
  `CAP_SETPCAP` the new inheritable set must be a subset of the old
  inheritable and permitted sets; it must always be a subset of the old
  inheritable set and the bounding set; the new permitted set must be a
  subset of the old one. Experiment: after the bounding set lost
  `CAP_SETPCAP` and capset dropped it, putting it back into the inheritable
  set fails with EPERM.
- capabilities(7), "Effect of user ID changes on capabilities": the
  permitted, effective and ambient sets are cleared only when a uid was 0
  before and none is after. **A change between two non-zero uids keeps every
  capability.** Experiment: a helper child with CapPrm/CapEff/CapAmb 0x480
  called `setresuid(1000,1000,1000)` from 65534 and still held 0x480; a
  child it then exec'd held 0x480 too and could call `setresuid(0,0,0)`
  successfully. After the service cleared its ambient and inheritable sets,
  the next exec'd child held 0 in every set except CapBnd, and
  `setresuid(0,0,0)` failed with EPERM.
- prctl(2) `PR_SET_NO_NEW_PRIVS`: execve grants no privileges that could not
  have been had without it; set-user-ID bits and file capabilities do not
  work; it is inherited and cannot be unset.
- capabilities(7) `CAP_SETUID`: arbitrary uid changes; **forge the uid in
  `SCM_CREDENTIALS`**; write a uid mapping in a user namespace. `CAP_SETGID`
  likewise for gids and the supplementary group list. unix(7)
  `SCM_CREDENTIALS` confirms the forging rule. user_namespaces(7): a writer
  with `CAP_SETUID` in the parent namespace "can make mappings to arbitrary
  user IDs"; the writer needs that capability "in the user namespace of the
  process pid", and a capability in a namespace holds in all its
  descendants, so a capped process in the initial namespace may write the
  map of a namespace **another, unfiltered process created**. Since Linux
  5.12 a uid_map line that maps **parent uid 0** also needs `CAP_SETFCAP`;
  that rule covers neither gid_map (so outer gid 0 can be mapped) nor any
  other uid. (Corrected after review: the first version of this contract
  said "mapping uid 0 needs CAP_SETFCAP" as if that closed the route.)
- setns(2): joining a user namespace needs `CAP_SYS_ADMIN` in it, and
  user_namespaces(7) gives a process every capability in a namespace whose
  owner uid is its euid. So a service that switched to a listed uid could
  join a namespace that uid made.
- Landlock applies to procfs opens: in the experiment below, a Landlock
  domain without `/proc` could not read `/proc/self/status`. An id map is
  written through `/proc/PID/uid_map`, so with `/proc` outside every
  read_write path the map route is closed.
- ptrace(2), "Ptrace access mode checking", step 5.2: access is denied unless
  the caller's capabilities are a superset of the target's permitted set (or
  the caller has `CAP_SYS_PTRACE`). Experiment: an uncapped child of a capped
  service, same uid, could not open the service's `/proc/PID/environ`
  (EACCES). This is what keeps a same-uid process out of the helper while it
  briefly holds `CAP_SETPCAP`.
- seccomp(2): the `arch` field must be checked; x86-64 and x32 share
  `AUDIT_ARCH_X86_64` and differ by `__X32_SYSCALL_BIT` in `nr`, so a filter
  must refuse that bit. Installing a filter without `CAP_SYS_ADMIN` needs
  no_new_privs.
- Landlock (ABI 1 to 5, the rights this package handles) does **not**
  restrict `connect(2)` to a pathname Unix socket. Experiment: a process in a
  Landlock domain that handled every v1 file right and allowed no path could
  not read `/etc/hostname` (EACCES) but connected to a socket in `/tmp`.

## Which capabilities

| Name | Bit | Grantable | Why |
| --- | --- | --- | --- |
| `net_bind_service` | 10 | yes | Bind TCP/UDP/SCTP ports below 1024. Nothing else. |
| `setuid` | 7 | yes, with `setuid_to` | See below. |
| `setgid` | 6 | yes, with `setgid_to` | See below. |
| every other capability | | **never** (`sandbox_cap_denied`) | |

Never grantable, and why, for the ones people ask for:
`sys_admin` (mount, namespaces, a hundred other things: root),
`sys_module` (load kernel code), `sys_ptrace` (read and write any process),
`sys_rawio` (raw I/O ports and devices), `dac_override` and
`dac_read_search` (skip file permission checks, so the Landlock domain is
the only file limit left; `dac_read_search` also allows `open_by_handle_at`,
which escapes path-based rules), `fowner`, `chown`, `fsetid` (take files
over), `setfcap` and `setpcap` (manufacture capabilities), `net_admin`
(routes, firewall, interfaces), `net_raw` (raw packets, spoofing),
`kill` (signal any process, sahinit included), `sys_chroot`, `mknod`,
`linux_immutable`, `ipc_owner`, `ipc_lock`, `sys_boot`, `sys_nice`,
`sys_resource`, `sys_time`, `sys_tty_config`, `lease`, `audit_*`,
`mac_*`, `syslog`, `wake_alarm`, `block_suspend`, `bpf`, `perfmon`,
`checkpoint_restore`, `net_broadcast`, `sys_pacct`. Each can be argued for
in some service; none is needed now, and each needs its own justification
and its own contract before it is added.

The names are the lowercase kernel names without `CAP_`. The full list of 41
names (bits 0 to 40) is known, so a real but denied name gets
`sandbox_cap_denied` and a typo gets `sandbox_cap`. A repeated name is
`duplicate_field`, as for every string list.

The old closed set (`chown`, `dac_override`, `fowner`, `kill`, `net_admin`,
`sys_admin`) loaded and then failed every start; it now fails at load. No
working unit changes.

## Why setuid and setgid need targets

`CAP_SETUID` lets a process become any uid, including 0. What limits that,
with only the brief's mechanisms:
- the bounding set is the granted set, so uid 0 gains no capability by
  exec, and no_new_privs clamps any exec to the caps already held;
- no_new_privs makes set-user-ID binaries and file caps inert;
- Landlock still confines every file access, whatever the uid.

What it does **not** limit, which makes the bare grant root-equivalent:
- **Unix sockets.** Landlock (ABI 1 to 5) does not confine `connect` to a
  pathname socket, and many daemons authorise by `SO_PEERCRED`. As uid 0 the
  service can talk to the D-Bus system bus as root and ask systemd to start
  a unit as root; with `setgid` alone it can become gid `docker` and use
  `/var/run/docker.sock`. Either is full root.
- **Signals.** As uid 0, or any other uid, it can signal that uid's
  processes: kill sahinit (in `supervise` mode it is an ordinary root
  process) or any other service.
- **Owner rights.** As uid 0 it owns every root-owned file: it can read
  `/etc/shadow` (0640 root) if `/etc` is in its Landlock domain, and it can
  `chmod` any root-owned file **anywhere**, because landlock(7) says chmod(2),
  chown(2), setxattr(2), utime(2) and truncate(2) by path "currently" cannot
  be restricted. `chmod 0666 /etc/shadow` needs no capability for its owner.
- **User namespaces.** With `CAP_SETUID`/`CAP_SETGID` it can create a user
  namespace, or find one an unfiltered process created, and write its id
  map with any outer uid but 0 (which needs `CAP_SETFCAP` since 5.12) and
  any outer gid, 0 included, when it can write the map file under `/proc`.
  It can also join, with setns, a namespace owned by a uid it switched to.
- **`SCM_CREDENTIALS`.** It can send any uid and gid, 0 included.

So batch 1 requires the target lists, and the helper enforces them with a
seccomp filter (the "id filter") on top of no_new_privs and Landlock:

| Syscall | Rule |
| --- | --- |
| `setuid`, `setfsuid` | the argument (low 32 bits, as the kernel reads `uid_t`) is in `setuid_to`, the unit's own uid, or 0xffffffff |
| `setreuid`, `setresuid` | every argument is, likewise |
| `setgid`, `setfsgid`, `setregid`, `setresgid` | the same with `setgid_to` and the unit's own gid |
| `setgroups` | only a size of 0 (clear the list) |
| `unshare`, `clone` | `CLONE_NEWUSER` in the flags is refused |
| `setns` | refused (joining a user namespace; every other kind needs `CAP_SYS_ADMIN` anyway) |
| `clone3` | ENOSYS (its flags are in memory a filter cannot read; libc and Go fall back to `clone`) |
| any other arch, x32 syscalls on x86-64 | the process is killed |

Refused calls fail with EPERM. The filter is installed only for a unit that
holds `setuid` or `setgid`, is inherited by every child and cannot be
removed. Linux amd64 and arm64 only; elsewhere `seccomp_unavailable`. The
status claim gains `,id_filter` when it is on, and sahinit checks that the
helper reports the filter exactly when the unit needs it.

Rules for the lists (`sandbox_ids` for any of them): `setuid_to` is present
exactly when `caps` has `setuid`, `setgid_to` exactly when it has `setgid`;
each has 1 to 64 unique integers from 1 to 4294967294 (any other JSON value,
null included, is `sandbox_ids` too); neither may hold 0. A unit with any
caps may not have gid 0 as its gid or among its groups (`sandbox_ids`),
since the filter allows the unit's own gid and setgroups can only shrink the
list. All of this is checked at load.

The supervisor's own uid and gid (trusted principals) may not be a target,
the unit's gid or one of its groups. That is checked **at start**, in
`sandbox.Launch`, by the supervisor itself (`sandbox_ids`): `sahinit plan`
may run as any user, so at load the supervisor's ids are not known. (The
first version checked it at load against the caller's euid.) As root the
supervisor's ids are 0, which the load rules already refuse; the start
check matters for a non-root supervisor, which cannot give caps anyway, and
is defence in depth.

**The map route needs a read-only `/proc` (`sandbox_proc`).** The filter
stops creating and joining user namespaces, but a namespace another,
unfiltered process created can still have its id map written by a holder of
`CAP_SETUID`/`CAP_SETGID` (above). A unit with `setuid` or `setgid` may
therefore not list `/`, `/proc` or any path under `/proc` in
`read_write_paths` (`sandbox_proc`, at load and again in the helper on the
resolved paths). The "no user namespace, never uid or gid 0" guarantee
depends on that rule. It checks paths, not filesystems: a procfs mounted
somewhere else beneath a read_write path is not detected.

What the id filter still does **not** stop, stated in units.md and
security.md:
- the service may act as **any listed uid or gid**: their files inside its
  Landlock domain, `chmod` and `utime` on their files anywhere (landlock(7)),
  their processes (signals, ptrace if Yama allows), and every Unix socket
  that trusts them;
- **forged `SCM_CREDENTIALS`** with any uid and gid, 0 included: the filter
  cannot read ancillary data. A receiver that trusts `SCM_CREDENTIALS` over
  `SO_PEERCRED` (journald's `_UID` field, for one) can be lied to;
- Landlock does not confine Unix socket connects or the network.

## Mechanism and order

Parent (`sandbox.Launch`, sahinit as root):
1. A unit with caps needs a sandbox, an explicit non-zero uid (already
   `sandbox_root`), and a root supervisor: an unprivileged supervisor has no
   capability to give and is refused with `sandbox_cap` before anything
   starts.
2. The helper is started through `exec.Cmd` with `Credential` (the unit's
   uid, gid, groups, as today) and `AmbientCaps` = granted set ∪
   `CAP_SETPCAP`. Go's fork child sets `PR_SET_KEEPCAPS`, changes
   groups, gid and uid, then capsets permitted and inheritable to include
   each ambient cap and raises each into the ambient set. The exec of the
   helper (a plain binary) then leaves P = E = I = A = granted ∪ setpcap and
   the bounding set full (verified by experiment, above).

Helper (`sahinit apply`, uid N, single locked thread):
3. Read and decode the spec as today; join the cgroup; refuse uid 0.
4. **Entry check:** capget and `PR_CAP_AMBIENT_IS_SET` must show exactly
   granted ∪ setpcap in all four sets, else `sandbox_cap`.
5. **Bounding set:** for every capability 0 to the kernel's last (probed with
   `PR_CAPBSET_READ` until EINVAL) that is not granted, `PR_CAPBSET_DROP`;
   `CAP_SETPCAP` itself is dropped last. Any failure is `sandbox_cap`.
6. **Drop setpcap:** capset P = E = I = granted. The ambient bit for setpcap
   falls with it.
7. **Second check:** P = E = I = A = bounding = granted, exactly.
   This is the end of the only window in which the helper holds more than
   the service will. Nothing between steps 2 and 7 opens a file, uses a
   capability or runs code other than the helper's own.
8. As today: umask, stream files (as uid N), Landlock rules, then in
   `restrict`: capset P = E = I = granted (unchanged call, a no-op now),
   no_new_privs, and **not** `PR_CAP_AMBIENT_CLEAR_ALL` (the one difference
   from the no-caps path), then `landlock_restrict_self`.
9. With setuid or setgid: install the id filter (`PR_SET_SECCOMP`), which
   needs no_new_privs and so comes after it.
10. **Final check:** as step 7, plus no_new_privs set. Then the status line
    and execveat, as today. The exec (no_new_privs, plain or not) keeps the
    ambient set and so the granted set.

Interactions:
- **no_new_privs** is set as before; it stops set-user-ID and file-cap
  programs from widening anything, and clamps a uid-0 exec to the permitted
  set (which the id filter already prevents).
- **Landlock** is unchanged and applies to every uid the service becomes.
  None of the granted caps bypasses it (dac_* are never grantable).
- **The helper** still runs as the unit's uid; it does not start as root.
  The extra it holds (setpcap) cannot widen anything: without it in the
  bounding set it cannot be added back, and setpcap only adds bounding-set
  caps to the inheritable set, which the bounding set already limits to the
  granted set by step 6.
- **User namespaces** are not used by sahinit. The id filter refuses new
  ones and setns for setuid/setgid units, and `sandbox_proc` keeps the id
  maps of other namespaces out of reach. A net_bind_service-only unit may create one
  as any unprivileged process can; that gains nothing outside it.
- **seccomp** is new to sahinit and used only for the id filter.

## No caps, no change

A unit with an empty `caps` (or none) runs the same code as today: the
parent sets no `AmbientCaps`; the helper skips steps 4 to 7 and 9; `restrict`
capsets all-zero and clears the ambient set as today. The service's
`/proc/self/status` shows CapInh, CapPrm, CapEff and CapAmb 0, CapBnd equal to
the supervisor's (today's value, unchanged: an unprivileged helper cannot cut
it), NoNewPrivs 1, Seccomp 0. A test asserts exactly that. Cutting the
bounding set for no-caps units too would need the same setpcap step and is
left as an open decision.

## Who may use it

- **Exec units from `--dir`:** yes. The unit file must pass the existing
  checks (root- or supervisor-owned, not writable by others), so only root
  can grant. There is no extra flag beyond the lists for setuid/setgid.
- **Sash units:** refused (`sash_caps`). sash scripts run under grants whose
  caps were designed to be refused (`caps_unsupported`); giving the sash
  process itself caps was never reviewed. A sash spawn's caps are now always
  outside the unit's (empty) ceiling, so they are `ceiling`; the sash host
  also refuses a spawn plan with caps (`caps_unsupported`) before anything
  else, since `Launch` would now honour them.
- **Deployment units (`--deployment-root`):** refused (`deployment_caps`).
  The signed policy admits a unit file but says nothing about capabilities;
  until it does, a signer should not be able to grant them without saying
  so. Open decision for the owner.
- `setuid` stays in the cgroup-trusted list (unchanged): the id filter means
  it can no longer become the supervisor's uid, but leaving it there is the
  conservative choice. Open decision.

## Inheritance (what a service must do)

Granted caps are ambient. Every child the service execs gets the same set,
and keeps it after a `setuid` to another non-zero uid. sinetd, which forks
per-service children and drops them to another user, must make sure the
children get nothing. One way, in a Go service: once at start, on every
thread (`syscall.AllThreadsSyscall`, cgo off), clear the ambient set
(`PR_CAP_AMBIENT_CLEAR_ALL`) and capset the inheritable set to 0, keeping
permitted and effective. A child exec'd after that holds no capability,
whatever uid it runs as (verified by experiment). Even if a service gets
this wrong, its children stay inside the id filter and the Landlock domain.

## Codes

| Code | Change |
| --- | --- |
| `sandbox_cap` | now: an unknown capability name (load); at start, the supervisor is not root, or the helper could not reach or verify exactly the granted set |
| `sandbox_cap_denied` | new: a real capability that is not on the allowlist (load) |
| `sandbox_ids` | new: a `setuid_to`/`setgid_to` rule, or gid 0 with caps (load); the supervisor's own ids (start) |
| `sandbox_proc` | new: setuid/setgid with `/`, `/proc` or a path under it writable (load, and in the helper) |
| `seccomp_unavailable` | new: the id filter cannot be installed on this kernel or architecture (start) |
| `sash_caps` | new: a sash unit lists caps (load) |
| `deployment_caps` | new: a deployment unit lists caps (load) |

Docs: units.md (sandbox fields, the rules, inheritance), codes.md (above),
security.md (guarantees and what is not guaranteed), README (scope line).

## Threats

- **Hostile service.** Holds exactly the granted set; cannot regain others
  (bounding set, no_new_privs); cannot reach files outside Landlock; with
  setuid/setgid cannot become uid or gid 0, the supervisor, or any unlisted
  id, cannot add supplementary groups, cannot make or join a user namespace
  or reach another's id map (`sandbox_proc`). It
  **can** bind any port below 1024 on any address (net_bind_service; take
  over a port another daemon has not bound yet), act as any listed id, forge
  `SCM_CREDENTIALS`, and connect to any Unix socket and the network.
- **Hostile child of a service.** Inherits the ambient set unless the
  service cleared it, and always inherits no_new_privs, Landlock and the id
  filter. It cannot ptrace or read the memory of its capped parent while it
  holds fewer caps (ptrace(2) step 5.2).
- **Unit author mistake.** A typo is `sandbox_cap`; a dangerous cap is
  `sandbox_cap_denied`; setuid without a target list, 0 or gid 0 is
  `sandbox_ids` at load (`plan` shows them); the supervisor's own id is
  `sandbox_ids` at start. Listing the wrong
  user is not detectable: the service gets that user's powers.
- **Helper bugs between privilege states.** The helper holds setpcap only
  between its start and step 7; it checks the full state on entry, after the
  cut and just before exec, and any mismatch is `sandbox_cap` with no exec.
  The parent accepts only a claim that matches whether the id filter was
  needed. A same-uid process cannot ptrace the helper in that window
  (ptrace(2) 5.2) but can still signal it (a failed start, as today).
- **Out of scope:** the kernel (trusted), root on the host, Landlock not
  confining sockets or the network, `SCM_CREDENTIALS` forging, other
  architectures than amd64 and arm64 for setuid/setgid, a compromised unit
  directory.

## Tests

Linux, as root in the privileged container (`internal/sandbox`,
`caps_linux_test.go`), with a probe target that reads
`/proc/self/status` or the same state through capget and prctl:
- no caps: CapInh/CapPrm/CapEff/CapAmb 0, CapBnd as the test process's,
  NoNewPrivs 1, Seccomp 0;
- `[net_bind_service]` as uid 65534: all five sets 0x400; binds a port below
  1024; `setresuid` fails; after dropping its caps it cannot bind;
- `[setuid,setgid]` with targets: all five sets 0xc0, Seccomp 2; uid 0, gid
  0, an unlisted uid, `setgroups` with a group and `unshare(CLONE_NEWUSER)`
  fail with EPERM; switching to the listed ids works and leaves the caps
  (the kernel rule), dropping them leaves 0; a child exec'd without the drop
  holds the caps (documented hazard), with the drop holds none;
- Landlock holds with caps: a path outside the domain is EACCES;
- helper entry check: a helper started with one cap too many, or without
  the ambient caps, refuses with `sandbox_cap` and runs nothing;
- the sinetd unit as shipped (copied to a fixture, only `exec[0]` pointed at
  a stand-in) loads, starts, binds a low port and reports 0x400; with the
  three names and target lists it starts and reports 0x4c0; with the three
  names and no lists it is refused at load.

Portable (`internal/unit`, `internal/deploy`): every denied name, an unknown
name, every `sandbox_ids` rule, `sash_caps`, `deployment_caps`, and the
filter program's shape and jump ranges.

Each check is mutation-verified: removed once, the test that covers it must
fail. The report lists which.
