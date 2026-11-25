# Unit sockets, batch 1: decision

2026-11-25. Branch `fix/landlock-make-sock`, from `origin/feat/unit-caps`.
Report: sinetd binds `/run/sinetd/grant.sock` (and optionally a metrics
socket) inside its only `read_write_paths` entry, `/run/sinetd`, and its start
fails with EACCES under the sahinit sandbox. The gap predates the capability
work.

## What the sandbox does today

`internal/sandbox/sandbox_linux.go` handles these Landlock file rights (only
those the kernel's ABI knows, capped at ABI 5) and grants a subset:

| Right | ABI | Handled | `read_only_paths` | `read_write_paths` |
| --- | --- | --- | --- | --- |
| EXECUTE, READ_FILE, READ_DIR | 1 | yes | granted | granted |
| WRITE_FILE, REMOVE_DIR, REMOVE_FILE, MAKE_DIR, MAKE_REG | 1 | yes | | granted |
| TRUNCATE | 3 | yes | | granted (unrestricted below ABI 3) |
| MAKE_SOCK | 1 | yes | | **denied** |
| MAKE_FIFO | 1 | yes | | **denied** |
| MAKE_CHAR, MAKE_BLOCK | 1 | yes | | **denied** |
| MAKE_SYM | 1 | yes | | **denied** |
| REFER | 2 | yes | | **denied** (ABI 1 denies reparenting always) |
| IOCTL_DEV | 5 | yes | | **denied** |

Verified in a privileged golang:1.26 container, kernel 7.0.12-linuxkit
(Landlock ABI 8, applied 5), through `sandbox.Launch` as uid 65534 with
`read_only_paths: ["/"]`, `read_write_paths: [DIR]`: inside DIR, `bind()` of
a pathname Unix socket, `mkfifo`, `mknod` of a character and a block device
and `symlink` all fail with EACCES; creating, truncating and renaming a
regular file in the same directory, `mkdir` and a same-directory hard link
work; `rename` and `link` into a subdirectory fail with EXDEV (REFER);
`bind()` in a read-only directory fails with EACCES; `connect()` to a socket
outside every listed path succeeds.

**Was the omission deliberate?** No reason is written anywhere. The sets came
in with the first commit (`899d9e7`, "Add the sahinit userspace supervisor")
already split into "granted" (`accessWrite`) and "handled but never granted"
(`accessHandled`), so the special-file rights were denied on purpose in the
sense that someone listed them separately. But no design note, review, code
comment, reference page or commit message says why, none mentions sockets or
FIFOs, and `units.md` describes `read_write_paths` as "Paths the service may
read and write beneath", which a reader takes to include binding a socket.
The ABI commit (`1072383`) and hardening batch 1 changed only which rights
are handled per ABI. So: a deliberate deny-by-default for special files, with
no recorded reasoning and an undocumented consequence.

## Decision

1. **`read_write_paths` is unchanged.** It still grants no MAKE_SOCK,
   MAKE_FIFO, MAKE_CHAR, MAKE_BLOCK, MAKE_SYM, REFER or IOCTL_DEV.
2. **New opt-in field `sandbox.socket_paths`**: directories in which the
   service may create (bind) pathname Unix sockets. Each entry grants exactly
   MAKE_SOCK beneath it and nothing else. Rules:
   - same path grammar as the other lists (`sandbox_path`), unique
     (`duplicate_field`), counted in the 64-path total;
   - each entry must be **at or beneath a `read_write_paths` entry**, by path
     components (`/srv/ab` is not beneath `/srv/a`), checked as written and
     again after Load resolves links, and in the helper (`sandbox_socket`);
   - at launch each is opened without following any symlink and must be a
     directory (`sandbox_path`).
   An entry equal to a read_write path (sinetd: `"/run/sinetd"` in both) is
   the expected use.
3. **FIFOs stay denied.** No service needs one now. A later need gets its own
   reviewed field.
4. **Device nodes stay denied** (MAKE_CHAR, MAKE_BLOCK): they would also need
   `CAP_MKNOD`, which is never grantable, and a device node is a direct route
   to hardware or kernel memory.
5. **Symlinks stay denied** (MAKE_SYM). A link planted in a writable directory
   is the classic confused-deputy primitive against a privileged process that
   later walks that directory (tmp cleaners, backups, log rotation, a root
   `chown -R`). sahinit's own opens refuse links, but other software on the
   host may not. No service has asked for it. (Hard links of regular files in
   one directory work, under MAKE_REG and the kernel's `protected_hardlinks`.)
6. **REFER and IOCTL_DEV stay denied** (unchanged; recorded here because they
   surprise: a rename or hard link into another directory is EXDEV even
   inside one read_write path, and device ioctls on a device opened in a
   writable path are refused). Open decision for the owner whether REFER
   should join `read_write_paths`.
7. **Who may use it:** every sandboxed unit: exec units from `--dir`, sash
   units and deployment units. It is a file right within a directory the unit
   can already write, not a privilege over other processes, and it is written
   in the root-owned (or, for a deployment, signed) unit file. Units that do
   not set it behave exactly as before.

### Why the opt-in and not "read_write_paths gets MAKE_SOCK"

Granting MAKE_SOCK on every read_write path is a one-line change, but it widens
every existing unit, sash and deployment units included, without their files
saying so. What it adds, concretely: the service itself gains no privilege
(it can already listen on TCP, on abstract Unix sockets, and connect to any
socket), but **other processes** that can reach the path may now connect to
something the service controls. In a private directory such as `/run/sinetd`
that is the point. In a shared writable directory it is socket squatting: a
unit given `/tmp` or `/var/tmp` (both sticky 1777) could create
`/tmp/.X11-unix/X0` or any well-known name a client connects to before the
real server does, and impersonate that server. A regular file at the same
name, which the unit can create today, only breaks the client; a socket
answers it. The opt-in keeps that power to directories the unit file names
for the purpose, and the beneath rule keeps it from adding any writable
location.

FIFOs add the same squatting plus a blocking `open()` that can stall a
reader expecting a regular file; with no requester, they stay out.

### Interaction with the capability rules (`sandbox_proc`)

For a unit holding `setuid` or `setgid`, no read_write path may be `/`,
`/proc` or below `/proc`, or be on or contain a procfs. A socket path cannot
dodge that:
- it must be at or beneath a read_write path, which the proc rule already
  confines, so a socket path in `/proc` is `sandbox_socket` (no read_write
  path can contain it) or `sandbox_proc` (the read_write path that would);
- a procfs mounted beneath a read_write path, socket directory or not, is
  already `sandbox_proc` (mountinfo check in the helper);
- the rule grants only MAKE_SOCK: it cannot open, write or truncate anything,
  so even on a procfs it could not write an id map (procfs also has no
  `mknod`).

A setuid unit binding a socket in its own socket path is tested, as is the
refusal of `/proc` as a socket path.

### connect()

Landlock through ABI 5 does not restrict `connect()` to a pathname Unix
socket at all (the experiment above; landlock(7) has no such right). The new
right confines only where the service may *create* a socket, never which
sockets it may reach. security.md says so next to the field. (ABI 6 adds
scoping for abstract sockets and signals, which this package does not
handle; pathname connects stay unrestricted there too.)

## Codes

| Code | Change |
| --- | --- |
| `sandbox_socket` | new: a `socket_paths` entry not at or beneath any `read_write_paths` entry (load, after resolving links, and in the helper) |
| `sandbox_path` | also: a `socket_paths` entry that is missing, a link or not a directory (start) |

## Threats

- **Hostile service with `socket_paths`.** Can bind pathname sockets in the
  listed directories only, and so serve any process that connects there. It
  gains no file access it did not have (the entry is inside a writable path),
  no device node, FIFO or symlink, and no new capability. Out of scope as
  before: connects to any socket, the network.
- **Hostile service without it.** Unchanged: no socket anywhere on disk.
- **Unit author mistake.** A socket path outside every writable path is
  `sandbox_socket` at load (`plan` shows it). Listing a shared directory such
  as `/tmp` in both lists is not detected: it allows squatting there.
- **Bind mounts.** Landlock rules attach to inodes. A directory that root
  bind-mounted beneath a socket path receives MAKE_SOCK by every path that
  reaches it, as a bind mount beneath a read_write path already receives
  write access. Mounts are root's; not detected.

## Tests

Linux, as root in the privileged container (`internal/sandbox`): bind
succeeds in a socket path; fails with EACCES in a read_write path that is not
a socket path, in a read-only path and outside every path; FIFO, character
and block device and symlink creation still fail inside a socket path; a
setuid/setgid unit binds in its socket path and is still refused a procfs
socket path; the shipped sinetd unit fails to bind `grant.sock` and binds it
with `socket_paths: ["/run/sinetd"]` added. Portable (`internal/unit`): the
beneath rule (as written, sibling prefix, after resolution), grammar,
duplicates, the total count. Each check is mutation-confirmed on a scratch
copy.
