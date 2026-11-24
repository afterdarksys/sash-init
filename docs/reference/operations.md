# Operations guide

How to install, boot, configure, upgrade, roll back, recover and troubleshoot
sahinit. Flags are in [cli](cli.md), unit fields in [units](units.md), files in
[config files](config-files.md) and tokens in [codes](codes.md).

**Scope today.** `supervise` is the supported way to run sahinit: under an
existing init with a delegated cgroup v2. PID 1 mode is **experimental**: it is
exercised in QEMU boots (initramfs images, and a disposable ext4 disk booted
twice), not on real hosts. Boot policy is **metadata only** for `--dir`
catalogs: nothing admits or blocks a unit from it. A [deployment](../deployments.md)
(`--deployment-root`) is the one place a signed policy admits units; there is
no issuer for it yet. sash services run with test-made grants and floors;
there is no fleet signer yet.

## Requirements

| Need | Why | Without it |
| --- | --- | --- |
| Linux | sandbox, cgroups, PID 1 | `supervise` runs with process groups (`unsupported` cgroups) and no sandbox (`sandbox_unsupported`); for development only |
| cgroup2 mounted at `/sys/fs/cgroup`, the supervisor's cgroup delegated (writable) | one cgroup per service, kill-all, limits, peer checks | `cgroup_unavailable`; `--no-cgroups` falls back to process groups |
| `cpu`, `memory`, `pids` controllers offered to the root | limits | units with that limit are left out (`cgroup_controller`) |
| Linux 5.7 (`clone3` with `CLONE_INTO_CGROUP`) | child joins its cgroup before exec | the helper path is used automatically |
| Linux 5.14 (`cgroup.kill`) | kill-all | freeze-and-kill fallback; PID 1 mode requires it |
| Linux 5.6 (`openat2`) | sandbox paths, sash file verbs | `openat2_unavailable` |
| Landlock (5.13+, enabled in `lsm=`) | sandbox | `landlock_unavailable` for sandboxed units |
| Linux 5.3 (pidfd); 6.5 (`SO_PEERPIDFD`, amd64/arm64) | race-free signalling and peer pinning | start-time fallback with a documented residual race |
| `/proc` | executing the checked file through `/proc/self/fd` | launches fail; PID 1 mounts it |

The VM suite runs Debian's Linux 6.1 amd64 kernel; the Docker suite runs
whatever kernel the Docker host has.

## Install

sahinit is one static Go binary. There is no package or release download yet;
build from the repository (Go 1.26):

```sh
git clone https://github.com/afterdarksys/sash-init.git
cd sash-init
./build.sh                                  # tests, vet, Linux cross-compile
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sahinit ./cmd/sahinit
install -o root -g root -m 755 sahinit /usr/local/sbin/sahinit
install -d -o root -g root -m 755 /etc/sahinit /etc/sahinit/units
```

The binary, every directory above it, the unit directory and every unit file
must be owned by root (or the supervisor's uid) and not group- or
other-writable. Check a catalog before running it:

```sh
sahinit plan --dir /etc/sahinit/units
```

`plan` prints the boot waves and names every refused or cgroup-trusted unit.

## Running under another init (supervise)

### systemd

```ini
# /etc/systemd/system/sahinit.service
[Unit]
Description=sahinit service supervisor

[Service]
ExecStart=/usr/local/sbin/sahinit supervise --dir /etc/sahinit/units --socket /run/sahinit/sahinit.sock
ExecReload=/usr/local/sbin/sahinit ctl --socket /run/sahinit/sahinit.sock status
Delegate=yes
RuntimeDirectory=sahinit
RuntimeDirectoryMode=0700
KillMode=mixed
TimeoutStopSec=11min

[Install]
WantedBy=multi-user.target
```

- `Delegate=yes` makes the unit's cgroup writable by sahinit, which becomes the
  cgroup root: it moves itself into `ROOT/supervisor` and creates
  `ROOT/NAME.service` per service. systemd's `ExecReload` runs in
  `ROOT/.control`, which sahinit accepts as a control peer while the root is
  protected (a controller enabled below it).
- The socket directory must be writable only by its owner; `/tmp` is refused.
- `TimeoutStopSec` should cover the longest unit timeout twice (stop grace
  plus cgroup drain) for the slowest shutdown wave.
- SIGTERM stops sahinit gracefully: every service is stopped in reverse
  dependency order.

### Docker (tests and development)

```sh
docker run --rm --init --privileged --cgroupns=private ... sahinit supervise --dir /units --socket /run/sahinit/s.sock
```

The container's root cgroup must be emptied into a leaf first so controllers
can be enabled (see `internal/cgroup/cgtest`). Do not run sahinit as the
container's PID 1 (that is init mode); use `--init`.

### Allowing other users to use the socket

```sh
sahinit supervise ... --uid 0 --uid 1001 --gid 1001
```

`--uid` replaces the default (the supervisor's own uid), so list it too. With
another uid the socket is 0660 with group `--gid`. Every request is still
checked by peer credentials, and a request from inside a service is
`peer_supervised`.

## First boot as PID 1

Experimental. The host contract: an initramfs (or the kernel) has already made
the local root available; sahinit does not discover storage, load modules or
configure the network (those are services).

1. Build a static binary (above) and install it on the root, for example as
   `/sbin/sahinit`, with the catalog in `/etc/sahinit/units`.
2. Boot with `init=/sbin/sahinit` (or install it as the initramfs `/init`). As
   PID 1 every argument is an init flag; the defaults are
   `--dir /etc/sahinit/units --socket /run/sahinit/control.sock
   --shutdown-timeout 30s`.
3. Strongly consider `--recovery /sbin/your-recovery-program` (a local console
   program run as root). There is none by default.
4. Verify in a VM first: `python3 scripts/test-boot.py`.

What PID 1 does, in order: makes `/` mount propagation private; mounts
`/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/run` and `/sys/fs/cgroup`
where missing; creates a sticky `/tmp` when missing; opens
`/dev/console`; disables Ctrl-Alt-Del's immediate reboot (it becomes SIGINT);
creates `/run/sahinit` (0700) and `/sys/fs/cgroup/sahinit/supervisor`; checks
for `cgroup.kill`; enables `cpu`, `memory` and `pids`; starts
`sahinit supervise --boot-strict ...` in `/sys/fs/cgroup/sahinit/supervisor`
with only `PATH`, `HOME=/root` and `TERM=linux`; then reaps every orphan.

In strict boot **every boot unit is essential unless it says
`"essential": false`**: any refused unit file or limit, a graph error, an
essential unit that is not ready when the boot waves end, or one that later
becomes `failed` (a non-zero exit, a signal, `restart_limit`, `watchdog`),
stops on its own, or waits on a failed `needs` provider, stops the supervisor,
and PID 1 enters recovery. A oneshot that exited 0, a unit in an automatic
restart and a unit stopped with `ctl stop` are fine. Mark units the machine
can live without (a getty, a DHCP client) `"essential": false`; their
failure stays theirs, and their dependents wait (`blocked`). Test a catalog
with plain `supervise` (without `--boot-strict`) and `sahinit validate`
before booting it.

### Persistent ext4 root

`contrib/initramfs/init` is a BusyBox initramfs `/init` for a local ext4
root. **It, not sahinit, checks the filesystem and switches root**: it mounts
`/proc`, `/sys` and `/dev`, reads `sahinit.root=/dev/DEVICE` from the kernel
command line (split on whitespace with globbing off, never evaluated), loads
`virtio_pci`, `virtio_blk` and `ext4` if they are modules, waits up to 10 s
for the device, runs `e2fsck -p` (exit 0 or 1 continue; anything else fails),
mounts the root read-write, moves `/proc`, `/sys` and `/dev`, and
`switch_root`s to `/sbin/sahinit init` with the arguments the kernel passed
to `/init`. On any failure it execs the initramfs's `/sahinit init --dir
/etc/sahinit/failed` (a missing catalog, so strict boot fails and PID 1 waits
in recovery); it never opens a shell. Package it with a static BusyBox,
`/sahinit`, `e2fsck` and its libraries, and the kernel's modules;
`tests/boot/make-images.sh` is a working example. Encrypted, LVM, RAID,
UUID-addressed and network roots are not handled.

At shutdown PID 1 runs `swapoff` on every area in `/proc/swaps` before
unmounting; it never enables swap. `python3 scripts/test-boot.py --scenario
persistent` boots a disposable ext4 image twice and checks it offline with
`e2fsck -fn` after each shutdown.

### Console and host services

PID 1 mounts devpts (so `/dev/ptmx` and `/dev/pts/N` work) and `/dev/shm`;
it does not start a getty or a login. Every service starts as the leader of
a new session (`setsid`), so a getty can take its terminal as controlling
terminal. `docs/examples/host/` has example units: a serial `agetty` (marked
`"essential": false`), `udevd` with a coldplug `udevadm trigger` oneshot,
`modprobe` and a foreground `udhcpc`. They are recipes for an image that
already contains those programs, the login and PAM configuration agetty's
`login` needs, udev rules and firmware; adjust paths and interfaces. None uses
autologin. `sahinit host device-wait --path /dev/vdb` is a oneshot that
waits for a device node.

### Readiness watchdog

A notify unit with `"watchdog": "5s"` must write a byte to fd 3 at least
every 5 s after it is ready; otherwise it is killed (`watchdog`) and its
restart policy applies. For a program that speaks sd_notify, wrap it:

```json
{"name":"agent","type":"simple","ready":"notify","watchdog":"5s","restart":"on-failure",
 "exec":["/sbin/sahinit","host","notify-adapter","--watchdog","5s","--","/usr/sbin/agent"]}
```

The adapter supports `READY=1` and `WATCHDOG=1` from its direct child only;
run the program in the foreground. This does not replace a hardware
watchdog: nothing pets `/dev/watchdog`.

### Power and signals

| Signal to PID 1 | Effect |
| --- | --- |
| SIGTERM or SIGUSR2 | power off |
| SIGINT (also Ctrl-Alt-Del) | reboot |
| SIGUSR1 | halt |
| SIGHUP | retry setup and boot, once the supervisor and recovery program are gone |

Shutdown: SIGTERM to the supervisor and up to `--shutdown-timeout` for it to
stop every service in reverse order; then SIGTERM and SIGKILL to every
remaining process (1 s each); sync; unmount every non-pseudo filesystem,
deepest first, remounting busy ones read-only (root last); sync; the power
operation. PID 1 never exits, even if the kernel refuses it.

## Journal

`supervise --log-dir /var/log/sahinit` (or `init --log-dir ...`) keeps a
bounded on-disk journal of every unit's stdout and stderr and of lifecycle
events; without it output lives only in the in-memory tails of
`ctl diagnostics`. Provision the directory on a writable filesystem:

```sh
install -d -o root -g root -m 700 /var/log/sahinit
sahinit logs --unit web --follow
sahinit logs --unit web --contains timeout --since 250
sahinit events --unit web --boot "$(cat /proc/sys/kernel/random/boot_id)"
```

A directory that cannot be used (read-only root, wrong owner or mode, another
supervisor's lock) never fails a boot: the supervisor logs
`journal_unavailable TOKEN` and runs without one. Retention is 1 MiB plus four
archives; a full in-memory queue drops records (counted in diagnostics). It is
bounded operational logging, not a tamper-evident audit log.

## Live catalog changes

```sh
sahinit validate --dir /etc/sahinit/candidate
sahinit ctl --socket /run/sahinit/control.sock --dir /etc/sahinit/candidate diff
sahinit ctl --socket /run/sahinit/control.sock --dir /etc/sahinit/candidate apply
sahinit ctl --socket /run/sahinit/control.sock rollback
sahinit ctl --socket /run/sahinit/control.sock explain web
```

`diff`, `apply`, `rollback` and `activate` are root only (`root_required`).
`apply` validates the whole candidate (graph, limits) before it stops
anything, stops changed and removed units and every unit that transitively
`needs` one, then starts the affected units that are desired. Unaffected
units keep running. A failed replacement restores the old catalog. Side
effects of programs (and finished oneshots) are not undone. The change lives
in memory only: deploy the files to `--dir` too, or the next supervisor start
loads the old ones. Catalogs with sash units cannot be changed live
(`catalog_sash`). With a deployment, use `ctl activate` instead.

## Deployments

Signed, verified catalogs with immutable generations: see
[deployments](../deployments.md).

## Sash services

A sash unit runs a sash service script; sahinit verifies a signed grant before
every start and performs the script's privileged verbs itself. Set-up, end to
end:

1. **Install sash** at a root-owned path, for example `/usr/bin/sash` (the
   default of `--sash`). It must pass the executable checks.
2. **Fleet key.** Install the fleet's Ed25519 public key (the signer keeps the
   private key; sahinit never holds it):
   ```sh
   install -o root -g root -m 644 fleet.pub /etc/sahinit/fleet.pub   # 32 raw bytes or 64 hex digits
   ```
3. **State directory** for floors and the mount table, private to the
   supervisor's uid:
   ```sh
   install -d -o root -g root -m 700 /var/lib/sahinit/sash
   ```
4. **Service account.** sash never runs as root: create a user and group, for
   example `app` (uid/gid 990). The script's `user` and `group` must name
   them.
5. **Service script and grant**, root-owned; the grant exactly 0600:
   ```sh
   install -d -o root -g root -m 755 /etc/sahinit/services /etc/sahinit/grants
   install -o root -g root -m 644 app.sash /etc/sahinit/services/app.sash
   install -o root -g root -m 600 app.grant /etc/sahinit/grants/app.grant
   ```
   The grant (`sash/2`, purpose `service`) must name `"service":"app"` and the
   same `user`/`group`, and list every program the script spawns (`exec`),
   every env name (`env_names`), the file roots (`file_read`, `file_write`),
   mount points and sources (`mounts`, `mount_sources`).
6. **Floor** (optional but recommended): a signed `sahinit-sash-floor/1`
   document raises the minimum grant serial for the service:
   ```sh
   sahinit sash floor-install --dir /var/lib/sahinit/sash --fleet-pub /etc/sahinit/fleet.pub app.floor
   sahinit sash floor-show --dir /var/lib/sahinit/sash --fleet-pub /etc/sahinit/fleet.pub
   ```
   Run these as the supervisor's uid (root). Without a floor every serial is
   admitted.
7. **Unit** `/etc/sahinit/units/app.json`:
   ```json
   {
     "name": "app",
     "sash": { "file": "/etc/sahinit/services/app.sash", "grant": "/etc/sahinit/grants/app.grant" },
     "execution": { "uid": 990, "gid": 990 },
     "sandbox": { "read_only_paths": ["/usr", "/etc/sahinit/services"], "read_write_paths": ["/srv/app"] }
   }
   ```
8. **Run** with the sash flags (for PID 1, the same flags go to `init`):
   ```sh
   sahinit supervise --dir /etc/sahinit/units --socket /run/sahinit/sahinit.sock \
     --sash /usr/bin/sash --sash-fleet-pub /etc/sahinit/fleet.pub --sash-floor-dir /var/lib/sahinit/sash
   ```
   At start sahinit runs `sash --describe` for each sash unit (as its uid,
   sandboxed, 5 s, in a scratch cgroup) and derives ordering, readiness, stop
   and restart from it. A unit that fails is left out with `TOKEN FILE`.
9. **Operate**: `ctl status app` shows the grant serial, the entries run and
   the process name table; `ctl reload app` and `ctl check app` run those
   entries; `ctl stop app` runs the `stop` entry, then kills the cgroup and
   unmounts the service's mounts.

Revoking a grant: install a floor with `min_serial` above the bad grant's
serial. The next start of that service fails with `sash_grant_revoked` (logged
`sash_grant app sash_grant_revoked`), without restart. A running service is
not stopped by a floor; stop and start it.

### Rotating the sash fleet key

There is one fleet key. Floors on disk verify only with the key that signed
them, and an install compares against the existing floor, so a floor signed by
the old key fails closed (`sash_floor_store_failed`) once the new key is in
place. Rotate with the supervisor stopped:

1. Have the signer issue, with the **new** key, a grant for every sash service
   (serial at or above its current floor) and a floor for every service that
   has one (`min_serial` at least the current one). Record the current floors:
   `sahinit sash floor-show --dir D --fleet-pub OLD.pub`.
2. Stop the supervisor (under PID 1: boot into recovery or another init).
3. Move the old floor files out of the state directory
   (`mv D/*.floor /root/old-floors/`). Until step 5 there is no floor.
4. Install the new key at the `--sash-fleet-pub` path (root, 0644).
5. Install the new floors: `sahinit sash floor-install --dir D --fleet-pub NEW.pub FILE`.
6. Install the new grants (root, 0600).
7. Start the supervisor; check `ctl status`.

Because steps 3 to 6 happen with nothing running, no start sees the gap.

## Boot policy

Boot policy is **metadata only** today: these commands verify and store signed
documents; the supervisor does not read them. Formats and rules are in
[boot policy](../boot-policy.md).

```sh
install -d -o root -g root -m 700 /var/lib/sahinit-policy
install -o root -g root -m 644 boot-trust.json /etc/sahinit/boot-trust.json
sahinit policy verify --trust /etc/sahinit/boot-trust.json --document policy.json
sahinit policy cache  --trust /etc/sahinit/boot-trust.json --document policy.json --cache /var/lib/sahinit-policy
sahinit policy status --trust /etc/sahinit/boot-trust.json --cache /var/lib/sahinit-policy
```

### `never` lifetime (the default)

A version-2 policy with `"lifetime":"never"` has no expiry and needs no clock.
It ends only when a higher sequence replaces it or a floor revokes it. To
revoke, install a signed `sahinit-boot-floor/1` floor:

```sh
sahinit policy floor-install --trust T --document floor.json --cache C
sahinit policy floor-show --trust T --cache C
sahinit policy status --trust T --cache C   # a policy below the floor: state revoked, exit 1
```

Floors only rise (`policy_floor_rollback`); the same floor again is a no-op;
a different floor at the same `min_sequence` is `policy_floor_conflict`.

### `renew` lifetime

A `renew` policy is valid in `[not_before, expires_at)`, in grace until
`offline_until`, then expired. Reading its state needs `--trust-system-clock`,
an explicit assertion that the system clock is trustworthy. Renewal is the
optional worker [`examples/policy-refresh.json`](../examples/policy-refresh.json):

```sh
sahinit policy refresh --trust T --cache C --endpoint https://ISSUER/PATH \
  --credential /var/lib/sahinit-refresh/credential --trust-system-clock
```

On a `never` host it prints `not_renewing` and exits 0 without any network
access. Give the unit `"restart": "on-failure"`. There is no issuer yet.

### Rotating boot-policy keys

The trust file holds up to 16 keys; each document names its `key_id`. A
cached policy or floor signed by a key that is no longer in the trust file
fails verification, which also blocks normal replacement. Rotate with overlap:

1. Add the new key to `keys` in the trust file, keeping the old one.
2. Install a policy signed with the new key at a higher `sequence`
   (`policy cache`; a `renew` policy also needs `--trust-system-clock`).
3. If a floor is installed, install a floor signed with the new key and a
   **higher** `min_sequence` (at most the new policy's sequence). Re-signing
   the same payload is treated as the same floor and keeps the old file.
4. `policy status` and `policy floor-show` must succeed.
5. Remove the old key from the trust file; run `policy status` again.

If the old key was removed too early, put it back, or (an administrator's
decision that discards anti-rollback state) remove `policy.json` and
`floor.json` from the cache and install fresh documents.

## Upgrading

- **Under another init:** replace the binary atomically
  (`install -m 755 sahinit /usr/local/sbin/sahinit.new && mv ... sahinit`),
  then restart the service. Stopping the supervisor stops every service; the
  new one cleans leftover service cgroups (`cgroup_leftover`) and sash mounts
  (`sash_mount_leftover`) and boots again. The supervisor re-executes its own
  binary as the sandbox helper for every launch, so restart it promptly after
  replacing the file rather than running a new helper under an old supervisor.
- **PID 1:** replace the binary and reboot. PID 1 does not re-execute itself.
- **Units:** check a new catalog with `sahinit validate`, then either
  `ctl --dir DIR apply` (root, no sash units) or restart the supervisor.
- **State:** policy caches, policy floors and sash floors only rise and are
  read by any version that has them; an upgrade does not touch them.

## Rollback

Keep the previous binary (`/usr/local/sbin/sahinit.prev`). To roll back,
move it into place and restart the supervisor (or reboot for PID 1). A
rolled-back binary that predates a feature refuses units using it (for
example `unknown_field` for a newer field), so roll the catalog back with it.
Floors and the policy cache are not rolled back by design. For PID 1 keep a
bootloader entry with the previous init (`init=/lib/systemd/systemd`, or
`init=/bin/sh` for a shell).

## Recovery

When the supervisor exits under PID 1 (a strict-boot failure, a crash), PID 1
kills everything in `/sys/fs/cgroup/sahinit`, then starts `--recovery` on the
console as root if one is configured (started again shortly after it
exits, so it is always available). Repair the catalog from recovery, then send SIGHUP to PID 1
(`kill -HUP 1`): once the recovery program exits, PID 1 re-runs setup and
starts the supervisor again.

- If the **init flags** are invalid, PID 1 logs
  `sahinit-init: recovery: setup: ERROR` (`invalid init configuration`, or Go's
  flag error for an unknown flag) and falls back to
  the defaults **without** a recovery program. SIGHUP cannot fix this, because
  the flags do not change. Reboot with corrected kernel arguments, or with
  another init.
- Without a recovery program, PID 1 stays up and answers the power signals
  and SIGHUP (which retries boot at once).
- The console log lines start with `sahinit-init:` (PID 1) or are the
  supervisor's tokens.

## Troubleshooting by symptom

| Symptom | Likely cause | Check or fix |
| --- | --- | --- |
| `supervise` exits 2 with `cgroup_unavailable` | not delegated; cgroup v1; read-only cgroupfs | `Delegate=yes`; `stat -fc %T /sys/fs/cgroup` is `cgroup2fs`; or `--no-cgroups` |
| `cgroup_busy` / `socket_busy` | another supervisor on the same cgroup root or socket | stop it |
| `socket_perm` | socket directory is `/tmp` or group-writable | `install -d -m 700 /run/sahinit` |
| a unit is missing from `status` | it was left out at load | the start-up stderr has `TOKEN FILE`; run `sahinit plan` |
| the whole catalog refuses with one token | a parse error in one file refuses the catalog | `sahinit plan --dir DIR` prints the token; check every file |
| `exec_perm` | a directory on the program's path is user-owned or group-writable | `namei -l /path/to/program` |
| `exec_interp` | `#!/usr/bin/env ...` | name the real interpreter |
| `ctl` says `peer_supervised` | run from inside a service, a service's session, or the root of an unprotected cgroup root | run from an admin shell outside the root; see `cgroup_root_unprotected` |
| `ctl` says `uid_denied` | uid not allowed | run as the supervisor's uid or add `--uid` |
| `ctl start` on a oneshot says `arg_required` | oneshots run at boot or through the `oneshot` op | expected |
| a notify service times out | it never writes to fd 3 | write one byte to `$SAHINIT_READY_FD` |
| a service restarts then `restart_limit` | crash loop (5 in 30 s) | `ctl diagnostics NAME`: stderr tail and `last_exit` |
| `cgroup_stuck` | a process in `D` state | find it in `ROOT/NAME.service/cgroup.procs` |
| a sandboxed unit fails with `sandbox_cap` | non-empty `caps` | remove `caps` |
| `landlock_unavailable` | Landlock not in `lsm=` | check `/sys/kernel/security/lsm` |
| a sash unit is left out with `sash_fleet_key` / `sash_floor_store` / `sash_cgroups` | sash flags missing, or `--no-cgroups` | add `--sash-fleet-pub`, `--sash-floor-dir` |
| `sash_describe` | sash missing, script error, or describe over 5 s | run `sash --describe FILE` as the service user |
| `sash_identity_mismatch` | the script's `user`/`group` do not resolve to the unit's ids | `getent passwd USER` |
| a sash start fails with `sash_grant_revoked` | serial below the floor | issue a newer grant |
| every sash start fails with `sash_floor_store_failed` | state directory permissions, or floors signed by an old fleet key | `ls -ln` the directory (0700, supervisor uid); see key rotation |
| PID 1 machine sits at a console after boot | strict boot failed | read the log lines before `recovery:` (`boot_service_failed NAME`); fix, or mark the unit `"essential": false`, and `kill -HUP 1` |
| a unit stays `blocked` | a `needs` provider is not ready | `ctl explain NAME` lists `blocked_by` |
| `journal_unavailable` at start | `--log-dir` read-only, missing parent, wrong owner or mode | `install -d -m 700 -o root DIR`; the supervisor runs without a journal meanwhile |
| `ctl apply` says `root_required` | not run as root | `sudo sahinit ctl ...` |
| a notify unit fails with `watchdog` | heartbeats stopped, or adapter and unit intervals differ | match `--watchdog` to the unit's `watchdog` |
| `policy status` says `clock_uncertain` | a `renew` policy without `--trust-system-clock` | establish trusted time, pass the flag |
| `policy_store_failed` | cache directory not owned by you or group-accessible | `chmod 700`, owned by the running uid |
