# Linux host init

`sahinit` now includes an experimental PID 1 parent for a local-root Linux
machine. The existing `supervise` command remains usable under another init.
This is a bootable foundation, not a complete distribution init replacement.

Build a static binary for the target architecture:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sahinit ./cmd/sahinit
```

An initramfs may install it as `/init`, or hand over an already mounted local
root containing the binary and its unit catalog. When invoked as PID 1 it enters
init mode automatically. No host installation or bootloader changes are performed
by the build or tests. `sahinit init` in an ordinary process refuses to run.

Defaults and options:

```text
init --dir /etc/sahinit/units --socket /run/sahinit/control.sock
     --shutdown-timeout 30s [--recovery /absolute/local/executable]
     [--sash /absolute/sash] [--sash-fleet-pub /absolute/fleet.pub]
     [--sash-floor-dir /absolute/dir]
```

The `--sash*` options are passed to the supervisor unchanged (see
[sash services](design/sash-services-1.md)). Without `--sash-fleet-pub` and
`--sash-floor-dir` every sash unit is refused at load, which strict boot treats
as a failed boot.

The kernel must provide procfs, sysfs, devtmpfs, tmpfs, cgroup v2 and
`clone3(CLONE_INTO_CGROUP)` (Linux 5.7+). Recovery cgroup cleanup uses
`cgroup.kill` (Linux 5.14+); use Linux 5.14 or newer for this host mode.
The VM suite currently exercises Debian's Linux 6.1 amd64 kernel. Kernel
configuration still matters; version alone does not guarantee these facilities.

PID 1 mounts `/proc`, `/sys`, `/dev`, `/dev/pts` (devpts, `ptmxmode=0666`),
`/dev/shm` (tmpfs, 1777), `/run` and `/sys/fs/cgroup`, creates a sticky `/tmp`
when it is missing, makes mount
propagation private, opens `/dev/console` as standard input/output/error, enables
the available CPU, memory and PID controllers, and starts a supervisor in
`/sys/fs/cgroup/sahinit/supervisor`. Service cgroups are siblings below
`/sys/fs/cgroup/sahinit`.

The supervisor is a separate child. It owns waits for service processes; PID 1
owns waits for the supervisor, recovery process and adopted orphans. This avoids
a competing `wait4(-1)` consuming an `exec.Cmd.Wait` result in the same process.
See the Linux [wait semantics](https://man7.org/linux/man-pages/man2/wait.2.html).

## Failure and recovery

Host mode starts the supervisor with `--boot-strict`. Refused unit files,
unavailable requested limits and invalid graphs enter recovery. Every boot unit
is essential unless its unit says `"essential": false`: an essential unit that
fails, that stops on its own, that is not ready when the boot waves finish, or
whose `needs` provider failed, shuts down the supervisor and enters recovery.
A unit marked `"essential": false` fails alone; its dependents are paused
(`blocked`) and resumed when it is ready again. Successful oneshots may stay
exited; explicit administrative stops stay stopped. Ordinary `supervise`
(without `--boot-strict`) never stops for a failed unit.

PID 1 remains alive when the supervisor fails. It kills the managed cgroup tree
and optionally launches the configured local recovery executable on the console.
No recovery executable is enabled by default. An enabled executable runs as root
on the local console; provision an authenticated recovery program where needed.
The supervisor and recovery executable receive a fixed minimal environment.

Send SIGHUP to PID 1 to request a retry of setup and boot once recovery exits.
A recovery program can send it before exiting. Recovery launch failures are
rate-limited; PID 1 still handles power signals. Invalid command-line arguments
cannot be repaired by SIGHUP because those arguments remain the same.

## Power operations

| Signal to PID 1 | Action |
| --- | --- |
| SIGTERM or SIGUSR2 | Poweroff |
| SIGINT (including Ctrl-Alt-Delete) | Reboot |
| SIGUSR1 | Halt |
| SIGHUP | Request boot retry when supervisor is absent; wait for recovery to exit |

PID 1 first gives the supervisor the configured shutdown deadline. The supervisor
stops dependents before providers, including manually started units; independent
units in each wave stop concurrently. PID 1 then terminates remaining processes,
escalates to KILL, reaps, syncs, attempts `swapoff` of every active swap area,
attempts deepest-first unmounts of data mounts,
remounts busy filesystems/root read-only, syncs again and invokes the kernel power
operation. Pseudo filesystems remain available for diagnostics. Failed unmounts
and power operations are logged; PID 1 never deliberately exits after setup.
Uninterruptible kernel I/O can still block sync/unmount; a hardware watchdog is
not implemented. See Linux [reboot semantics](https://man7.org/linux/man-pages/man2/reboot.2.html).

## Verification and remaining scope

```sh
./build.sh                  # native race tests, vet, Linux test compilation
./scripts/test-linux.sh     # Linux race suite with private cgroup namespace
python3 scripts/test-boot.py # QEMU boots, serial assertions, bounded VM lifetime
python3 scripts/test-boot.py --scenario sash  # only the sash scenario
```

The QEMU harness uses disposable initramfs images and no VM network or host
disks. It retains serial logs and images in the printed temporary directory.
`--assets DIR` reruns existing images; those images must be rebuilt to test new
source. The fixture tests orphan adoption/reaping, service cgroups, reverse
shutdown, poweroff/reboot, bad configuration, failed boot, failed runtime service,
supervisor crash, a service ignoring TERM and boot retry after recovery repairs
the catalog.

The `sash` scenario runs real sash services under PID 1. The images include a
static sash built from the sash repository (`SASH_SRC` or `--sash-src`, default
`../sash-initp1`, branch `feat/init-phase1`, passed read-only as a Docker build
context). `tests/boot/sashfix` makes a fleet key in memory each time the images
are built and writes only its public half, the signed `sash/2` grants and a
signed floor; the private key is never written, and nothing is committed. The
floor is installed with `sahinit sash floor-install`. Init runs with `--sash
/sash --sash-fleet-pub /etc/sahinit/fleet.pub --sash-floor-dir
/var/lib/sahinit/sash`. The image holds:

- `svc` (boot): makes `/srv/svc/d` (0750, nobody) and a file in it, mounts a
  tmpfs at `/mnt/svc` and spawns `/probe sleeper` as nobody, which signals
  readiness on the notify pipe; its stop entry stops it and touches
  `/srv/svc/stopped`.
- `revoked` (not boot): a valid grant at serial 5 below its floor of 6.
- `sashcheck` (boot oneshot, root, no sandbox): starts the driver in a new
  session and moves it to the root cgroup, because the control socket refuses
  peers that are supervised services (`peer_supervised`).

The driver asserts, through `sahinit ctl` and `/proc`, that `svc` is running
and ready at grant serial 5; its spawned process is in
`/sahinit/svc.service` as uid 65534; the directory, the file and the tmpfs
(`nosuid,nodev,noexec`) exist; `ctl start revoked` fails with
`sash_grant_revoked`, the unit is failed with no restart and `svc` keeps
running; and `ctl stop svc` runs the stop entry (exit 0, the file it touched),
the spawned process and the service cgroup are gone and `/mnt/svc` is
unmounted. It then powers off. The serial log must also carry the supervisor's
`sash_grant revoked sash_grant_revoked`. It takes about 75 s under TCG, so it
gets at least 180 s.

The revoked unit is not a boot unit on purpose: in host mode every boot unit is
essential, so a boot unit whose grant is refused enters recovery. The refused
grant "fails the unit without stopping boot" only for a unit that is started
later. Not covered here: shutdown (rather than `ctl stop`) of a running sash
service, bind mounts, restart policy and the `check` and `reload` entries.

The `notify` scenario runs an sd_notify service through `sahinit host
notify-adapter` with a 500 ms watchdog; it sends three heartbeats and stops,
and the watchdog kills it (the unit is `"essential": false`, so the host does
not enter recovery). The `persistent` scenario (`--scenario persistent`)
builds an ext4 root image and an initramfs whose `/init` is
`contrib/initramfs/init`: that script, not sahinit, runs `e2fsck -p`, mounts
the root and `switch_root`s to `/sbin/sahinit init`. It boots the disk twice,
checks a counter survives and runs an offline `e2fsck -fn` after each
shutdown. No host disk is attached. See [operations](reference/operations.md)
for the initramfs entry point, the journal, live catalog changes and the
console, device and network examples, and [deployments](deployments.md) for
verified deployment generations.

Still outside this milestone: root discovery beyond `sahinit.root=/dev/...`,
encrypted, LVM/RAID or network root, device hotplug, network configuration
beyond the example units, hardware watchdogs and distribution packaging.
Services may supply some of these. sahinit itself does no fsck and no
switch_root; the initramfs script does.

Deployments carry exec units only (no sash units, no boot jobs); there is no
SystemAPI issuer and no artifact downloader. Sash services run under PID 1
(the `sash` VM scenario), with test-made grants and floors; there is no fleet
signer yet. Existing Linux sandbox/cgroup trust limitations continue to apply.
Service watchdogs do not provide a hardware reset guarantee.
