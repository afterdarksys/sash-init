# Minimal Linux host init

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
```

The kernel must provide procfs, sysfs, devtmpfs, tmpfs, cgroup v2 and
`clone3(CLONE_INTO_CGROUP)` (Linux 5.7+). Recovery cgroup cleanup uses
`cgroup.kill` (Linux 5.14+); use Linux 5.14 or newer for this host mode.
The VM suite currently exercises Debian's Linux 6.1 amd64 kernel. Kernel
configuration still matters; version alone does not guarantee these facilities.

PID 1 mounts `/proc`, `/sys`, `/dev`, `/run` and `/sys/fs/cgroup`, makes mount
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
unavailable requested limits, invalid graphs and failed boot waves enter recovery.
All boot units are essential in this mode: a failed boot unit or an unexpectedly
exited long-running boot unit shuts down the supervisor and enters recovery.
Successful oneshots may stay exited; explicit administrative stops stay stopped.
Ordinary `supervise` retains its previous best-effort boot behavior.

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
escalates to KILL, reaps, syncs, attempts deepest-first unmounts of data mounts,
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
```

The QEMU harness uses disposable initramfs images and no VM network or host
disks. It retains serial logs and images in the printed temporary directory.
`--assets DIR` reruns existing images; those images must be rebuilt to test new
source. The fixture tests orphan adoption/reaping, service cgroups, reverse
shutdown, poweroff/reboot, bad configuration, failed boot, failed runtime service,
supervisor crash, a service ignoring TERM and boot retry after recovery repairs
the catalog.

Still outside this milestone: root discovery/switch-root, fsck, encrypted or
network root, device hotplug/module loading, swap teardown, PTY/login setup,
network configuration, durable logs, hardware watchdogs, live transactional
reload and targeted dependency failure propagation. Services may supply some of
these. Persistent-disk teardown is not proven by the initramfs tests.

Signed policy remains metadata-only; verified artifact admission, the SystemAPI
issuer and sash boot execution are separate unfinished integrations. Existing
Linux sandbox/cgroup trust limitations continue to apply.
