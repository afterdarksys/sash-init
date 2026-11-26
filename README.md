# SAHINIT

**Reference documentation:** [docs/reference](docs/reference/README.md): every
command and flag, the unit schema, environment, files, every refusal code,
operations (install, PID 1, sash services, key rotation, upgrade, recovery,
troubleshooting) and the security model.

**Current scope.** `supervise` under an existing init with a delegated cgroup
v2 is the supported mode. PID 1 mode is **experimental** (QEMU initramfs boots
only). Boot policy is **metadata only** for `--dir` catalogs: verified and
cached, never enforced; a [verified deployment](docs/deployments.md)
(`--deployment-root`, exec units only) is the one mode where a signed policy
admits units, and it has no issuer yet.
sash services run with test-made grants and floors: there is no fleet signer
and no policy issuer yet. Sandboxed exec units may hold only `net_bind_service`, `setuid` and
`setgid` ([unit capabilities](docs/design/unit-caps-1.md)), and the network is
not confined. There are no packaged releases.

A Go userspace service supervisor with strict JSON units, dependency boot waves,
readiness checks, restart limits, explicit execution identities, bounded output tails,
a Unix control socket, optional Linux sandboxing, and a cgroup v2 cgroup per
service with kill-all and memory, CPU and PID limits.
An experimental Linux PID 1 parent adds early mounts, orphan reaping, recovery
and host power operations. See [host init](docs/host-init.md) for boot assumptions,
VM tests and remaining limitations.

```sh
go build -o /tmp/sahinit ./cmd/sahinit
/tmp/sahinit plan --dir ./units
/tmp/sahinit supervise --dir ./units --socket /run/sahinit/sahinit.sock
```

On Linux `supervise` needs a delegated cgroup v2, for example systemd's
`Delegate=yes`, and refuses to start without one (`cgroup_unavailable`).
`--no-cgroups` keeps plain process groups; status reports that, and units with
limits are refused. Units without a sandbox that run as root or as the
supervisor's uid are `cgroup_trusted`: the cgroup guarantees are not promised
for them. See [cgroups](docs/execution.md#cgroups).

Preview migration from systemd, daemontools, or OpenRC:

```sh
/tmp/sahinit migrate --from systemd --source ./exported-services
# Write a new catalog; --boot explicitly enables startup:
/tmp/sahinit migrate --from systemd --source ./exported-services --out ./units --boot
```

The converters support a documented static subset and report unsupported semantics.
They never execute source scripts or replace the running init system.
See the [migration guide](docs/migration.md) for compatibility and the
[feature roadmap](docs/roadmap.md) for priorities.

```sh
./build.sh
./scripts/test-migration-docker.sh
# Linux suite as root, with a writable cgroup2 for the cgroup tests:
docker run --rm --init --privileged --cgroupns=private -v "$PWD":/src -w /src \
  -v sahinit-gomod:/go/pkg/mod -e GOFLAGS=-buildvcs=false golang:1.26-bookworm go test -race ./...
```

Without `--privileged --cgroupns=private` the cgroup tests are skipped, and
each one says why.

A unit may name a sash service script instead of `exec`. sahinit then runs `sash --describe` at load, verifies the service's signed `sash/2` grant and its per-service floor before every start, and performs the script's process verbs itself after re-checking each one. See [sash services, batch 1](docs/design/sash-services-1.md). `./scripts/test-sash-docker.sh` builds sash from its repository and runs the end-to-end tests against it.

For scripts and AI agents: `plan`, `validate`, `ctl status|explain|diff`,
`logs`, `events`, `codes` and `version` take `--json` (one JSON object on
stdout, stable fields, a stable `code` on failure); `sahinit codes` prints
every code with its meaning and fix. See
[JSON output](docs/reference/cli.md#json-output).

Execution context, local control commands, and lifecycle diagnostics are documented
in [execution and diagnostics](docs/execution.md).

Signed boot-policy metadata can be verified, cached, and inspected with
`sahinit policy`, and `sahinit policy refresh` can renew `renew`-mode policies
from a provisioned HTTPS endpoint. See [boot-policy metadata](docs/boot-policy.md)
for the wire contract and scope; there is no issuer yet, and policy is not
enforced (metadata only).

## License

sahinit is free software, licensed under the GNU General Public License, version 3 or (at your option) any later version (GPL-3.0-or-later). See [LICENSE](LICENSE). Every Go source file carries an `SPDX-License-Identifier: GPL-3.0-or-later` header.
