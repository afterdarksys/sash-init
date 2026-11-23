# SAHINIT

A Go userspace service supervisor with strict JSON units, dependency boot waves,
readiness checks, restart limits, explicit execution identities, bounded output tails,
a Unix control socket, optional Linux sandboxing, and a cgroup v2 cgroup per
service with kill-all and memory, CPU and PID limits.
It is not yet a PID 1 replacement.

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

Execution context, local control commands, and lifecycle diagnostics are documented
in [execution and diagnostics](docs/execution.md).

Signed boot-policy metadata can be verified, cached, and inspected with
`sahinit policy`, and `sahinit policy refresh` can renew `renew`-mode policies
from a provisioned HTTPS endpoint. See [boot-policy metadata](docs/boot-policy.md)
for the wire contract and scope; there is no issuer yet, and policy is not
enforced (metadata only).
