# SAHINIT

A Go userspace service supervisor with strict JSON units, dependency boot waves,
readiness checks, restart limits, explicit execution identities, bounded output tails,
a Unix control socket, and optional Linux sandboxing.
It is not yet a PID 1 replacement.

```sh
go build -o /tmp/sahinit ./cmd/sahinit
/tmp/sahinit plan --dir ./units
/tmp/sahinit supervise --dir ./units --socket /run/sahinit/sahinit.sock
```

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
```

Execution context, local control commands, and lifecycle diagnostics are documented
in [execution and diagnostics](docs/execution.md).

Signed boot-policy metadata can be verified, cached, and inspected with
`sahinit policy`. See [boot-policy metadata](docs/boot-policy.md) for the wire
contract and scope; policy enforcement and network renewal are not wired yet.
