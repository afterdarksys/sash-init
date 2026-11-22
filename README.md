# SAHINIT

A Go userspace service supervisor with strict JSON units, dependency boot waves,
readiness checks, restart limits, a Unix control socket, and optional Linux sandboxing.
It is not yet a PID 1 replacement.

```sh
go build -o /tmp/sahinit ./cmd/sahinit
/tmp/sahinit plan --dir ./units
/tmp/sahinit supervise --dir ./units --socket /tmp/sahinit.sock
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
