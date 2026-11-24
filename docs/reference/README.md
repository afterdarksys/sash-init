# sahinit reference

Complete reference documentation for `sahinit`, derived from the source code.
`internal/fail/docs_test.go` (run by `./build.sh`) fails when a token the code
emits is missing from [codes](codes.md), or a flag or command is missing from
[cli](cli.md).

| Page | Contents |
| --- | --- |
| [cli.md](cli.md) | Every command, subcommand and flag: types, defaults, constraints, output, exit status and error codes. |
| [units.md](units.md) | The unit JSON schema: exec and sash units, execution, sandbox, limits, readiness, restart, dependencies, boot, validation and refusal codes, with examples. |
| [environment.md](environment.md) | Environment variables sahinit sets for children, the clean-environment rules, and the file descriptors children receive. |
| [config-files.md](config-files.md) | Every file and directory sahinit reads or writes, with owner, mode and format rules; the control protocol and status schema. |
| [codes.md](codes.md) | Every refusal and diagnostic token: meaning and what to do. |
| [operations.md](operations.md) | Install, running under systemd or as PID 1, sash services end to end, boot policy, key rotation, upgrade, rollback, recovery, troubleshooting. |
| [security.md](security.md) | The trust model, what is guaranteed and what is not. |

Status: `supervise` under an existing init is the supported mode. PID 1 mode
is experimental. Boot policy is metadata only and not enforced. sash services
work with test-made grants and floors; no fleet signer or policy issuer exists
yet.

Design records and narrative guides: [execution and diagnostics](../execution.md),
[host init](../host-init.md), [boot policy](../boot-policy.md),
[migration](../migration.md), [roadmap](../roadmap.md), and the contracts in
[design/](../design/).
