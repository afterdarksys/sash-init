# Environment reference

sahinit **reads no environment variable of its own**: there is no
`SAHINIT_*` configuration variable, and every setting is a flag or a file.
This page lists what it sets for the processes it starts and the few
variables that still affect it through the Go runtime and libraries. It is
derived from `internal/unit/execution.go`, `internal/sandbox`,
`internal/hostinit/init_linux.go`, `internal/supervise/sash*.go` and
`internal/bootpolicy/refresh.go`.

## Variables sahinit sets

| Variable | Set for | Value |
| --- | --- | --- |
| `SAHINIT_READY_FD` | exec units with `"ready": "notify"`; every process a sash service spawns | `3`. Write at least one byte to fd 3 to report readiness. The fd is the write end of a pipe; close it when done. |
| `PATH` | every service process, the sandbox helper, `sash --describe`, `sash --session` and sash-spawned processes | `/usr/bin:/bin:/usr/sbin:/sbin` unless the unit's (or the spawn's) environment sets `PATH`, which then replaces it. |
| `PATH`, `HOME`, `TERM` | the supervisor and the recovery program started by PID 1 | exactly `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `HOME=/root`, `TERM=linux`, and nothing else. |

No other variable is added. In particular sahinit does not set `NOTIFY_SOCKET`,
`LISTEN_FDS`, `INVOCATION_ID`, `HOME`, `USER`, `LOGNAME` or `SHELL` for
services: set what a program needs in `execution.environment`.

## Clean environment rules

- **Services never inherit the supervisor's environment.** A service gets
  exactly its unit's `execution.environment`, plus the default `PATH` when it
  sets none, plus `SAHINIT_READY_FD=3` for notify readiness.
- `execution.environment` entries are literal `KEY=value` strings, with no
  shell expansion. At most 128 entries and 16 KiB in total. `KEY` must match
  `^[A-Za-z_][A-Za-z0-9_]*$`, must be unique and must not start with
  `SAHINIT_` (reserved). Any violation is `execution_invalid` at load.
- There are no environment files and no per-unit inheritance switch.
- The sandbox helper (`sahinit apply`) runs with the service's environment and
  passes it on unchanged (adding only `SAHINIT_READY_FD`).
- **sash units** may not set `execution.environment` (`sash_unit_field`).
  `sash --describe` and `sash --session` get only the default `PATH`.
- **Processes a sash service spawns** get the names the spawn asked for, only
  if each is on the grant's `env_names` list, matches
  `^[A-Z][A-Z0-9_]{0,63}$` and is not on the fixed denylist (`env_refused`
  otherwise). At most 128 entries and 16 KiB. The denylist (copied from
  sash's `internal/grant/policy.go` and pinned by a test vector) is:
  - prefixes `LD_`, `DYLD_`, `MALLOC_`, `GIT_`;
  - `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `RES_OPTIONS`,
    `GLIBC_TUNABLES`, `TZDIR`, `BASH_ENV`, `ENV`, `IFS`, `SHELLOPTS`,
    `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONWARNINGS`, `PERLLIB`,
    `PERL5LIB`, `PERL5OPT`, `PERL5DB`, `RUBYLIB`, `RUBYOPT`, `NODE_OPTIONS`,
    `NODE_PATH`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`,
    `CLASSPATH`, `LUA_PATH`, `LUA_CPATH`, `OPENSSL_CONF`, `OPENSSL_ENGINES`.

  A secret value passed to a spawn is written only into the child's
  environment: never into logs, status, diagnostics or events. A spawned child
  never dumps core (`RLIMIT_CORE` is always 0), so a dump cannot carry it.

## Variables that affect sahinit itself

sahinit does not read these, but the Go runtime or standard library does, in
the supervisor's own process (and in `sahinit policy`, which runs in yours):

| Variable | Effect |
| --- | --- |
| `GODEBUG`, `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT`, `GOTRACEBACK` | Go runtime behaviour. Under PID 1 the supervisor has none of them. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Where `sahinit policy refresh` finds the system root certificates (Go's `crypto/x509` on Linux). A unit launch passes only the unit's own environment, so set them there if needed. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | **Ignored**: the renewal client uses no proxy. |

The supervisor's own environment under another init (for example systemd) is
whatever that init gives it; it does not reach services.

## File descriptors (for completeness)

Not environment variables, but part of the same contract:

| Process | fd 0, 1, 2 | Other fds |
| --- | --- | --- |
| exec unit | `/dev/null`, captured stdout, captured stderr | fd 3: readiness pipe (notify only). A `#!` script also keeps fd 4 for its interpreter. Every other fd from 3 up is closed at exec. |
| `sash --session` | `/dev/null`, captured stdout, captured stderr | 3: grant bytes, 4: fleet public key, 5: a fresh per-session public key with no private half kept (sash requires one), 6: the verb socket. |
| sash-spawned process | `/dev/null`, its stream (`journal`, `null` or a `file:` path) | fd 3: readiness pipe. |
| PID 1 children | `/dev/console` | none |
