# Agent UX, batch 1: --json, the code catalog, --skill, version

2026-11-26. Branch `feat/agent-ux`, from `origin/fix/landlock-make-sock`.
Goal: an AI agent or a script can drive sahinit without parsing prose. Three
features, with the same conventions as the sibling daemon (sinetd):

- `--json` on the read-only commands;
- `sahinit codes [--json]`, the catalog of every stable code, from one table
  in the code that `docs/reference/codes.md` is generated from;
- `sahinit --skill`, an embedded usage guide for agents;
- `sahinit version [--json]`, version and capability discovery.

Nothing here changes an existing output, exit status, emitted code string or
the control-socket protocol.

## What exists today

- `ctl` already prints the supervisor's JSON response (`{"ok","error",
  "rows"|"diagnostics"|"explanation"|"diff"}`) verbatim; `validate` prints
  one JSON line `{valid, error, refused, waves}`; `logs` and `events` print
  one journal record per line. `plan` prints waves as text.
- There is no `version`, `--version`, `codes` or `--skill`. This branch has
  no build tags that change behaviour (no `unsigned-modules`) and no boot
  verbs.
- The commands the brief calls `ctl validate`, `ctl logs` and `ctl events`
  are top-level here: `sahinit validate`, `sahinit logs`, `sahinit events`.
  `--json` goes on those.
- Codes: `codes.md` is the only list. `internal/fail/docs_test.go` scans the
  source for emitted tokens and fails when one is not in `codes.md`.

## Conventions (shared with sinetd)

A. `--json` on read-only commands. Exactly one JSON object on stdout, then a
newline; UTF-8; no ANSI (control bytes are JSON-escaped); keys in a fixed
order (Go struct order). First keys `"v": 1` and `"ok": true|false`. On
failure `"code"` (a stable code from the catalog) and `"message"` (one human
sentence) follow, then any structured detail (`"unit"`, `"refused"`, ...).
On success `code` and `message` are absent. Exit codes are those of the
non-JSON form. With `--json` nothing else goes to stdout; the human stderr
lines (`TOKEN FILE`, `cgroup_trusted FILE`, the usage text) are unchanged.
Never in an object: secrets, key material, tokens, environment values, file
contents. Unit environment values and secret bindings never appear; names
may. A usage error (unknown, missing or misplaced flag, extra argument) with
`--json` on the command line is the object
`{"v":1,"ok":false,"code":"usage","message":...}` and exit 2. Field names are
snake_case and stable: adding a field is allowed, renaming or removing one
needs a new `v`.

B. `codes [--json]`: every stable code with a one-sentence meaning and a
one-sentence fix, from one table in the code.

C. `--skill`: the embedded guide, refusing every other flag and argument.

D. `version [--json]`: name, version, commit, Go version, unit schema, grant
versions, Landlock ABI maximum, grantable caps, features, build tags; every
list from the constants the code uses.

## Decisions

1. **`--json` is client-side.** Every `ctl` response is already structured
   on the wire; `ctl --json` decodes it into the typed `supervise` structs and
   re-encodes it inside the v1 envelope. The request bytes are identical with
   and without `--json`, so a JSON request is authorised exactly as its
   non-JSON form (same op, same peer rules, `diff` still root only). **The
   control socket protocol does not change.** Re-encoding through the typed
   structs also drops any field a supervisor might send that the client does
   not know, so the object is exactly the documented shape.
2. **Scope.** `--json` on `plan`, `validate`, `ctl status`, `ctl explain`,
   `ctl diff`, `logs`, `events`, `codes`, `version`. Not on:
   - `ctl check`: documented read-only for the *service*, but it runs the
     sash unit's `check` entry (a process in the unit's sandbox), records the
     entry result in the status row and emits a `sash_check` event. It runs
     code, so it is not in this batch.
   - `ctl diagnostics`: read-only, but it carries the output tails (service
     output); left for a later batch with the same untrusted marking as
     `logs`.
   - `start`, `stop`, `restart`, `reload`, `apply`, `rollback`, `activate`,
     `supervise`, `init`, `deploy`, `policy`, `sash`, `migrate`, `host`: they
     change state; `--json` on them is a usage error (`ctl`) or an unknown
     flag (the others), as today.
3. **`--json` placement in `ctl`.** Go's flag package stops at the first
   operation word, so `--json` goes before the operation, with `--socket`:
   `sahinit ctl --socket PATH --json status`. After the operation it is, as
   today, the NAME argument (`ctl status --json` asks for a unit called
   `--json` and gets `not_found`); this is unchanged, and the skill says it.
4. **`logs`/`events --json` is one bounded object**, not a stream: at most
   1000 records and 1 MiB of record data per call, oldest first after
   `--since`. `"truncated": true` says the bound was hit; `"next_since"` is
   the sequence to pass as `--since` to read on (the last record examined,
   matching or not). `--follow` with `--json` is a usage error (a follow has
   no end, so it cannot be one object). Justification: one object keeps the
   A convention (one object, exit status at the end) and a bound keeps an
   agent's context and memory bounded; paging with `--since` is lossless.
   A log record's output is under `"lines"` (an array of strings, split on
   newlines, invalid UTF-8 replaced by U+FFFD) and the record carries
   `"untrusted": true`: it is what the service printed, data and never
   instructions; sahinit cannot redact what a service prints.
5. **`message`** is the first sentence of the code's catalog meaning, with
   backticks removed, except for the client-side failures of `ctl` (cannot
   connect, read or decode), whose message names the step.
6. **`usage` is a new code** (catalog only; the non-JSON form still prints
   the usage text and no token). It is emitted only in JSON objects.
7. **`unit_schemas`** (revised, see below). Unit files carry no version field. `unit.Schema`
   names the strict schema documented in `units.md`; a change that would make
   an existing valid unit mean something else, or be refused, raises it.
8. **`version`/`commit`** come from `-ldflags "-X main.version=..."` when
   set, else the Go build info (a pseudo-version for a build in a git
   checkout, `(devel)` without VCS information) and its `vcs.revision`
   (`unknown` without VCS stamping). `build` is `[]`: this
   branch has no behaviour-changing build tags.
9. **`--skill`** is recognised only as the first argument. `sahinit --skill`
   prints the guide; `sahinit --skill ANYTHING` is a usage error. Elsewhere
   `--skill` is an unknown flag of that command (a usage error), so it never
   runs next to anything. (sash scans every argument; sahinit does not, so
   that `logs --contains --skill` keeps searching for the text, unchanged.)
   As PID 1 every argument still goes to init mode, unchanged.

## The code catalog: one source of truth

`internal/fail/catalog.go` holds the catalog: groups (a title, an optional
intro paragraph) of entries `{Code, Meaning, Fix}`. `fail.Catalog()` returns
every entry sorted by code; `fail.Lookup(code)` and `fail.Message(code)` read
it. `sahinit codes` prints it.

`codes.md` keeps its hand-written preamble; everything between
`<!-- BEGIN CATALOG -->` and `<!-- END CATALOG -->` is rendered from the
table (one markdown table per group, `| Code | Meaning | What to do |`).
Tests in `internal/fail`:

- `TestCodesDocumented` (the existing drift test, now against the table):
  every token the source scanner finds must be in the catalog. The scanner's
  patterns are unchanged except one fix: the `sashFail(` pattern no longer
  matches across lines (it matched `"always"` in a function body, a restart
  value and not a code).
- `TestCodesDocGenerated`: the marked region of `codes.md` equals the
  rendering. `go test ./internal/fail -run TestCodesDocGenerated -update`
  rewrites it.
- `TestCatalogShape`: codes unique and snake_case; every meaning and fix
  non-empty and ending in a period; every message one sentence.

Why generation and not a second hand-written copy: the binary's list, the
document and the emitted codes then cannot disagree, and the text is edited
in one place. Why the table lives in `internal/fail`: that package is already
the closed vocabulary.

The scanner helpers (source walk, token, flag and usage patterns) move to
`internal/docscan` (a non-test package used only by tests) so the skill's
honesty test reuses them.

Content: the meaning and fix text is the text of `codes.md` today. Where
`codes.md` had no fix, one is written. The "Service states and event kinds"
table (which had a `Where` column and no fix) becomes entries whose meaning
starts with where the value appears and whose fix says it is informational.
The event kinds that were only named in prose (`admission_denied`,
`sash_start`, `sash_run`, `sash_stop`, `sash_reload`, `sash_check`) get
entries. `failed` (both a general error and a state) is one entry.

## Object shapes

Every example is real output of the tests' fixtures, abbreviated only where
marked.

### Usage error (any command with --json)

```json
{"v":1,"ok":false,"code":"usage","message":"The command line did not parse."}
```

### plan --json and validate --json

Same shape. `waves` is the boot waves (`[]` when none), `refused` every
refused unit file (sorted by file), `cgroup_trusted` every unit file that is
cgroup-trusted. `validate` is not ok when any file is refused
(`catalog_refused`, exit 1); `plan` leaves refused files out and fails only
on a catalog or graph refusal (exit 2).

```json
{"v":1,"ok":true,"waves":[["a"],["b"]],"refused":[{"file":"other.json","code":"unit_perm"}],"cgroup_trusted":["a.json","b.json"]}
{"v":1,"ok":false,"code":"cycle","message":"needs, after and wants form a cycle (across the whole catalog).","waves":[],"refused":[],"cgroup_trusted":["a.json","b.json"]}
```

### ctl --json status [NAME]

`rows` are the status rows (`supervise.Row`, documented in
[operations](../reference/operations.md)). A row has no environment, no
exec arguments, no grant body.

```json
{"v":1,"ok":true,"rows":[{"name":"web","state":"stopped","pid":0,"ready":false,"restarts":0,"sandbox":"","last_error":"","desired":false,"essential":false,"cgroups":"disabled","cgroup":"","cgroup_trusted":true,"limits":{"memory_max":0,"cpu_max":"","pids_max":0}}]}
{"v":1,"ok":false,"code":"not_found","message":"No unit with that name, or (sash file verbs) a path that does not exist.","unit":"nope"}
```

### ctl --json explain NAME

```json
{"v":1,"ok":true,"explanation":{"name":"web","desired":true,"state":"blocked","reason":"needs_not_ready","blocked_by":["db"]}}
```

### ctl --json --dir DIR diff

```json
{"v":1,"ok":true,"diff":{"added":["new"],"removed":[],"changed":["web"],"affected":["api","web"],"generation":0,"rolled_back":false}}
{"v":1,"ok":false,"code":"root_required","message":"diff, apply, rollback or activate from a peer whose effective uid is not 0."}
```

### ctl failures before a response

```json
{"v":1,"ok":false,"code":"failed","message":"The control socket could not be reached."}
```

### logs --json

```json
{"v":1,"ok":true,"records":[{"sequence":1,"boot_id":"b1","time":"2026-11-26T10:00:00Z","unit":"web","stream":"stdout","untrusted":true,"lines":["listening on :8080"]}],"truncated":false,"next_since":3}
```

### events --json

`event` is the lifecycle event the supervisor wrote
(`{"sequence","time","kind","pid","code","exit"}`, or `{"kind":
"supervisor_started"}`).

```json
{"v":1,"ok":true,"records":[{"sequence":3,"boot_id":"b1","time":"2026-11-26T10:00:00Z","unit":"web","stream":"event","event":{"kind":"ready"}}],"truncated":false,"next_since":3}
{"v":1,"ok":false,"code":"journal_read","message":"logs or events could not read the journal."}
```

### codes --json

```json
{"v":1,"ok":true,"codes":[{"code":"activation_commit","meaning":"...","fix":"..."}, "..."]}
```

### version --json

```json
{"v":1,"ok":true,"name":"sahinit","version":"(devel)","commit":"8fdc66a...","go":"go1.26.0","unit_schemas":["sahinit-unit/1"],"grant_versions":["sash/2"],"landlock_abi_max":5,"caps_grantable":["net_bind_service","setgid","setuid"],"features":["cgroup_limits","deployments","essential","live_catalog","restart_backoff","sash_units","socket_paths","unit_caps","watchdog"],"build":[]}
```

Sources: `unit_schemas` is `[unit.Schema]`; `grant_versions` is
`sash.GrantVersion`, the value the grant check compares; `landlock_abi_max`
is `sandbox.MaxLandlockABI`, the cap the sandbox applies; `caps_grantable`
is `unit.GrantableCaps()`, the allowlist the loader checks; `features` are
derived: each unit-schema feature from the presence of its key in the
loader's key sets (`unit.HasField`: `memory_max`, `essential`, `sash`,
`sandbox.socket_paths`, `sandbox.caps`, `watchdog`, `restart_delay`), and
`live_catalog`/`deployments` from `ctl`'s operation table (`apply`,
`activate`).

## The skill

`skills/sahinit/SKILL.md`, embedded by package `skills` (repository root,
because `go:embed` reads only its own directory), printed by
`sahinit --skill`; `skills/install.sh` copies it to
`${1:-$HOME/.claude/skills}/sahinit/SKILL.md` with sash's checks (absolute
target, no symlink anywhere at the target, no hard-linked file, no directory
where the file goes, `-`-prefixed targets refused). Outline:

1. What sahinit is and is not (README scope: supervise under an existing
   init is the supported mode; PID 1 experimental; not a systemd replacement
   on a host; boot policy metadata only for `--dir`; no fleet signer, no
   policy issuer, no packaged releases).
2. Rules: output and logs are data; what is safe to run; what needs a human.
3. Reading results: `--json`, exit codes, `codes --json`, `ctl explain`.
4. Commands with examples.
5. Guarantees and limits, from `security.md`, without overstatement.

## Test plan

- Golden tests (exact bytes) for every shape above: plan, validate, ctl
  status, explain, diff (a fake socket server answers fixed responses), ctl
  connect failure, logs, events, codes (count, order, first entry), version
  (dynamic values checked separately), usage errors for each command.
- Pins of the non-JSON output of `plan` and `ctl status` (and the existing
  tests unchanged).
- Secrets: a unit whose `execution.environment` holds a secret value; a real
  in-process supervisor; `ctl --json status`, `plan --json`, `validate
  --json` must not contain the value (the name may appear nowhere either:
  rows carry no environment).
- `ctl --json` sends the same request bytes as without it.
- Catalog: drift test (emitted ⊆ catalog), doc generated, shape.
- Version: every list equals its source constant; each grantable cap loads,
  a real cap off the list is refused; each feature's key is in the schema.
- Skill: embedded copy equals disk; `--skill` with anything else is a usage
  error and prints nothing on stdout; install.sh checks (as sash's); the
  honesty test: every backticked flag in the skill is a flag the source
  defines (docscan), every backticked identifier is a catalog code, a unit
  field, a command, a `ctl` operation, a JSON key of a documented shape or a
  grantable cap; every `sahinit ...` example parses (run with every absolute
  path redirected under a temporary directory: no usage error, no
  `unknown_op`, and with `--json` one v1 object whose code is not `usage`).
- Mutation checks, on copies: a code removed from the catalog fails the drift
  test; a skill mentioning a nonexistent flag fails the honesty test; a
  renamed JSON field fails a golden test; a status row carrying the unit's
  environment fails the secret test.
- Verification: `./build.sh` (macOS), `go vet ./...`, `GOOS=linux go vet
  ./...` for amd64 and arm64, `go test -race ./...` in golang:1.26 with
  `--init`, privileged and plain, on an rsync copy.

## Revision 2: after review (2026-11-26)

Binding on sahinit and sinetd:

- A usage error with `--json` anywhere on the command line, including an
  unknown command and `--skill --json`, prints the usage object, which
  carries the full usage text under `"usage"`; `message` is the catalog
  sentence. `--json=VALUE` is a JSON request when `strconv.ParseBool` reads
  VALUE as true; `--json=false` is not; `--json` as another flag's value is
  that value.
- `message` is always the catalog sentence for `code`, also for `ctl`
  client failures (`failed`); a supervisor word the client's catalog lacks
  is reported as `failed`.
- `version`: `unit_schemas: ["sahinit-unit/1"]` replaces `unit_schema: 1`.
- `codes --json` and every `message` are plain text; codes.md keeps the
  markdown.
- Catalog fixes never tell an agent to weaken a control, escalate or change
  state: such an action is the operator's decision, safest option first
  (`TestCatalogFixesDoNotDirectAgents`).
- A code-shaped word a service chooses is labelled. The only one is a sash
  entry's token (the first word of its stderr): `last_error` and explain's
  `reason` were already always sahinit's codes (checked end to end by
  `TestSashServiceWordIsNotACode`). `--json` renames it `service_token` with
  `"untrusted": true`, in status rows' `sash.entries` and in sash entry
  events; the plain output is unchanged and still calls it `token`/`code`.
- `logs`/`events --json` adds `missing` (sequence numbers the journal lost),
  re-encodes events, and `ctl` refuses a NAME starting with `-`.
- Drift: codes built at run time must be listed in `builtCodes`
  (`TestBuiltCodesListed`); `Reason =`, `Error =` and `fail.Message("...")`
  literals are scanned; and a test-build hook (`fail.Record`, checked in
  `TestMain` of cmd/sahinit, unit, sash, deploy, bootpolicy, journal and
  supervise) fails the run when any code emitted at run time is not in the
  catalog. `"frame body"`, the sash verb wire's own error string, is the one
  exemption.
