# Boot-policy metadata verification and cache

Implemented: strict Ed25519 verification, local trust ceilings, validity states,
renewal ordering, a signed lifetime mode (`never` or `renew`), a signed
revocation floor, and a durable metadata cache. **This does not enforce boot policy
in the supervisor, validate catalog artifacts, start recovery, or run sash jobs.**
The one exception is a [verified deployment](deployments.md), where the
supervisor admits exec units by a staged policy; boot jobs are refused there.
Every CLI report says `"enforcement":"metadata_only"`. An optional renewal
worker (`sahinit policy refresh`) fetches `renew` policies from one provisioned
HTTPS endpoint; see [renewal worker](#renewal-worker-renew-mode-only). No
SystemAPI issuer for that endpoint exists yet.

## Commands

Supply an administrator-provisioned trust file and a signed document from the
issuer. These are example paths, not installed defaults:

```sh
sahinit policy verify --trust /etc/sahinit/boot-trust.json \
  --document /tmp/boot-policy.json --trust-system-clock

# Provision this private metadata directory before use.
mkdir -m 700 /var/lib/sahinit-policy
sahinit policy cache --trust /etc/sahinit/boot-trust.json \
  --document /tmp/boot-policy.json --cache /var/lib/sahinit-policy \
  --trust-system-clock

sahinit policy status --trust /etc/sahinit/boot-trust.json \
  --cache /var/lib/sahinit-policy --trust-system-clock

sahinit policy floor-install --trust /etc/sahinit/boot-trust.json \
  --document /tmp/boot-floor.json --cache /var/lib/sahinit-policy

sahinit policy floor-show --trust /etc/sahinit/boot-trust.json \
  --cache /var/lib/sahinit-policy
```

`--trust-system-clock` is an explicit assertion that the current UTC wall clock
was established by a trusted source. It does not authenticate time. On Linux,
that anchor advances with CLOCK_BOOTTIME, including suspend; backward wall-clock
changes cannot extend it. The library also accepts injected clocks for testing.
Unsupported platforms and invocations without the flag report `clock_uncertain`.
No timestamp in a policy establishes clock trust. Each new process/boot needs a
fresh trusted anchor; a disk timestamp alone does not establish elapsed downtime.

- `verify`: checks the signature, schema, identity, ceilings, and current normal
  validity. Prints a safe summary; exits 1 for grace, expiry, or uncertain time.
- `cache`: accepts only normally valid metadata and persists it after ordering
  checks. Does not activate configuration or extend any running job's authority.
- `status`: re-verifies cached metadata and reports its state, including grace or
  expiry, its `lifetime`, and `floor_min_sequence` when a floor is installed.
  Exit 0 means successful inspection, not permission to boot. A cached policy
  below the floor reports `"state":"revoked"`, `"error":"policy_revoked"` and
  exits 1; the revoked document's details are not printed.
- `floor-install`: verifies a revocation floor and persists it. A lower floor is
  refused (`policy_floor_rollback`); the same floor is an idempotent retry; a
  different floor with the same `min_sequence` is `policy_floor_conflict`.
  Needs no clock.
- `floor-show`: re-verifies and prints the installed floor, or
  `policy_floor_missing`.

A `never` policy needs no `--trust-system-clock` for `verify`, `cache` or
`status`: its validity does not read the clock.

Usage errors exit 2. Other failures exit 1 with a stable error token. Summaries
contain sequence, generation, payload digest, deadlines, and validity state, not
scripts, credentials, or the full policy. Invalid/missing caches report an error;
there is no silent repair or fallback to older documents.

## Trust file

All fields are required except `max_lifetime`. The local administrator provisions tenant, host,
enrollment and recovery-profile IDs; a map of key IDs to standard-base64 raw
32-byte Ed25519 public keys; and these integer ceilings:

| Field | Typical value | Accepted local range |
| --- | --- | --- |
| `max_validity_seconds` | 604800 | 1 through 31622400 |
| `max_grace_seconds` | 172800 | 0 through 31622400 |
| `max_job_seconds` | 300 | 1 through 86400 |
| `min_refresh_seconds` | 30 | At least 30 |
| `max_refresh_seconds` | 86400 | At least minimum, at most maximum validity |
| `max_lifetime` | `"never"` | `"never"` (both modes allowed; the default when omitted) or `"renew"` (refuses `never` policies with `policy_lifetime_cap`) |

The validity, grace and refresh ceilings apply to `renew` policies only; they
are still required. Tightening `max_lifetime` to `renew` makes a cached `never`
policy fail to load with `policy_lifetime_cap`. A `renew` replacement at a higher
sequence (and, since the mode changes, a higher catalog generation) still
installs over it: the cached document is read without the cap only to order the
new one.

Because an omitted `max_lifetime` means `never`, a trust file written before
this field existed accepts `never` policies signed by its keys. A host that
must always expire needs `max_lifetime: "renew"` written into its trust file.

There must be 1–16 distinct public keys. The trust file must be a regular file,
owned by root or the effective user and not writable by group/others; the command rejects
a symlink at its final component. Ancestor directories must be administrator
controlled. The trust input is never loaded from an issuer response. Key rotation
is not implemented: removing a key needed to verify the cache makes it unusable
and prevents normal replacement. Keep required old keys during planned migration;
the procedure is in [operations](reference/operations.md#rotating-boot-policy-keys).

A complete **test-only** example is
[`trust.json`](../internal/bootpolicy/testdata/trust.json). Its private seed is public
in the fixture tests. Never deploy that key or trust file on a real host.

## Wire contract: `sahinit-boot-policy/1` and `/2`

Two payload versions are accepted. The version selects the shape:

- `sahinit-boot-policy/1`: [`payload.json`](../internal/bootpolicy/testdata/payload.json).
  It has no `lifetime` field and is always `renew`, exactly as before; a
  `lifetime` field in a version-1 payload is refused.
- `sahinit-boot-policy/2`: [`payload-never.json`](../internal/bootpolicy/testdata/payload-never.json).
  The same fields plus a required `lifetime`, `"never"` or `"renew"`. New
  policies should be issued as version 2 with `"never"`, the default mode.
  A version-2 `renew` policy follows every version-1 time rule.

For `never`: `expires_at`, `offline_until` and `refresh_after_seconds` must be
`0`, and `not_before` must equal `issued_at` (no delayed start); anything else is
`policy_bad_shape`. `not_before` stays on the wire for a common shape but means
nothing more. A `never` policy is `valid` whatever the clock says, including no
clock, an untrusted clock, or a clock that jumps forward or back. It ends only
when a higher sequence replaces it or the revocation floor rises above it.
Changing lifetime mode is a permission change and needs a higher catalog
generation; moving from version 1 to version-2 `renew` at the same generation is
an ordinary renewal.

The complete, required payload shape is illustrated by the fixtures, with Go types in
`internal/bootpolicy/policy.go`. No unknown or missing fields are accepted, even
inside jobs, units, or scopes. Nulls and duplicate keys at any depth, trailing
JSON, and invalid UTF-8 are rejected. Empty arrays must be `[]`, not null/omitted.

Envelope fields are exactly `key_id`, `payload`, `signature`. The latter two use
canonical standard base64 (padding required where applicable; no whitespace).
Ed25519 signs the ASCII prefix `sahinit-boot-policy-v1` followed by a newline and
the **decoded payload bytes exactly as supplied**. The signature is 64 bytes.
The verifier never reconstructs JSON to check a signature. JSON key order and
whitespace may vary across separately signed policies; one sequence must retain
identical payload bytes across retries. Keys come only from local trust.

Verification order: local trust and input size; envelope/base64 shape; signature;
strict payload schema; host/recovery binding; semantic and ceiling checks. Cache
loading verifies all of these even when a document has expired.

Constraints:

- Envelope at most 384 KiB; decoded payload at most 256 KiB; nesting at most 16.
- IDs match `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. IDs are immutable enrollment labels,
  not hostnames. Digests are 64 lowercase hexadecimal characters.
- Sequences and generations are integers from 1 to 9007199254740991, so JavaScript
  and Go represent them exactly. Timestamp integers are positive UTC seconds,
  at most the same bound. Fractional/exponent forms are not accepted for integers.
- Require `issued_at <= not_before < expires_at <= offline_until`.
  Normal validity is limited from **issuance**, including a delayed start.
  Refresh interval is within local ceilings and strictly shorter than the normal
  window. Install refuses future/not-yet-valid documents, with no implicit skew.
- Up to 256 units and 256 jobs, with 64 dependencies/scopes per item. Graphs must
  be acyclic and references must exist. Jobs can depend on units and other jobs;
  units have unit dependencies. Cross-type reverse dependencies are not in v1.
- `offline_units` and `offline_jobs` must be subsets closed over their declared
  dependencies. Offline jobs cannot start units outside the offline subset.
  `runtime_restart_units` must also be dependency-closed. These validations are
  metadata checks, not runtime admission decisions.
- Job phases are `boot` and/or `cleanup`, without duplicates. Deadlines must fit
  the local ceiling. Scopes are unique `{operation, resource}` objects, with a
  named resource rather than a free-form executable or filesystem path.
- Recognized operation names: `mount.ensure`, `device.wait`, `module.load`,
  `network.apply`, `unit.start`, `unit.stop`, `unit.status`. These are reserved
  policy vocabulary, **not newly implemented sash verbs**. Unit scopes reference
  declared units; other resources require later catalog validation.

The catalog hash and script hashes are signed claims at this stage. Their files,
imported modules, executable artifacts, and actual dependency graph have NOT been
checked. No caller may use `Verify` or cache presence alone as execution authority.

## Revocation floor: `sahinit-boot-floor/1`

A floor is a separate signed document, in the same envelope, signed by a
boot-policy key from the trust file over the prefix `sahinit-boot-floor-v1` and a
newline (never the policy prefix, so neither document verifies as the other).
Its payload has exactly these fields, all required
([`floor-payload.json`](../internal/bootpolicy/testdata/floor-payload.json)):

| Field | Rule |
| --- | --- |
| `version` | `sahinit-boot-floor/1` |
| `tenant_id`, `host_id`, `enrollment_id` | Must match the trust file, as for a policy (`policy_host_mismatch`) |
| `min_sequence` | 1 through 9007199254740991. Policies with a lower sequence are revoked |
| `issued_at` | Positive UTC seconds, informational; the clock is never compared to it |

The floor applies to both lifetime modes. It is stored as `floor.json` in the
cache directory, with the same safety checks, lock, temporary file, fsync,
rename and directory fsync as `policy.json`. A missing floor means no floor. A
floor file that is unsafe, corrupt or fails verification fails closed: status,
caching a policy, and installing a new floor are all refused until an
administrator repairs it. `Load` refuses a cached policy below the floor with
`policy_revoked`, and `cache` refuses a new one the same way. The floor is
checked after verification, so a policy refused for another reason reports that
reason.

## Time states and renewal ordering

Normal validity is `[not_before, expires_at)`; grace is
`[expires_at, offline_until)`; expiry begins exactly at `offline_until`. Missing,
not-yet-valid, and clock-uncertain states are distinct. Zero grace is supported.
`Verify` does not use a clock, allowing expired cache to retain its anti-rollback
sequence. `CheckFresh` requires normal validity; `State` is observational only.
These time states apply to `renew` policies; a `never` policy is always `valid`.

A lower sequence is refused. An identical signed payload at the current sequence
is an idempotent retry; different payload bytes at that sequence are a conflict.
A higher sequence cannot reduce catalog generation. At the same generation,
only sequence, issuance/validity times, and refresh interval may change. Changes
to permissions, catalog hash, policy ID, jobs, dependency arrays, or subsets
require a higher generation. Array reordering also counts as a change.

This cache holds **latest verified metadata only**. It does not model active and
pending boot catalogs. A high-sequence document with unavailable artifacts can
therefore advance metadata ordering but cannot authorize execution. Future
activation must validate artifacts and maintain separate active/pending records;
it must not let a pending renewal extend the active catalog's authorization.

## Cache transaction and failure behavior

The caller provisions an owner-only directory. A directory FD anchors operations;
final-component symlinks, unsafe ownership/modes, hard-linked metadata/lock files,
and non-regular files are refused. An exclusive nonblocking file lock serializes
processes; a contending writer/reader receives `policy_store_busy` and can retry.

`policy.json` is the signed envelope and the high-water sequence together:

1. Verify the candidate and existing document; enforce renewal ordering.
2. Create a random, exclusive 0600 temporary file in the cache directory.
3. Write and fsync the complete envelope; close it and recheck time.
4. Atomically rename it to `policy.json`, then fsync the directory.
5. Acknowledge only after the directory sync succeeds.

There is no separately updated counter that could get ahead of its document.
After a process crash, readers observe the old or new complete document. A failure
after rename is an ambiguous commit: the open store fails closed and must be
reopened; retrying the same document is safe and resyncs the directory. Orphaned
`pending-*` files from process crashes are ignored, never adopted. No automatic
cleanup or disk-space quota is implemented yet.

These guarantees assume a local filesystem that honors rename/fsync semantics.
Tests terminate processes at transaction checkpoints; they do not simulate sudden
power loss or storage-controller failure. Deleting/replacing the cache directory,
restoring a full disk snapshot, privileged tampering, or substituting the binary
is outside this file-based anti-rollback guarantee. A missing cache is initial
provisioning, not proof that an earlier sequence never existed. Protected monotonic
state and a verified boot chain remain future work.

## Renewal worker (`renew` mode only)

```sh
sahinit policy refresh --trust FILE --cache DIR --endpoint HTTPS_URL \
  --credential FILE [--trust-system-clock] [--once]
```

The worker is optional and off the boot path. It does only one thing: fetch a
signed policy document and hand it to the same install path as `cache`. It
never activates configuration, restarts services or runs scripts, and every
event says `"enforcement":"metadata_only"`.

### Which hosts renew

The worker decides the host's mode before it reads a clock or a credential:

| Trust `max_lifetime` | Cached policy | Mode |
| --- | --- | --- |
| `renew` | anything or none | `renew` |
| `never` (or omitted) | `renew` (version 1, or version 2 `renew`) | `renew` |
| `never` (or omitted) | `never` | `never` |
| `never` (or omitted) | none | `never` |

The cached policy is read as `cache` reads it to order a replacement, so a
policy below the revocation floor, or a `never` policy after the cap was
tightened to `renew`, still renews; a new policy is how such a host recovers.
A corrupt or unsafe cache or floor fails closed before any request.

**`never` mode.** The worker prints one event,
`{"event":"not_renewing","ok":true,"error":"","enforcement":"metadata_only","lifetime":"never"}`,
and exits 0, in both run and `--once` modes. It needs no clock, reads no
credential and opens no connection. With an empty cache and a `never` cap the
first policy must be installed by other means (`policy cache`), or the cap set
to `renew`. If a refresh installs a `never` policy (allowed only by a `never` cap
and a higher catalog generation), the worker prints the attempt and
`not_renewing` and exits 0. Use `"restart": "on-failure"` so that a clean exit is
not restarted; start the worker again after the host moves to `renew`.

**`renew` mode.** `--trust-system-clock` is required in practice: without a
trusted clock the worker reports `policy_clock_uncertain` and exits 1, without
any request. A clock that loses trust while running ends the worker the same
way, since an anchored clock cannot regain trust in the same process.

### Transport and credential

The endpoint is provisioned locally, never discovered from a response. It must
be `https://` with a host and no user info, query or fragment
(`policy_refresh_config`, without echoing the URL). The client uses TLS 1.3
only, the system certificate roots, no environment proxy, no redirects (a 3xx
is a failure, and the credential is not resent), no compression, a 10-second
connect and handshake limit, a 20-second header limit, a 30-second overall
limit, 16 KiB of response headers and a body of at most 384 KiB
(`policy_refresh_size`).

The credential file is reread on every attempt, so it can be rotated in place.
It must be a regular file owned by the worker's effective uid, mode 0600 or
stricter, with one link, and not a symlink at its final component. Its content
is 32 to 4096 printable ASCII characters with no spaces, and at most one trailing
newline. Anything else is `policy_refresh_credential`, before any connection.
The credential is never printed, logged or put in an error.

### Request and response

```
POST <endpoint>
Authorization: Bearer <credential>
Content-Type: application/json
Accept: application/json

{"tenant_id":"...","host_id":"...","enrollment_id":"...",
 "sequence":N,"catalog_generation":N,"policy_sha256":"<payload sha256 hex>"}
```

The body comes from the trust file and the cached policy (zeros and `""` with no
cache). It is advisory: the issuer must authenticate the host from the
credential, select its assigned policy itself, and never take tenant, host,
permissions or scopes from the body.

Only `200` with a signed policy envelope as the body (no `Content-Encoding`
other than `identity`) can renew. `401` and `403` are `policy_refresh_denied`;
any other status, including `204` and `304`, is `policy_refresh_http`. The body is
passed to the same install as `cache`: signature, host binding, trust ceilings,
the lifetime cap, normal validity now, ordering and the floor. A response
identical to the cache is `policy_refresh_stale`; extending validity needs a new
sequence and signature. A failed or stale response never changes the cache or
extends its validity.

The worker does not accept floors. A floor arrives by other means
(`policy floor-install`).

### Schedule and events

Each line on stdout is one JSON event: `event` (`scheduled`, `attempt`,
`not_renewing`), `ok`, `error` (a token), `enforcement`, and when known
`lifetime`, `sequence` and `next_attempt_seconds`.

- At start, a valid cached `renew` policy that is not yet due
  (`issued_at + refresh_after_seconds`) is reported as `scheduled` with the wait,
  which is 80 to 100 percent of the time left, never later than the due time.
  Otherwise the first attempt is immediate, including in grace or after expiry.
- After a success the next attempt is the signed refresh interval with plus or
  minus 20 percent jitter, kept before normal expiry.
- After a failure the retry is 30 seconds, doubling to at most 5 minutes, with
  the same jitter and capped at 5 minutes.

`--once` makes one attempt and prints one `attempt` event (or `not_renewing`),
exit 0; a refusal prints its token on stderr and exits 1. SIGINT and SIGTERM stop
either mode with exit 0. A failure writing stdout stops the worker with exit 1.

### Example unit

[`examples/policy-refresh.json`](examples/policy-refresh.json) is a native
sahinit unit for the worker. Its endpoint (`ISSUER.invalid`) and uid/gid
(`64990`) are placeholders to replace; there is no default issuer, credential or
identity. It is sandboxed, so it must run as a non-root uid (`sandbox_root`), and
has no capabilities and `boot: false`. Before use, provision as root:

```sh
groupadd -g 64990 sahinit-refresh && useradd -u 64990 -g 64990 -M -s /usr/sbin/nologin sahinit-refresh
install -d -o root -g root -m 755 /var/lib/sahinit-refresh
install -o root -g root -m 644 boot-trust.json /var/lib/sahinit-refresh/boot-trust.json
install -d -o 64990 -g 64990 -m 700 /var/lib/sahinit-refresh/policy
install -o 64990 -g 64990 -m 600 credential /var/lib/sahinit-refresh/credential
```

A trust file may be owned by root or by the uid that runs the command, and must
not be group- or other-writable. Here it is root-owned, so the worker can read
but not change the keys it trusts. The cache must be owned by the worker uid;
the sandbox grants the trust file and credential read-only and only the cache
directory read-write. The sandbox paths for the system roots and name
resolution are Debian's; adjust them to the distribution. If `/etc/resolv.conf`
is a symlink (for example to systemd-resolved's stub file), list its real path
in `read_only_paths`. The example is checked by a test to parse as a sandboxed,
non-root unit; it has not been run against an issuer.

Outside a unit, `SSL_CERT_FILE` and `SSL_CERT_DIR` in the environment can
redirect the system roots, but a unit launch passes only the unit's own
`environment`. The endpoint URL is visible in `/proc/<pid>/cmdline`, so never
put a secret in it; the credential belongs only in the credential file.

### Not done

- No SystemAPI issuer, endpoint or host credential exists; the contract above is
  what an issuer must implement.
- The design's narrow local install interface is not built: the worker writes the
  cache itself. With a root-owned trust file it cannot change its trust keys,
  but a compromised worker can still write any policy those keys signed, or
  remove its cache. Separating the fetcher from the installer is future work.
- The cache is still metadata only; nothing reads it to admit units or jobs.
- No warning event before normal expiry, no durable record of the last attempt,
  and no floor delivery over the network.

## Verification

```sh
./build.sh
node scripts/check-boot-policy-vector.mjs
```

The first runs race tests, vet, and Linux cross-compilation including bootpolicy.
The second verifies the exact Go signatures in Node for the version-1 policy, the
version-2 `never` policy and the floor, reproduces them with the public test
seed, and checks both signature domains, a wrong key, a tampered payload, and two
negative vectors (`floor-wrong-domain.json`, `policy-wrong-domain.json`) that Go
refuses. It is not a production issuer.
Tests cover schema/identity rejection, validity boundaries, grace ceilings,
injected suspend/rollback, renewal ordering, concurrent writers, unsafe cache
files, corruption, expired-cache reload, and process interruption at commit stages;
lifetime shapes and version pairing, a `never` policy across clock jumps, the
trust cap, and floor tampering, wrong key, wrong domain, host binding, lower
floor, conflict, revocation of cached and new policies, unsafe or corrupt floor
files, and interrupted floor commits. Renewal tests use a local TLS 1.3 server:
success, denied and failing statuses, oversized and malformed bodies, large
headers, compression, rollback and stale responses, redirects and proxy
settings, untrusted certificates and TLS 1.2, credential shape, mode, symlink,
hard link, FIFO and rotation, cancellation, backoff and recovery, scheduling in
validity, grace and expiry, clock loss, `never` mode with no connection, a
`never` response under each cap rule, a revoked cache renewing, and a corrupt
cache or floor stopping before any request. CLI tests cover arguments, `--once`,
cancellation, output failure, and on Linux a trusted-clock run.

The design for subsequent issuance, sash sessions, catalog activation, and VM boot
remains in [renewable boot policy](design/renewable-boot-policy.md).
