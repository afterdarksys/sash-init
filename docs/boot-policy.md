# Boot-policy metadata verification and cache

Implemented: strict Ed25519 verification, local trust ceilings, validity states,
renewal ordering, a signed lifetime mode (`never` or `renew`), a signed
revocation floor, and a durable metadata cache. **This does not enforce boot policy
in the supervisor, validate catalog artifacts, start recovery, or run sash jobs.**
Every CLI report says `"enforcement":"metadata_only"`. SystemAPI issuance and
network refresh are the next integration slice.

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
policy fail to load.

There must be 1–16 distinct public keys. The trust file must be a regular file,
owned by the effective user and not writable by group/others; the command rejects
a symlink at its final component. Ancestor directories must be administrator
controlled. The trust input is never loaded from an issuer response. Key rotation
is not implemented: removing a key needed to verify the cache makes it unusable
and prevents normal replacement. Keep required old keys during planned migration.

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
files, and interrupted floor commits.

The design for subsequent issuance, sash sessions, catalog activation, and VM boot
remains in [renewable boot policy](design/renewable-boot-policy.md).
