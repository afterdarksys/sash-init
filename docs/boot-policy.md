# Boot-policy metadata verification and cache

Implemented: strict Ed25519 verification, local trust ceilings, validity states,
renewal ordering, and a durable metadata cache. **This does not enforce boot policy
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
  expiry. Exit 0 means successful inspection, not permission to boot.

Usage errors exit 2. Other failures exit 1 with a stable error token. Summaries
contain sequence, generation, payload digest, deadlines, and validity state, not
scripts, credentials, or the full policy. Invalid/missing caches report an error;
there is no silent repair or fallback to older documents.

## Trust file

All fields are required. The local administrator provisions tenant, host,
enrollment and recovery-profile IDs; a map of key IDs to standard-base64 raw
32-byte Ed25519 public keys; and these integer ceilings:

| Field | Typical value | Accepted local range |
| --- | --- | --- |
| `max_validity_seconds` | 604800 | 1 through 31622400 |
| `max_grace_seconds` | 172800 | 0 through 31622400 |
| `max_job_seconds` | 300 | 1 through 86400 |
| `min_refresh_seconds` | 30 | At least 30 |
| `max_refresh_seconds` | 86400 | At least minimum, at most maximum validity |

There must be 1–16 distinct public keys. The trust file must be a regular file,
owned by the effective user and not writable by group/others; the command rejects
a symlink at its final component. Ancestor directories must be administrator
controlled. The trust input is never loaded from an issuer response. Key rotation
is not implemented: removing a key needed to verify the cache makes it unusable
and prevents normal replacement. Keep required old keys during planned migration.

A complete **test-only** example is
[`trust.json`](../internal/bootpolicy/testdata/trust.json). Its private seed is public
in the fixture tests. Never deploy that key or trust file on a real host.

## Wire contract: `sahinit-boot-policy/1`

The complete, required payload shape is illustrated by
[`payload.json`](../internal/bootpolicy/testdata/payload.json), with Go types in
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

## Time states and renewal ordering

Normal validity is `[not_before, expires_at)`; grace is
`[expires_at, offline_until)`; expiry begins exactly at `offline_until`. Missing,
not-yet-valid, and clock-uncertain states are distinct. Zero grace is supported.
`Verify` does not use a clock, allowing expired cache to retain its anti-rollback
sequence. `CheckFresh` requires normal validity; `State` is observational only.

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
The second verifies the exact Go signature in Node, reproduces it with the public
test seed, and checks signature-domain separation. It is not a production issuer.
Tests cover schema/identity rejection, validity boundaries, grace ceilings,
injected suspend/rollback, renewal ordering, concurrent writers, unsafe cache
files, corruption, expired-cache reload, and process interruption at commit stages.

The design for subsequent issuance, sash sessions, catalog activation, and VM boot
remains in [renewable boot policy](design/renewable-boot-policy.md).
