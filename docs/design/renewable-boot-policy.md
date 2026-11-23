# Renewable SystemAPI boot policy

Status: design, 2026-11-22. Local metadata verification, caching, time states,
and an optional host-side refresh worker are implemented; see
[implementation scope](../boot-policy.md). Issuance, artifact verification,
runtime admission, and sash boot execution are not wired.
Scope: sahinit boot authorization, sash boot jobs, and SystemAPI renewal.

## Decision

SystemAPI issues a signed, host-specific authorization to boot an exact catalog
of resources and scripts. A supervised job refreshes that authorization well
before it expires. A cached policy supports offline boot for a bounded interval.
Policy expiry does not kill running applications or cause a reboot.

This is boot admission and lifecycle authorization, not a continuously renewed
license to keep the machine powered on. Continuous runtime enforcement, if later
required for particular workloads, needs a separate explicit contract.

Proposed fleet defaults (configurable within a locally provisioned ceiling):

| Setting | Default | Meaning |
| --- | --- | --- |
| Normal validity | 7 days | Admission of the approved boot catalog |
| Refresh interval | 6 hours | Fetch a fresh signed authorization |
| Refresh jitter | +/- 20 percent | Spread fleet traffic |
| Signed offline grace | 48 hours | Limited cached operation after normal expiry |
| Warning threshold | 24 hours remaining | Alert before normal expiry |
| Retry | 30 seconds, exponential to 5 minutes, jittered | Retry failed refreshes |
| Fetch deadline | 30 seconds | One refresh attempt cannot hang the boot graph |

Grace is part of the signed authorization, not an extension invented by the host.
These defaults allow up to nine days of specified offline authorization from
issuance; they are not a seven-day hard revocation guarantee. A strict profile
sets the grace deadline equal to normal expiry.

## Three distinct authorities

1. **Local recovery profile:** installed with the host image under administrator
   control. Contains trust roots, host binding, acceptance ceilings, essential
   mounts, console recovery, and the minimal networking and refresh path. It can
   run without a fleet policy. Fleet policy cannot remove this recovery path.
2. **Renewable boot policy:** names the approved boot catalog and precise local
   job/resource permissions. SystemAPI signs; the host verifies and caches.
3. **Interactive/remote authority:** existing short-lived SystemAPI leases,
   sash session grants, and secsvc grants. A boot policy grants no terminal,
   arbitrary command, package-management, or secsvc API access.

Use a dedicated boot-policy signing key and signature domain. Do not reuse the
SystemAPI lease key, sash fleet/emergency keys, or secsvc grant key. No fleet
private signing key is installed on the host. The refresh credential may request
only this host's assigned policy; it cannot edit policy or choose permissions.

## Responsibilities and boot order

- **sahinit:** loads the recovery profile; verifies cached policy and artifacts;
  admits units/jobs; owns process lifecycle and deadline enforcement.
- **Local boot executor:** validates typed sash requests against the exact job's
  policy. Performs mount, device, module, network, and service operations. It is
  local and independent of the SystemAPI agent and secsvc.
- **sash:** executes the existing language as a supervised process. A proposed
  boot-specific session verifies boot authority and exposes only approved verbs.
- **Refresh job:** fetches signed policy through the outbound management path and
  submits it to a narrow local install interface. It cannot write trust state or
  activate arbitrary catalogs directly.
- **SystemAPI:** resolves host assignment, authorizes issuance, signs renewals,
  records delivery/acceptance, and reports missing refreshes.
- **secsvc:** may consume boot-policy status and audit events through a separately
  specified adapter. Its absence must not block boot-policy verification.

The local recovery profile brings up essential filesystems, enough devices and
networking for refresh, and the refresh client/agent. Normal boot can proceed
from a valid cache without waiting for a network request. With no acceptable
cache, the host stays in recovery while attempting renewal.

A minimal refresh transport must not depend on applications admitted by the
policy it is trying to obtain. Initial deployment can use the existing outbound
agent if all its bootstrap dependencies are in the recovery profile. Do not add
a second general-purpose remote execution service.

## Proposed signed document

The initial metadata wire schema and Go/Node signature fixture are now defined
in [the implementation contract](../boot-policy.md). The broader lifecycle design
below remains a target. Logical payload fields:

| Field | Contract |
| --- | --- |
| `version` | `sahinit-boot-policy/1` |
| `tenant_id`, `host_id`, `enrollment_id` | Immutable enrollment binding, not hostname |
| `policy_id` | Stable identity of the assigned policy |
| `sequence` | Strictly increasing per enrollment, including across policy reassignment |
| `catalog_generation` | Approved configuration generation; distinct from renewal sequence |
| `issued_at`, `not_before`, `expires_at`, `offline_until` | Integer UTC seconds |
| `refresh_after_seconds` | Suggested interval, bounded by local acceptance policy |
| `catalog_sha256` | Digest of the exact resource/job manifest |
| `units` | Unit IDs and required-unit dependencies for subset validation |
| `jobs` | Job IDs, script digests, resource scopes, allowed phases, deadlines and dependencies |
| `offline_units`, `offline_jobs` | Exact subsets permitted during grace |
| `runtime_restart_units` | Exact subset allowed automatic restart after full expiry |
| `recovery_profile_id` | Required locally installed baseline profile |

The manifest binds unit definitions, script bytes and imported sash modules,
execution identity/environment, resource configuration, and executable artifacts
or an explicitly identified immutable image. A pathname alone is not artifact
identity. Runtime data paths are separate and remain mutable within their scopes.
No executable glob, unrestricted filesystem root, or wildcard entitlement.

Envelope proposal: `{key_id, payload, signature}` with payload and signature as
standard base64. Ed25519 signs `sahinit-boot-policy-v1\n` followed by the decoded
payload bytes. The payload is UTF-8 JSON with duplicate keys, unknown fields,
trailing values, and invalid integer ranges rejected. Verification uses the exact
signed bytes, avoiding cross-language JSON reserialization ambiguities. The signer
must produce deterministic payload bytes for a given sequence.

Initial limits: 256 KiB decoded payload, 384 KiB envelope, 256 units/jobs each,
64 scopes per job, and bounded strings/arrays. Artifacts are distributed separately
with their own manifest sizes and hashes; a policy response cannot be an unbounded
artifact download. Renewals of unchanged content retain the catalog generation and
hash, but increment sequence and change validity timestamps.

## Admission states

Intervals use an exclusive end: normal `[not_before, expires_at)`, grace
`[expires_at, offline_until)`. Time uncertainty is a separate state.

| State | Boot/new starts | Running services | Refresh |
| --- | --- | --- | --- |
| Valid | Approved catalog and jobs | Normal lifecycle | Periodic |
| Grace | Only signed offline subsets, plus local recovery | Keep running; restarts only for offline subset | Retry and alert |
| Expired | Recovery profile only | Keep running; automatic restart only for signed `runtime_restart_units` | Retry and alert |
| Missing/unverifiable cache | Recovery profile only | No authority inferred from invalid bytes | Retry |
| Clock uncertain | Recovery profile only | Preserve running work; no new policy-based admission | Restore trusted time, then reevaluate |

Offline subsets must be dependency-closed and cannot enlarge normal permissions.
The default `runtime_restart_units` is empty. Opting a workload into that list
explicitly grants post-expiry restart continuity for that running boot only; it
does not authorize starting it after a subsequent reboot. If a required dependency
is unavailable, report the blocked restart rather than starting it implicitly.
Shutdown and safe cleanup remain available in every state. Never force poweroff
or unmount a live application filesystem merely because authorization expired.

Bad refresh responses do not replace a valid installed policy or reset its expiry.
A newer valid policy that removes authority takes effect for subsequent admission;
it does not implicitly kill already running work. An explicit authorized lifecycle
operation is needed to stop such a workload. Offline revocation cannot be immediate.

Boot jobs have bounded execution lifetimes. A refresh cannot extend a running
job's authority implicitly. The executor rechecks authorization at each verb;
expiry denies new mutations. In-flight operations have deadlines and defined
completion/cleanup behavior; mounts and network changes are not generally atomic
or reversible. PID 1 enforces the process deadline even if the interpreter hangs.

## Renewal and crash-safe installation

Proposed flow (route/frame names are not existing APIs):

1. Refresh at startup when due, every interval thereafter, and after connectivity
   returns. A recent cached policy never blocks boot on this network request.
2. Authenticate as the enrolled host and send active sequence, catalog generation,
   and hash. SystemAPI selects its assigned policy, not caller-supplied scopes.
3. Server returns a newly signed document. A no-change HTTP response alone cannot
   renew authorization: new expiry requires a new signature and sequence.
4. Host caps input, checks envelope shape, recognized key and signature, host
   binding, schema, time, sequence, local ceilings, and manifest availability.
   Require `issued_at <= not_before < expires_at <= offline_until` and reject
   issuance implausibly in the future. Unknown schema versions are refused.
5. Reject a lower sequence. An identical document at the current sequence is an
   idempotent retry; different bytes at the same sequence are rejected. A changed
   catalog hash requires an advancing catalog generation. Renewal alone must not
   silently change scripts, units, or permissions.
6. Stage artifacts and validate the complete dependency graph before acceptance.
   Open verified scripts/modules from immutable or protected storage and execute
   those verified bytes; avoid a hash-check/path-reopen substitution race.
7. Persist document, digest, maximum accepted sequence, and active generation as
   one recoverable transaction: fsync immutable records, then atomically replace
   and fsync the state pointer. Serialize updates. Acknowledge only after durable
   commit. Crash recovery yields the complete previous or complete new state,
   never an advanced sequence with no corresponding recoverable document.
8. Refresh of the same catalog updates authorization only. A changed catalog is
   staged for next boot by default; live apply is a separate authorized transaction.
   Keep active and pending policy/generation status distinct. Pending validity
   never extends the old active catalog's authorization.
9. Report accepted, pending, and active sequences/generations to SystemAPI, with
   expiry and clock status. Server delivery is not proof of host activation.

Rollback to older configuration requires a newly signed higher-sequence policy
with a new catalog generation referencing the old artifacts. Never lower the
anti-rollback sequence to recover configuration. Reenrollment is an explicit
administrator operation and rotates the enrollment binding.

## Clock, revocation, and trust limits

Within a boot, derive a nondecreasing authorization clock from trusted UTC plus
Linux CLOCK_BOOTTIME elapsed time (including suspend); backward wall-clock steps
cannot extend validity. Recheck at admission and each privileged verb. A trusted
forward correction can shorten remaining authority. A signed future-dated policy
must not establish trusted current time by itself.

Across power loss, a saved last-seen time is only a lower bound: it cannot prove
how long the host was off. Ordinary disk state and an untrusted RTC cannot give a
hard offline expiry guarantee. If no trustworthy time source exists, report
`clock_uncertain` and boot recovery until trusted time or an explicitly authorized
local recovery action is available. Never silently reset the validity countdown
on reboot. Authenticated time bootstrap and acceptable RTC guarantees must be
specified for the target platform before claiming hard expiry.

Root compromise, rollback of the entire disk image, or replacement of sahinit can
bypass file-based enforcement. Strong enforcement against those threats requires
a verified boot chain and protected monotonic state; TPM-backed support is a later
profile, not a v1 claim. Initial scope protects against network tampering, replay
against intact local state, accidental configuration drift, and routine outages.

Provision a separate boot trust root. Rotate online signing keys through
versioned trust metadata authorized by that root, with overlap for offline hosts.
A response must never install its own untrusted verification key. Lost root keys
or corrupted trust metadata require the local recovery process. Key rotation,
revocation, and local recovery must have test vectors before rollout.

## Sash integration contract

Current sash denies privileged verbs without a session grant, has a closed verb
table, and starts no external programs. Its existing `sash/1` fleet and emergency
purposes must not be repurposed as boot grants.

Add a boot-specific launch/session path with a dedicated trust input. sahinit
passes the signed boot policy, job ID, verified script input, and a per-job local
verb socket through inherited FDs. sash verifies the policy and its own job scope;
the local executor independently checks every request against that same policy
and job identity. A script cannot choose a different job ID to gain permissions.
There is no locally minted fleet grant and no private signing key needed at boot.

The script uses existing language constructs (functions, loops, try/catch, typed
values). Mount/device/network verbs are new capabilities to be implemented and
registered in the closed table. Initialization and cleanup permissions are explicit.
Imported modules must be bound by digest. Plan/needs output must show the required
boot scopes without executing or approving them.

## Observability

Expose policy state, active/pending generation and sequence, policy digest,
normal/grace deadlines, last refresh success, next attempt, last refusal code,
clock confidence, and offline/post-expiry admission decisions. Never log host
credentials or full environment/secret-bearing manifests. Emit durable local
events for policy acceptance, grace entry, expiry, rejection, recovery use, and
activation; forward when connectivity returns. This audit path is independent of
secsvc availability. Read-only status is not proof of TPM attestation.

Suggested stable refusal codes: `policy_missing`, `policy_bad_signature`,
`policy_host_mismatch`, `policy_rollback`, `policy_sequence_conflict`,
`policy_not_yet_valid`, `policy_expired`, `policy_clock_uncertain`,
`policy_artifact_mismatch`, `policy_scope_denied`, `policy_store_failed`.

## Implementation slices and acceptance tests

1. Local verifier/cache/state machine with injected clock and fixtures. No remote
   issuer or PID 1 dependency. Golden vectors shared with SystemAPI's signer.
2. SystemAPI issuance and a supervised refresh client; narrow local install API;
   durable install acknowledgement and observable active/pending state.
3. Sash boot sessions and local typed executor, first with one mount/check job.
4. QEMU boot/recovery tests and controlled expiry/outage exercises.
5. Trust rotation and durable audit integration, then staged fleet rollout.

Required cases: valid offline reboot; grace subset enforcement; expiry with running
workloads preserved; expired reboot to recovery; dependency-closed offline graphs;
wrong host/enrollment/key/domain; tampered/oversized/duplicate-field documents;
old and conflicting sequences; missing or swapped artifacts; expiry during a job;
unauthorized job/socket reuse; failed refresh preserving cache; crash at every
persistence boundary; pending catalog not renewing active authority; backward time
and suspend; uncertain RTC after power loss; legitimate configuration rollback;
key rotation while offline; recovery after refresh credentials need reenrollment.

Initial acceptance: a VM boots an approved cached sash job with the control plane
disconnected, renews without restarting services, refuses unauthorized script
changes, and enters bounded recovery after cached boot authority expires.

## References

Local contracts reviewed: `sash/README.md`, sash's closed verb/language references,
`docs/plans/2026-11-06-sash-design.md`, and `systemapi-security/README.md`.
This proposal does not change their existing grant formats.

The Update Framework provides a useful precedent for signed metadata expiry,
persistent version checks, and root-authorized key rotation. This design borrows
those principles; it does not implement or claim TUF conformance:
https://theupdateframework.github.io/specification/latest/
