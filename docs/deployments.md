# Verified local deployments

A deployment is a verified local bundle plus a signed boot policy, kept as
immutable generations with `active`, `pending` and `previous` pointers. This is
the host-side consumer only: enrollment, signing keys, a policy issuer and
artifact transport are not part of sahinit. No example production key or
implicit network trust is created. Renewing a cached policy alone never
activates a bundle.

**Deployments carry exec units only.** A sash unit in a bundle is refused
(`deployment_sash`); boot jobs are not supported: a policy with `jobs` or
`offline_jobs`, or a manifest with non-empty `jobs` or `resources`, is
refused (`deployment_jobs`). Put setup steps in oneshot units. Sash units are
deployed through `--dir` catalogs.

## Bundle format

The signed policy's `catalog_sha256` is the SHA-256 of the **exact bytes** of
`manifest.json` (no re-canonicalisation). Every field is required, including
the empty arrays; unknown, duplicate or null fields are refused.

```json
{
  "version": "sahinit-catalog/1",
  "units": [{"path": "units/web.json", "sha256": "64 lowercase hex digits"}],
  "artifacts": [{"path": "artifacts/web", "sha256": "64 lowercase hex digits"}],
  "jobs": [],
  "resources": []
}
```

Unit files are `units/NAME.json`, in the normal [unit schema](reference/units.md)
except that `exec[0]` is `@/artifacts/NAME`, naming a manifest artifact; the
verifier replaces it with the path inside the generation. The unit set and
each unit's `needs` must equal the policy's `units`. The normal schema and
graph checks still apply.

Limits: an artifact at most 64 MiB, a unit file 64 KiB, a bundle 256 MiB.
Paths stay inside the bundle; symlinked files, unsafe owners and writable
files or directories are refused. Generation directories are private (0700);
files are copied, synced and renamed before the pending pointer moves.

What is bound: the declared files. Not bound: the kernel, shared libraries,
an interpreter's dependencies, or files named in arguments. Provision the rest
of the root image as trusted content. Root on the host can still change
anything.

## Stage, bootstrap, activate

```sh
sahinit deploy stage --root /var/lib/sahinit/deploy --trust /etc/sahinit/trust.json \
  --bundle /root/candidate --manifest /root/candidate/manifest.json \
  --document /root/candidate/policy.json --trust-system-clock
sahinit deploy status --root /var/lib/sahinit/deploy --trust /etc/sahinit/trust.json
sahinit deploy bootstrap --root /var/lib/sahinit/deploy \
  --trust /etc/sahinit/trust.json --trust-system-clock
```

`bootstrap` is only for the first installation, when there is no active
generation. Run the supervisor (or PID 1) on it:

```text
sahinit supervise --deployment-root /var/lib/sahinit/deploy \
  --trust /etc/sahinit/trust.json --trust-system-clock --socket /run/sahinit/control.sock
sahinit init --deployment-root /var/lib/sahinit/deploy --trust /etc/sahinit/trust.json \
  --trust-system-clock
```

`--trust-system-clock` accepts the system clock as the time anchor for
expiring (`renew`) policies; without it their admission fails closed
(`policy_clock_uncertain`). `never` policies work without a clock, still
subject to sequence checks and the revocation floor.

For later changes, stage first, then as root:

```sh
sahinit ctl --socket /run/sahinit/control.sock activate
```

The supervisor takes the deployment lock, re-verifies the pending generation,
checks it is fresh, admits every unit, applies it as a live catalog change
(affected units are restarted, others keep running) and then atomically moves
the active pointer, keeping the old one as `previous`. If the pointer cannot
be written the old catalog is restored (`activation_commit`). If the rename
succeeded but the directory sync failed, it reports `deployment_durability`
and keeps the candidate running, matching the pointer; check the storage.
`activate` is refused before the boot waves end (`boot_in_progress`).

## Admission

Every start (boot, `ctl start`, an automatic restart, a dependency resume) is
admitted against the **active** generation's policy and the revocation floor
in `ROOT/policy`; a pending renewal never extends the active lease.

| Policy state | Admitted |
| --- | --- |
| valid | every unit in the policy |
| grace | `offline_units` only |
| expired | automatic restarts of `runtime_restart_units` only; manual starts are denied |
| below the floor | nothing (`policy_revoked`) |
| not yet valid, clock uncertain | nothing |

A refused start marks the unit `failed` with the policy token and an
`admission_denied` event; a strict boot then enters recovery for an
essential unit. Running services are not killed when a lease expires.

Every launch also hashes the executable it is about to run, through the
descriptor it executes, against the manifest digest (`artifact_digest`).

To revoke, install a signed floor into the deployment's policy store:
`sahinit policy floor-install --trust T --document floor.json --cache ROOT/policy`.
Restoring earlier content requires a newly signed, higher-sequence
generation; `ctl rollback` and `ctl apply` are refused in this mode. There is
no artifact downloader and no pruning: keep old generations for diagnosis,
manage the disk, and never delete the active or pending one.
