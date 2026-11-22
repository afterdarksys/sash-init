# Boot-policy lifetime: decision

2026-11-22, Ryan: support both lifetime modes, configurable. The default is the first, `never`.

## Modes

| Mode | Validity | Revocation | Network |
| --- | --- | --- | --- |
| `never` (default) | A policy has no expiry. It stays valid until it is replaced by a higher sequence or revoked. | A signed **revocation floor**: a document signed by the boot-policy key, holding `min_sequence`. A cached policy below the floor is refused. The floor only ever rises. It is installed the same way as a policy (signature, atomic write, fsync), and a lower floor is refused. | None needed. A host takes a new policy or a new floor whenever one is delivered (offline media, the agent, or renewal when enabled). |
| `renew` | The existing design (`renewable-boot-policy.md`): signed validity (default 7 days), refresh every 6 hours with jitter, and 48 hours of signed grace. | Validity runs out, and the revocation floor also applies. | The renewal worker (`sahinit policy refresh`). |

The mode is part of the **signed** policy (`lifetime: "never"` or `"renew"`), so a host cannot switch modes on its own. The local trust file may cap it. For example, `max_lifetime: "renew"` refuses `never` policies on hosts that must expire.

## Consequences

- **Clock.** The trusted-clock problem (audit item 9) matters only in `renew` mode. `never` does not read the clock to decide validity.
- **Renewal worker.** The draft on `fix/renewal-slice` stays as the `renew` transport. It is finished and committed as optional, and is not on the boot path.
- **Key rotation** (audit item 10) applies to both modes. A cached policy signed by a key that has been removed from the trust file must be replaced by one signed with a current key. The procedure needs to be documented.

## Build order

1. Batch 1 hardening (`hardening-1.md`). It is independent of this decision.
2. **Done** (`feat/policy-lifetime`). The `lifetime` field, the revocation floor, the trust cap, and the `never` default, with tests both ways.
3. Finish the renewal slice behind `renew`.

## Step 2 decisions (2026-11-22)

- **Wire version.** `sahinit-boot-policy/1` is unchanged and always means `renew`; its golden vector is byte-identical. `sahinit-boot-policy/2` adds a required `lifetime`. The version selects the shape: `lifetime` is refused in version 1 and required in version 2. New policies should be version 2 with `never`.
- **`never` and time.** `expires_at`, `offline_until` and `refresh_after_seconds` must be 0, and `not_before` must equal `issued_at`. We kept `not_before` on the wire but gave it no effect: honouring a delayed start would need a trusted clock forever, and a clock set back before it would end the policy. A `never` policy is `valid` with no clock, an untrusted clock, or any clock value.
- **Mode change.** Switching lifetime needs a higher catalog generation. Version 1 to version-2 `renew` at the same generation is an ordinary renewal (the wire version is excluded from the renewal comparison).
- **Floor.** A separate document, `sahinit-boot-floor/1`, in the same envelope, signed over the domain `sahinit-boot-floor-v1\n` (policies use `sahinit-boot-policy-v1\n`). Fields: `version`, `tenant_id`, `host_id`, `enrollment_id`, `min_sequence`, `issued_at`. Sequences at or above `min_sequence` are admitted. A lower floor is `policy_floor_rollback`, the same `min_sequence` with different bytes is `policy_floor_conflict`. Stored as `floor.json` beside `policy.json` with the same atomic write. A corrupt floor fails closed.
- **Trust cap.** `max_lifetime` is optional in the trust file and defaults to `never` (both allowed). In code, `Trust.Validate` requires it to be set explicitly; only `DecodeTrust` applies the default.
- **CLI.** `sahinit policy floor-install|floor-show`. `status` reports `lifetime` and `floor_min_sequence`, and reports a revoked cache as `state: revoked`, exit 1.
- **Open.** The floor shares the anti-rollback limits of the policy cache: deleting the cache directory or restoring a snapshot removes it. Key rotation (audit item 10) is still not documented.
