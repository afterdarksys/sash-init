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
2. The `lifetime` field, the revocation floor, the trust cap, and the `never` default, with tests both ways.
3. Finish the renewal slice behind `renew`.
