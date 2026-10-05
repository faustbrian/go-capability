# Adoption, migration, and FAQ

## Adoption checklist

1. Name one issuer namespace and explicit audiences.
2. Inventory resource names and operations; do not encode general roles.
3. Choose bearer or subject binding for each profile.
4. Set the shortest practical lifetime and an explicit skew budget.
5. Generate collision-resistant public capability IDs.
6. Select HMAC only when every verifier may hold the shared secret; use Ed25519
   when verifiers should receive public keys only.
7. Version URL profiles and allowlist every scheme, authority, and query name.
8. Use durable atomic consumption for one-time or bounded-use actions.
9. Define revocation consistency, outage, audit, and reconciliation behavior.
10. Remove tokens from application logs, traces, metrics, analytics, referrers,
    exception reports, and fixtures.

## Migration

### Module and import paths (v2 source)

Version 2 declares `github.com/faustbrian/go-capability/v2` at the repository
root, targeting Go 1.27. There are no version-specific source directories or
branches. Stable v2 releases use root `v2.x.y` Git tags. Declaring the module
path alone does not establish public module resolution.

Change the integrating module's required major version and all seven package
imports together:

| Package | v2 source import |
| --- | --- |
| Core | `github.com/faustbrian/go-capability/v2` |
| HTTP | `github.com/faustbrian/go-capability/v2/adapters/http` |
| Memory | `github.com/faustbrian/go-capability/v2/adapters/memory` |
| Retained HTTP facade | `github.com/faustbrian/go-capability/v2/caphttp` |
| Retained memory facade | `github.com/faustbrian/go-capability/v2/memory` |
| PostgreSQL | `github.com/faustbrian/go-capability/v2/postgres` |
| Valkey | `github.com/faustbrian/go-capability/v2/valkey` |

Package identifiers remain unchanged. V1 and v2 exported types are distinct;
mixing imports cannot share grants, resolvers or store interfaces without an
explicit application boundary. Token payload `Version: 1`, `cap1` framing and
signed-url-v1 profiles remain wire v1; the Go module major is not a wire version.

The following issuer, replay/migration and finite-admission changes must be
adopted with the imports, not hidden behind legacy defaults. Maintained external
consumers and the historical identity-platform additive-only contract are not
migrated by this source change. Local `make clean-consumer` uses a disposable
replacement of the owned v2 source; actual release qualification requires a
fresh public consumer without replacements or workspace assistance.

### Explicit issuer policy (next major)

Version 2 intentionally rejects the formerly valid omitted-issuer verification
and authorization behavior. This major requires deliberate consumer adoption;
it is not a compatible v1 patch.
Select `VerifyOptions.Issuer` and either HTTP path's `VerifierOptions.Issuer`
from trusted application configuration, not the token or request. Configure
each `Key.Issuer` or custom resolver's `ResolvedKey.Issuer` as the key's actual
owner. Supply `Use.Issuer` from the application's intended operation namespace.
All three namespaces must match the authenticated payload exactly. Missing
fields fail closed; do not restore acceptance with a wildcard or legacy default.
Globally unique key IDs, `Resolver.Resolve`'s signature, and the v1 token wire
remain unchanged. Unkeyed exported struct literals must also be migrated.

The identity-platform's older additive-only promise for existing verification
and grant behavior is superseded for this security change, not satisfied by it.
Its pinned contracts and consumers require deliberate next-major adoption before
identity-platform or ecosystem completion can be claimed. Existing published-v1
consumers remain on their selected v1 behavior until explicitly migrated.

### Issuer-scoped replay (next major)

`Consumption.Issuer` is required. Custom stores must atomically key by the
exact `(Issuer, CapabilityID)` tuple, preserving its count, maximum and expiry.
Both memory paths implement this identity but remain process-local and lose
state on restart. A matching ID from another issuer has an independent quota;
changing a live tuple's signed maximum or expiry remains a conflict.

Before activating new durable writers, prove the existing ID-only ledger has
one legacy issuer and fence and drain **all** old writers, including restarted
or delayed workers. Old and new writers must not run concurrently against the
migrated ledger. Table locks alone do not establish this operational fence.

For PostgreSQL, retain migration `001_capability_consumptions.sql`. Apply it for
a fresh database, then run `postgres.MigrateLegacyConsumption(ctx, tx, owner)`
in a caller-owned transaction before using the new store. This is schema version
2: it exclusively locks the table, binds the explicit owner as a SQL parameter,
preserves `uses`, `max_uses` and `expires_at`, and replaces the ID-only primary
key with `(issuer, capability_id)`. The function neither commits nor rolls back.
Roll back on failure and commit before activating new writers; do not rerun it
on an already upgraded schema. Missing migration fails database operations
rather than supplying an implicit owner. Direct migration errors remain
caller-owned diagnostics. Store construction never runs a migration.

For Valkey, `Options.LegacyIssuer` is mandatory, including a fresh empty ledger.
Naming an empty ledger's initial owner is different from proving an existing
ledger's single owner. Preserve the existing `KeyPrefix` and mapped owner:
that issuer retains the **exact** old ID-only digest key and remaining quota.
Other issuers use domain-separated, length-framed tuple keys. Consumption
remains one atomic EVAL on one declared key; there is no cross-slot probe or
claim-derived owner. Changing the mapping or prefix on a live ledger can reset
quotas and is not supported.

If ownership is unknown or the old ledger mixed issuers, do not guess an owner,
reinterpret records or switch key formulas to regain allowances. Fence issuance
and every old writer, retire all old grants beyond expiry plus maximum accepted
skew and relevant clock/replication bounds, and remove retired state under the
application owner's migration plan before initializing a proven empty ledger.
Verify retained counters and activation fences independently. Rollback after
multi-issuer activation cannot simply drop the issuer column or restore old
writers; keep writers fenced and use an owner-reviewed recovery plan.

PostgreSQL rejects a request at or beyond expiry using the database transaction
clock, even if `Verify` accepts it within skew. Neither a retained expired row
nor a cleaned/absent row can supply fresh quota for that same expired grant.
A genuinely future-expiry replacement after the previous row expires retains
the established renewal behavior; IDs should still not be reused for ordinary
issuance. Memory and Valkey also make separate store-clock expiry decisions.
Align application clocks, skew and consumption windows.

These are source contracts and required deployment steps, not evidence that a
database, ledger, consumer or public major release has been migrated.

### Finite memory admission (next major)

The simple memory constructors keep their signatures but now impose finite
defaults: 10,000 records and 4 MiB of retained key-string bytes per store.
Use `StoreLimits` with `NewConsumptionStoreWithLimits` or
`NewRevocationsWithLimits` for other explicit positive budgets on either memory
path. All five revocation maps share one allowance and never evict.
Plan for `ErrCapacity`: replay refuses without consuming, while trusted
administrative writers must handle a failed insertion rather than assuming
revocation succeeded. A failed write does not permanently disable unrelated
queries. Configure query-string budgets for the full authenticated query;
oversized ordinary queries fail verification closed as `ErrRevocationUnknown`.
Own cleanup cutoffs, overload policy and revocation-store lifecycle; do not
replace a live ledger or discard revocations to regain admission. These finite
record/string budgets are not a byte-exact total heap limit. See
[admission accounting](replay-and-revocation.md#finite-process-local-admission).

### Adapter package paths

For v2 adoption, new code should import `github.com/faustbrian/go-capability/v2/adapters/http`
and `github.com/faustbrian/go-capability/v2/adapters/memory`. Existing v1 imports of
`github.com/faustbrian/go-capability/caphttp` and
`github.com/faustbrian/go-capability/memory` remain source- and
behavior-compatible facades within the published v1 interval. V2 retains
`github.com/faustbrian/go-capability/v2/caphttp` and
`github.com/faustbrian/go-capability/v2/memory` as separate facade types; this
adoption neither removes them nor restarts or shortens the promised interval.
The explicit issuer requirement applies equally to both HTTP paths. Migration updates the import paths and default
qualifiers to `capabilityhttp` and `capabilitymemory`; callers may temporarily
alias the new imports to their old qualifiers when an import-path-only change
is preferable. Do not move `postgres` or `valkey`; those packages remain
domain-owned because they implement the persisted replay model and atomic
bounded-use semantics.

The successor packages use the frozen default identifiers `capabilityhttp` and
`capabilitymemory`. Their named types are successor-owned; the legacy facades
retain their original, distinct named-type and reflection identities.

The legacy paths remain supported for at least 180 days after the successors
resolve publicly and through two subsequently published stable minor releases
that contain both paths, whichever is longer. Removal also requires all owned
consumers to migrate, clean external-consumer evidence, and a separately
authorized next-major release. No current v1 consumer must migrate immediately.

### Protocol adoption

Do not translate arbitrary JWT claims into capabilities. Define a new narrow
resource and operation vocabulary, issue both formats during a bounded overlap,
verify the capability at a separate endpoint or code path, and stop old
issuance before removing old verification. Preserve the old verifier until its
last token can no longer pass expiry plus skew.

For signed URLs, deploy a versioned profile rather than silently changing
canonicalization. Existing URLs retain their original profile name and verifier
until expiry. Scheme, authority, proxy-origin, query, and body-digest changes
are new profile versions.

## FAQ

### Are payloads confidential?

No. Header and payload are base64url encoded, not encrypted.

### Can a verified grant replace application authorization?

No. Verification authenticates encoded authority. The application must compare
the attempted issuer, audience, subject, resource, operation, tenant, and caveats.

### Can middleware consume one-time capabilities automatically?

Usually no. Consumption must be ordered with the protected side effect so an
application can handle unknown outcomes correctly.

### Why reject duplicate query parameters?

Frameworks and proxies disagree about whether the first, last, or every value
wins. Rejecting duplicates removes that parser differential.

### Does key or capability revocation propagate instantly?

Only if the configured store and all verifier reads provide that guarantee.
The in-memory adapter is process-local.

### Does this implement HTTP Message Signatures?

No. RFC 9421 belongs to the separate `http-signature` module. A deployment may
compose both protocols when their distinct threat models require it.
