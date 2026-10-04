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

### Explicit issuer policy (next major)

Current main intentionally rejects the formerly valid omitted-issuer verification
and authorization behavior. This requires a new major release and consumer
adoption; it is not a compatible patch or a claim that such a release exists.
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

This stage does not change `Consumption` or any replay-store schema or key.
Issuer-scoped replay identity and safe migration of live counters remain open;
continue isolating stores or ensuring globally unique capability IDs. A future
store migration must address old/new verifier coexistence and existing quotas,
not silently reset use allowances.

### Adapter package paths

New code should import `github.com/faustbrian/go-capability/adapters/http` and
`github.com/faustbrian/go-capability/adapters/memory`. Existing imports of
`github.com/faustbrian/go-capability/caphttp` and
`github.com/faustbrian/go-capability/memory` remain source- and
behavior-compatible facades within the published v1 interval. The next-major
issuer requirement applies equally to both HTTP paths. Migration updates the import paths and default
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
