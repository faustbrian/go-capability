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
the attempted audience, subject, resource, operation, tenant, and caveats.

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
