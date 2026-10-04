# API reference

This reference describes the unreleased `github.com/faustbrian/go-capability/v2`
source, not the published unversioned v1 module. All seven public package imports
use `/v2`; token-wire v1 remains unchanged. The [API baseline](../api/README.md)
is generated from the actual v2 exported contract. See
[module adoption](adoption.md#module-and-import-paths-v2-source).

## Core lifecycle

1. `CanonicalPayload` validates and encodes one `Payload`.
2. `Issue` signs that encoding with a `Signer`.
3. `Parse` checks framing and canonical bytes without returning authority.
4. `Verify` requires trusted `VerifyOptions.Issuer`, matches the signed issuer
   and trusted `ResolvedKey.Issuer`, then authenticates the token, time interval,
   key lifecycle, and optional `RevocationChecker`, returning an immutable `Grant`.
5. `Grant.Authorize` compares the explicit attempted `Use.Issuer`, audience,
   subject/bearer mode, resource, operation, tenant, and caveats.
6. `Grant.Consume` records bounded use through an atomic `ConsumptionStore`.

`Limits` is required on every parser and issuer. `DefaultLimits` is the reviewed
v1 profile; applications may choose tighter positive bounds.

## Signing and keys

`Signer` and `Verifier` expose only algorithm identity and canonical-byte
operations. Constructors bind HMAC-SHA-256 or Ed25519 to the correct standard
library key type. `KeySet` is an immutable local resolver for rotation overlap.
`BoundedResolver` constrains a remote `Resolver` by deadline, key-ID length, and
algorithm allowlist without creating goroutines.

Issuer strings are exact, bounded, nonempty namespaces; there is no wildcard,
claim-derived selection, or legacy default. `Key.Issuer` and
`ResolvedKey.Issuer` are trusted key ownership, not copies of a token claim.
Key IDs remain globally unique within a resolver, even across issuers.
Missing selection or invalid key ownership fails with `ErrInvalidConfiguration`;
issuer mismatch fails with `ErrUnauthorized`, without returning a grant.
Resolver dependency errors retain their existing sanitized classification.

## Signed URLs

`URLProfile.Validate` checks immutable profile policy. `SignURL` owns and fills
the payload resource and operation, then returns a canonical URL containing one
signature parameter. `VerifyURL` verifies the embedded token and independently
compares method, canonical URL, profile, and optional SHA-256 body digest.

## Replay and revocation

`ConsumptionStore` is the replaceable atomic-use contract. The
`adapters/memory`, `postgres`, and `valkey` packages implement it for
process-local, PostgreSQL, and Valkey ownership respectively.
Every store keys by the exact `(Consumption.Issuer, Consumption.CapabilityID)`
identity; issuer is required, different issuers do not share allowance, and the
same live tuple's expiry and maximum cannot be changed. Custom adapters must
implement this next-major contract rather than silently ignoring the new field.
PostgreSQL requires explicit schema-v2 `MigrateLegacyConsumption` in a
caller-owned transaction; construction does not migrate. Valkey requires
`Options.LegacyIssuer`, including on an empty ledger, and preserves that
owner's ID-only keys. Both require old-writer fencing and proven legacy
ownership or old-grant retirement. See [migration](adoption.md#issuer-scoped-replay-next-major).
`RevocationChecker` is the read boundary; `adapters/memory` supplies exact
process-local revocation sets. PostgreSQL and Valkey remain domain-owned paths
because they own the capability replay model and atomic consumption behavior.

Both memory paths expose `StoreLimits`, `DefaultStoreLimits`,
`NewConsumptionStoreWithLimits(clock, limits)` and
`NewRevocationsWithLimits(limits)`. Positive limits bound record count and
retained key-string bytes; the five revocation maps share one allowance.
The simple constructors keep their signatures with finite defaults of 10,000
records and 4 MiB per store. Capacity refusal never evicts an admitted entry.
Administrative revocation callers must handle insertion errors explicitly.
Input strings, including aggregate revocation-query fields, are bounded before
map hashing. See [admission and cleanup ownership](replay-and-revocation.md#finite-process-local-admission).

## HTTP

`adapters/http.Verifier` requires static trusted `VerifierOptions.Issuer`,
forwards it to core verification, uses a static trusted external origin, and
can carry the resulting grant through standard `net/http`
middleware. `adapters/http.SignRequest` is the HTTP-client adapter. Router,
authentication, authorization, tenancy, correlation, audit, and secret-store
integrations compose through `http.Handler`, request context,
`Grant.Authorize`, explicit issuer/tenant/correlation payload fields, safe
error categories, `Clock`, and the `Signer`/`Resolver` boundaries. The package
intentionally does not import or hide those application decisions behind
framework-specific middleware.

The released `caphttp` and `memory` packages are deprecated compatibility
facades. Their exported types retain their original, distinct named-type and
reflection identities while their operations delegate toward the canonical
successors with shared context keys, ownership, concurrency and serialization.
Both HTTP paths require explicit issuer configuration in the next-major source;
this intentionally changes their former omitted-issuer behavior. The successor package identifiers are
`capabilityhttp` and `capabilitymemory`.

All returned payload maps and slices are defensive copies. Caller-owned
contexts, database handles, HTTP bodies, clocks, and remote clients remain
caller-owned. No API starts background work.

Package-sanitized operational failures return the documented `Err*` category.
Those redacted paths discard arbitrary provider and adapter causes; only the
safe `context.Canceled` and `context.DeadlineExceeded` classifications are
retained. Trusted resolver policy failures are normalized to `ErrUnknownKey`
or `ErrAlgorithmMismatch`.

`Grant.Consume` also sanitizes store errors matching `ErrReplayExhausted`,
`ErrReplayConflict`, or `ErrCapacity`. Use `errors.Is` for policy and safe context
classifications; arbitrary store diagnostics and causes are discarded.
Bare replay-policy sentinels retain their identity, but wrapped store errors
are no longer returned unchanged. If a store error matches several supported
policy sentinels, all matching safe classifications are preserved. `ErrCapacity`
is trusted known-no-consume policy, not an unknown commit outcome. As on other
redacted paths,
`context.Canceled` takes precedence when both context classifications match.

This is not a blanket guarantee for every adapter error: direct store calls
can still return raw client errors. Keep provider diagnostics in a separately
redacted operational channel, never in capability-facing responses. See the
[repository security model](security-review.md) for source scope and remaining
boundaries.
