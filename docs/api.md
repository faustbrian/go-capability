# API reference

## Core lifecycle

1. `CanonicalPayload` validates and encodes one `Payload`.
2. `Issue` signs that encoding with a `Signer`.
3. `Parse` checks framing and canonical bytes without returning authority.
4. `Verify` authenticates the token, time interval, key lifecycle, and optional
   `RevocationChecker`, returning an immutable `Grant`.
5. `Grant.Authorize` compares the attempted `Use` with every encoded authority
   dimension.
6. `Grant.Consume` records bounded use through an atomic `ConsumptionStore`.

`Limits` is required on every parser and issuer. `DefaultLimits` is the reviewed
v1 profile; applications may choose tighter positive bounds.

## Signing and keys

`Signer` and `Verifier` expose only algorithm identity and canonical-byte
operations. Constructors bind HMAC-SHA-256 or Ed25519 to the correct standard
library key type. `KeySet` is an immutable local resolver for rotation overlap.
`BoundedResolver` constrains a remote `Resolver` by deadline, key-ID length, and
algorithm allowlist without creating goroutines.

## Signed URLs

`URLProfile.Validate` checks immutable profile policy. `SignURL` owns and fills
the payload resource and operation, then returns a canonical URL containing one
signature parameter. `VerifyURL` verifies the embedded token and independently
compares method, canonical URL, profile, and optional SHA-256 body digest.

## Replay and revocation

`ConsumptionStore` is the replaceable atomic-use contract. The `memory`,
`postgres`, and `valkey` packages implement it for process-local, PostgreSQL,
and Valkey ownership respectively. `RevocationChecker` is the read boundary;
the memory package supplies exact process-local revocation sets.

## HTTP

`caphttp.Verifier` verifies a request using a static trusted external origin and
can carry the resulting grant through standard `net/http` middleware.
`caphttp.SignRequest` is the HTTP-client adapter. Router, authentication,
authorization, tenancy, correlation, audit, and secret-store integrations
compose through `http.Handler`, request context, `Grant.Authorize`, explicit
issuer/tenant/correlation payload fields, safe error categories, `Clock`, and
the `Signer`/`Resolver` boundaries. The package intentionally does not import
or hide those application decisions behind framework-specific middleware.

All returned payload maps and slices are defensive copies. Caller-owned
contexts, database handles, HTTP bodies, clocks, and remote clients remain
caller-owned. No API starts background work.

Operational failures return the documented `Err*` category. Arbitrary
provider and adapter causes are discarded rather than retained in the error
graph; only `context.Canceled` and `context.DeadlineExceeded` remain available
through `errors.Is`. Keep detailed provider diagnostics in a separately
redacted operational channel, never in capability-facing errors.
