# Goal: Signed Capabilities And URLs

## Objective

Build `capability` as a focused Go library for issuing and verifying scoped,
tamper-evident, expiring capabilities, including signed URLs. A capability MUST
grant only explicitly encoded authority over named resources and operations.

The package MUST be suitable for downloads, uploads, invitations, callbacks,
one-time actions, delegated access, and service-to-service handoffs. It MUST NOT
become a general authentication, authorization, JWT, session, or cryptography
framework.

## Capability Contract

Define a versioned canonical payload containing at least issuer, audience,
subject or bearer mode, resource, allowed operation, issued-at, not-before,
expiration, nonce or capability ID, tenant/correlation metadata where allowed,
and bounded application caveats.

Specify exact semantics for absent fields, path and query encoding, Unicode,
ports, schemes, hosts, fragments, duplicate query parameters, methods, content
digests, clock skew, and canonical byte representation. Parsing and validation
MUST be separate from authorization to use the represented resource.

## Signing And Keys

- Support explicit signer/verifier interfaces using standard-library crypto.
- Ship a deliberately small reviewed algorithm set with algorithm/key-type
  binding and downgrade rejection.
- Support key IDs, rotation overlap, disabled keys, revocation, and remote key
  resolution through bounded adapters.
- Verification MUST never trust an algorithm selected solely by untrusted
  input.
- Constant-time comparison MUST be used where applicable.
- Key material MUST never appear in URLs, errors, logs, traces, fixtures, or
  metrics.

## Signed URLs

Provide deterministic signing and verification for absolute and explicitly
allowed relative URLs. Profiles MUST define covered method, authority, path,
query fields, expiration, optional body digest, and proxy/external-origin
handling. Verification MUST reject canonicalization ambiguity, parameter
smuggling, signature parameter duplication, authority substitution, path
traversal, and insecure downgrade according to policy.

## Replay And Revocation

Support reusable, bounded-use, and one-time capabilities. Replay state MUST be
an explicit replaceable contract with atomic consume semantics and in-memory,
PostgreSQL, and Valkey adapters where justified. Unknown consumption outcomes,
storage outage, expiry cleanup, and retry behavior MUST be documented.

Revocation MUST support capability ID, key, subject, resource, and issued-before
boundaries without promising instant global consistency unless the configured
store provides it.

## Integration

Provide optional `net/http`, router, middleware, HTTP-client, authentication,
authorization, tenancy, audit, correlation, clock, and secret-store adapters.
HTTP Message Signatures belong to `http-signature`; capability integrations MAY
use them but MUST not duplicate RFC 9421.

## Verification

Use official cryptographic vectors where applicable and independent
implementations for interoperability. Test canonicalization, rotation,
revocation, replay races, one-time atomicity, clocks, proxy origins, malformed
URLs, duplicate fields, tampering, cancellation, outages, and resource limits.
Fuzz every parser and canonicalizer. Exact 100% statement coverage and 100%
viable mutation kills are REQUIRED.

## Documentation And Delivery

Document threat model, bearer-token risk, profile design, signed URL examples,
one-time actions, proxy deployment, key rotation, revocation consistency,
failure modes, migration, FAQ, and complete APIs. Add manifests, CI, benchmarks,
changelog, and clean-consumer proof.

## Non-Goals

- user authentication or general authorization policy;
- arbitrary JWT/PASETO replacement;
- DRM, confidential payload encryption, or legal non-repudiation;
- hiding application decisions behind framework middleware.
