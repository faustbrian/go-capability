# Security review

## Reviewed boundaries

- Canonical payload and protected-header parsing reject alternate bytes,
  unknown or duplicate JSON fields, invalid UTF-8, controls, and excess input.
- Algorithm selection is limited to HMAC-SHA-256 and Ed25519 and is checked
  against the trusted verifier returned for the key ID.
- URL policy covers method, scheme, canonical authority and port, path, complete
  allowlisted query, expiry, profile name, and optional body digest.
- Replay adapters own atomic compare-and-increment; non-policy failures are
  surfaced as unknown outcomes.
- Revocation errors fail closed and consistency remains a store property.
- Operational errors expose stable categories and retain only the safe
  `context.Canceled` or `context.DeadlineExceeded` classification. Arbitrary
  signer, verifier, resolver, store, and body-digest causes are not retained in
  the returned error graph because their diagnostics may contain secrets.
- Trusted resolver policy failures preserve the stable `ErrUnknownKey` and
  `ErrAlgorithmMismatch` categories through bounded resolver layers without
  retaining a resolver's arbitrary diagnostic error.

The reviewed surface consists of payload version 1, signed-URL profiles, the
method/scheme/authority/path/query/body-digest covered components,
HMAC-SHA-256 and Ed25519, `KeySet` and `BoundedResolver`, the memory,
PostgreSQL, and Valkey consumption stores, memory revocation, `caphttp`, and
the stable exported error categories. There is no implicit default signer,
resolver, origin, clock, replay store, revocation store, or authorization
policy.

## Deployment risks

Bearer theft, confused-deputy use with an overly broad audience, key compromise,
clock manipulation, proxy-origin mistakes, and logging remain primary risks.
Mitigations are narrow resources and operations, subject binding where
available, short lifetimes, static origins, bounded skew, explicit rotation and
revocation procedures, atomic consumption, TLS, and end-to-end redaction.

PostgreSQL transaction loss and Valkey client timeout can occur after a consume
commit. Applications must treat those results as unknown, avoid blind retries,
and reconcile through an idempotency or transactional boundary. Valkey failover
durability and revocation propagation must be stated by the deployment; the
library makes no instant-global or exactly-once claim.

The live adapter suite installs the PostgreSQL migration and proves consumed
records survive both database-client replacement and abrupt caller-process
exit. It proves the same boundaries for Valkey. Deterministic fault adapters
exercise begin, read, insert, update, cleanup, commit, cancellation, malformed
reply, retry-race, and connection-loss outcomes. These are caller-process and
client failover-boundary exercises, not a claim that an operator's PostgreSQL
replication or Valkey persistence policy preserves acknowledged writes. Replica
promotion and data-loss windows remain deployment-owned and require exercises
against the exact production topology before adoption.

`BoundedResolver` performs no caching and consults its source on every lookup,
so key removal or compromise state is visible as soon as the source returns it.
If the source caches keys, that cache owns its finite stale-acceptance bound and
must not extend an old key beyond its activation interval or the deployment's
documented compromise-response objective.

`caphttp` is tested in an explicit authentication, body-limit, capability,
authorization, tenancy, correlation, audit, and application sequence. It uses
a configured external origin and ignores forwarding headers. Redirect targets
have a different canonical resource and therefore require a newly issued URL.
HTTP retries are transport-owned; reusable capabilities may be verified again,
while bounded capabilities must be consumed once at the application side-effect
boundary and unknown consumption outcomes must not be retried blindly.

## Evidence scope

The suite includes official RFC 4231 and RFC 8032 primitive vectors, canonical
golden values, hostile URL and token cases, rotation and outage cases, replay
races, cancellation, redaction, fuzz targets, race execution, coverage, and
mutation gates. Parser fuzzing covers the protected header and token framing,
canonical payload decoder/encoder, and signed-URL parser/canonicalizer. Replay
contention tests and the 10,000-execution fuzz campaigns provide bounded stress
and soak input; the implementation owns no goroutine, file, response body,
timer, ticker, rows, or connection lifetime, so leak review is performed at
each caller-owned adapter boundary. Public RFC vector bytes and generated
test-only values are not operational key material.
