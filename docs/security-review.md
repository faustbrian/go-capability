# Security review

## Model revision and source scope

Repository threat model revision **3**, dated **2026-10-04**, covers
`github.com/faustbrian/go-capability` at baseline commit
`06b8bf9dad845288f638c9cf6569624a7d598adf` plus the strict issuer correction
identified by these immutable runtime Git blobs:

| Source | Git blob |
| --- | --- |
| `token.go` | `1f842ca6a8ded73f925d859784c149c71b7be85c` |
| `resolver.go` | `ac08cc6bcb814065766398bc3d03dfd968b7296f` |
| `grant.go` | `8d81641c76576dccfb3fe9ab48ad5dbac0148a28` |
| `adapters/http/http.go` | `2e3f236fae68374b58bfb1ce6cfdb0a84184ff85` |
| `caphttp/http.go` | `1637ea2b5b4b227191d9bc35bda863de52f87fb3` |

All other runtime source is unchanged from that baseline, which includes the
revision 2 consumption policy-error correction. These are inspected immutable
source identities, not a prospective documentation commit, release, or
deployment identity. Revision 1 covered the unchanged runtime at
`4a9574a4b5903b86b43bdfb8424c8faa3db885cf` and its reporting-policy link.

The published `v1.1.1` tag identifies
`3fc043661119b72a4c5887b6bff9feab402ac910`, not this main-source baseline.
This model does not certify that release or any integrating application.
Revisit the model when runtime source, dependencies, protocol policy, adapters,
or the accepted deployment assumptions change. Model revisions are distinct
from module versions and do not require a module release by themselves.

The [protocol narrative](protocol.md#threat-model) and the residual-risk
register below form this repository model. It is a source-level assessment
with narrowly scoped ordinary-input issuer and policy-error regressions, not a vulnerability scan,
an independent cryptographic audit, a statement that broad security gates
passed, or completion of the ecosystem security goal.

## Assets, attackers, and trust boundaries

Protected assets are encoded authority, signing and verification keys,
bounded-use counters, revocation policy, subject and tenant boundaries, and
application side effects. Tokens and signed URLs are bearer credentials;
payloads can also disclose subject, tenant, resource, caveat, and correlation
metadata. Public capability IDs are not authentication secrets.

An unauthenticated requester can supply token bytes, URL components, methods,
and bodies; a token holder can replay, redistribute, or substitute those inputs.
A compromised issuer, key source, store, client implementation, application,
or maintainer crosses a trusted boundary rather than becoming trustworthy
because a token verifies.

- [Payload parsing](../payload.go), [token verification](../token.go), and
  [URL canonicalization](../url.go) separate attacker bytes from authenticated
  grants. Parsing alone supplies no authority.
- [Cryptographic implementations](../crypto.go) and
  [resolvers](../resolver.go) bind the selected algorithm, explicit key issuer
  ownership, and key lifecycle. Verification requires the application-selected
  issuer to match both the claim and trusted key ownership.
  Caller-supplied signers, verifiers, and remote resolvers remain trusted code.
- [Authorization](../grant.go) compares a verified grant with an
  application-supplied use including explicit issuer. Subject authentication,
  correct application namespace selection, resolver trust, business
  policy, and the protected side effect remain application boundaries.
- [Consumption](../replay.go) delegates atomic use counting to
  [memory](../adapters/memory/consumption.go),
  [PostgreSQL](../postgres/store.go), or [Valkey](../valkey/store.go).
  Database credentials, clients, migrations, replication, and persistence
  are operational trust boundaries. PostgreSQL queries use parameters;
  Valkey uses a constant script and a digest-derived key.
- [Revocation](../revocation.go) consults an optional checker; the
  [memory checker](../adapters/memory/revocation.go) is process-local.
- The [HTTP adapter](../adapters/http/http.go) verifies and carries a grant;
  `caphttp` and `memory` are compatibility facades over the canonical adapters.
  Ingress limits, proxy configuration, body reading, authorization, audit, and
  execution remain caller responsibilities.
- The core does not fetch URLs, resolve DNS, open files, decompress archives,
  execute commands, or own a queue or plugin loader. SSRF, filesystem traversal,
  request smuggling, decompression, and downstream parser hazards must still
  be assessed where applications turn a verified resource into an action.
  Dependencies, CI actions, and release publication are separate supply-chain
  boundaries; source inspection cannot establish their compromise status.

## Source-backed controls

- Canonical payload and protected-header parsing reject alternate bytes,
  unknown or duplicate JSON fields, invalid UTF-8, controls, and excess input.
- Algorithm selection is limited to HMAC-SHA-256 and Ed25519 and is checked
  against the trusted verifier returned for the key ID.
- URL policy covers method, scheme, canonical authority and port, path, complete
  allowlisted query, expiry, profile name, and optional body digest.
- Replay adapters own atomic compare-and-increment; non-policy failures are
  surfaced as unknown outcomes.
- Revocation errors fail closed and consistency remains a store property.
- Redacted operational error paths expose stable categories and retain only
  the safe `context.Canceled` or `context.DeadlineExceeded` classification.
  Arbitrary
  signer, verifier, resolver, store, and body-digest causes are not
  retained in those error graphs because their diagnostics may contain secrets.
  `Grant.Consume` normalizes replay-policy errors while preserving both policy
  classifications when both match and applying the existing safe context
  precedence. Bare replay-policy sentinels retain their identity. Direct store
  calls are not covered by that redaction guarantee.
- Trusted resolver policy failures preserve the stable `ErrUnknownKey` and
  `ErrAlgorithmMismatch` categories through bounded resolver layers without
  retaining a resolver's arbitrary diagnostic error.

The reviewed surface consists of payload version 1, signed-URL profiles, the
method/scheme/authority/path/query/body-digest covered components,
HMAC-SHA-256 and Ed25519, `KeySet` and `BoundedResolver`, the memory,
PostgreSQL, and Valkey consumption stores, memory revocation, the canonical
HTTP and memory adapters and their compatibility facades, and
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

The live adapter test definitions cover PostgreSQL migration installation,
database-client replacement, and abrupt caller-process exit, with corresponding
Valkey client and process cases. Deterministic fault tests cover begin, read,
insert, update, cleanup, commit, cancellation, malformed reply, retry-race,
and connection-loss outcomes. Their presence is not proof of execution at this
baseline or evidence that an operator's replication or persistence policy
preserves acknowledged writes. Replica promotion and data-loss windows remain
deployment-owned and require exercises against the exact production topology
before adoption.

`BoundedResolver` performs no caching and consults its source on every lookup,
so key removal or compromise state is visible as soon as the source returns it.
If the source caches keys, that cache owns its finite stale-acceptance bound and
must not extend an old key beyond its activation interval or the deployment's
documented compromise-response objective.

The HTTP test definitions include an explicit authentication, body-limit,
capability, authorization, tenancy, correlation, audit, and application
sequence; the adapter does not enforce that complete sequence. It uses
a configured external origin and ignores forwarding headers. Redirect targets
have a different canonical resource and therefore require a newly issued URL.
HTTP retries are transport-owned; reusable capabilities may be verified again,
while bounded capabilities must be consumed once at the application side-effect
boundary and unknown consumption outcomes must not be retried blindly.

## Accepted residual risks

These are conditional integration limitations, not accepted unresolved
vulnerabilities or authorization to deploy without the mitigation. Owners are
responsibility roles: the **integrating application owner** owns its deployment
and policy, and the **repository maintainer** owns library source and delivery.
Each owner must reassess its entry at the stated review condition.

### R1: Bearer theft and metadata disclosure

- **Owner:** integrating application owner.
- **Rationale:** signatures provide integrity, not secrecy or human identity.
- **Mitigation:** TLS, secret-safe storage, short lifetimes, narrow grants,
  independently authenticated subject binding where appropriate, and token,
  URL, referrer, log, trace, and audit redaction. Treat direct adapter errors
  and trusted callbacks' diagnostics as sensitive; direct adapter errors must
  not be exposed merely because they match a replay-policy category.
- **Review condition:** any transport, logging, analytics, payload-content, or
  capability-distribution change, or suspected token disclosure.

### R2: Confused deputy and incorrect application authority

- **Owner:** integrating application owner.
- **Rationale:** `Grant.Authorize` compares encoded fields, not business policy;
  HTTP middleware does not authorize or consume the grant.
- **Mitigation:** derive issuer, audience, subject, resource, operation, tenant, and
  caveats from trusted application state; authorize immediately before the
  protected action and keep that action's policy explicit.
- **Review condition:** a new operation, tenant, audience, authentication path,
  or middleware ordering change.

### R3: Key compromise and stale key or revocation policy

- **Owner:** integrating application owner.
- **Rationale:** key generation, resolver trust, cache freshness, and replicated
  revocation consistency are outside signature verification. HMAC verifiers
  hold signing-capable secrets; in-memory key copies have no erasure guarantee.
- **Mitigation:** restrict key access, choose Ed25519 when verifiers must not
  issue tokens, rotate explicitly, bound cache staleness, configure revocation
  where required, and exercise compromise response. `BoundedResolver` itself
  does not cache; memory revocation does not propagate to another process.
- **Review condition:** key compromise, key-source or cache changes, rotation,
  or a change to process count or revocation topology.

### R4: Clock, skew, and replay-state expiry disagreement

- **Owner:** integrating application owner.
- **Rationale:** verification uses the supplied clock and skew; stores have
  separate expiry decisions. Valkey expires records at the supplied expiry,
  not at verifier expiry plus skew.
- **Mitigation:** use trusted clocks, constrain skew, align verification and
  consumption windows, never reuse capability IDs, and do not remove live
  replay state before every relevant acceptance window has closed.
- **Review condition:** clock source, skew, lifetime, cleanup, or store expiry
  policy changes, or clock incidents.

### R5: Replay durability and unknown side-effect outcomes

- **Owner:** integrating application owner.
- **Rationale:** counting a use is not atomic with the business action; timeout
  or connection loss can follow a commit. Memory state disappears on restart;
  durable-store acknowledgement alone does not establish failover durability.
- **Mitigation:** do not use memory for cluster-wide one-time actions; configure
  and exercise durable persistence; fail closed on unknown consumption and
  reconcile using an application-owned transactional or idempotency boundary.
  The bundled PostgreSQL store owns its own transaction, not the application's
  side-effect transaction. No adapter guarantees exactly-once business execution.
- **Review condition:** retry, transaction, restart, persistence, replication,
  failover, or side-effect ordering changes, or an unknown consume outcome.

### R6: Proxy and downstream interpretation differences

- **Owner:** integrating application owner.
- **Rationale:** canonical signed bytes cannot ensure that a proxy, router,
  filesystem, remote fetcher, or other downstream consumer interprets them
  identically. Relative profiles do not bind an authority.
- **Mitigation:** use trusted static external origins, version narrow URL
  profiles, independently validate downstream destinations and paths, bound
  request bodies, and issue a new URL for a changed redirect resource.
- **Review condition:** proxy, router, origin, redirect, body-digest, profile,
  remote-fetch, or filesystem integration changes.

### R7: Caller-controlled work and retained state

- **Owner:** integrating application owner.
- **Rationale:** parser limits do not rate-limit requests or bound all lifetime
  state. Memory consumption needs cleanup; memory revocations have no removal
  API. Deadlines depend on trusted callbacks and clients honoring cancellation.
- **Mitigation:** select finite input limits, bound ingress and concurrency,
  enforce deadlines in callbacks and clients, bound issuance and administrative
  revocation rates, and plan replay cleanup and revocation-store lifecycle.
- **Review condition:** limit increases, traffic or retention changes, new
  callbacks or clients, or resource exhaustion and cancellation failures.

### R8: Supply-chain and maintainer compromise

- **Owner:** repository maintainer for source, dependencies, CI and releases;
  integrating application owner for its selected artifact and build pipeline.
- **Rationale:** token cryptography does not authenticate repository changes,
  dependencies, CI execution, or the provenance of a deployed binary.
- **Mitigation:** review and pin dependencies and actions, protect publication
  credentials, inspect release identity and applicable security-gate evidence,
  and pin the application's selected module version. Reporting and response
  remain governed by [SECURITY.md](../SECURITY.md).
- **Review condition:** dependency, action, toolchain, maintainer-access, or
  release changes, a relevant advisory, or suspected pipeline compromise.

## Unresolved security-goal boundaries

The following source limitations are not certified safe by this model and are
not accepted findings merely because integration precautions are possible:

- Explicit issuer selection, trusted key ownership, and attempted-use issuer
  comparison now fail closed in this next-major source. Correct configuration,
  key-source trust, published major adoption and direct-consumer migration still
  require validation; the former identity-platform additive-only compatibility
  promise is not satisfied by this intentional break. See [migration](adoption.md#explicit-issuer-policy-next-major).
- `Consumption` carries only capability ID, expiry, and maximum uses. The
  bundled replay stores do not bind identity to issuer. Applications must
  ensure globally unique IDs across a shared store or separate issuer-owned
  stores; issuer-scoped replay isolation is not a library guarantee.
- The memory consumption and revocation stores have no finite entry-count or
  aggregate retained-byte admission. Their direct APIs also retain caller
  strings without an explicit byte budget. Cleanup and application ingress
  controls can reduce exposure but do not establish the ecosystem goal's
  package-owned finite-memory requirement. R7 records integration precautions,
  not closure of this source limitation.
- Current-source hostile-input execution, scanner results, dependency and
  secret-scan status, release/clean-consumer verification, and production
  topology exercises are not established by this documentation assessment.

The repository maintainer owns assessment of these source limitations;
integrating application owners own validation of issuer trust and replay-store
separation before multi-issuer adoption. Reassess at any issuer, key-sharing,
store-sharing, or relevant API change. Any confirmed vulnerability needs a
separate evidence-backed disposition and affected-version determination;
this document neither invents one nor claims remediation.

## Evidence scope

The inspected test definitions include official RFC 4231 and RFC 8032 primitive
vectors, canonical golden values, hostile URL and token cases, rotation and
outage cases, replay races, cancellation, redaction, and fuzz targets.
References to race, coverage,
and mutation gates are not execution evidence or a passing result.
Parser fuzz targets cover the protected header and token framing,
canonical payload decoder/encoder, and signed-URL parser/canonicalizer. Replay
contention cases provide test inputs, not a recorded stress or soak result.
The core starts no background goroutines; PostgreSQL consumption owns
transaction completion while database and Valkey client lifetimes remain
caller-owned. Adapter and callback lifecycle behavior still needs execution
evidence. Public RFC vector bytes and generated test-only values are not
operational key material.

Revision 1 records source and test-definition inspection only. No tests,
benchmarks, fuzz campaigns, scanners, or runtime services were executed to
produce it. Revision 2 adds the policy-error correction and focused
[ordinary-input consumption tests](../consumption_policy_test.go); it does not
establish runtime-service, scanner, or broad hostile-input results. Revision 3
adds [ordinary issuer policy tests](../issuer_policy_test.go) and both owned HTTP
paths' issuer forwarding tests. It does not close replay-schema, finite-memory,
publication, ecosystem, or identity-platform adoption boundaries. Claims of
passed gates must refer to attributable results for the relevant immutable
source and environment rather than to this inventory.
