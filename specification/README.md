# Capability specification sources

`manifest.tsv` pins every external standard used to define or constrain the
v1 capability and signed-URL profiles. A row records the exact source version,
role, retrieval status, SHA-256 digest, byte count, and authoritative URL.

The sources have distinct authority:

- RFC 2104 defines HMAC and RFC 4231 supplies HMAC-SHA-256 vectors;
- RFC 8032 defines Ed25519 and supplies its vectors;
- RFC 4648 defines base64url encoding;
- RFC 8259 defines JSON syntax but not the package's canonical member order;
- RFC 3986 defines URI syntax and reference components but not signed-URL
  canonicalization policy;
- RFC 9110 defines HTTP methods and message semantics but not capability,
  replay, revocation, proxy-trust, or signature profiles.

The package-owned choices that complete those standards are recorded in
[`docs/specification-decisions.md`](../docs/specification-decisions.md). Run
`make conformance` to validate this manifest, official cryptographic vectors,
the independent Python token, and the selected protocol evidence.

## Decision conformance matrix

| Decision | Authority | Executable evidence | Peer or fixture evidence |
| --- | --- | --- | --- |
| CAPABILITY-DEC-001 | RFC 4648 | `TestIssueAndParseRejectEveryFramingBoundary`, `TestCanonicalPayloadHasOneStableRepresentation`, `FuzzParseTokenIsBounded` | `testdata/v1-hmac.token`, Python 3 standard library |
| CAPABILITY-DEC-002 | RFC 2104 | `TestHMACSHA256RFC4231Vector`, `TestEd25519RFC8032Vector`, algorithm-binding tests | RFC vectors, Python 3 standard library |
| CAPABILITY-DEC-003 | RFC 8259 | canonical parser tests, `FuzzParseNeverAcceptsTwoPayloadRepresentations` | `testdata/v1-hmac.token`, Python 3 standard library |
| CAPABILITY-DEC-004 | RFC 9110 adjacent time syntax | time-boundary tests | Not practical: local authorization interval policy |
| CAPABILITY-DEC-005 | RFC 9110 authorization distinction | grant authorization tests | Not practical: local authority model |
| CAPABILITY-DEC-006 | RFC 3986 | signed-URL canonicalization tests and fuzz target | Not assessed: no compatible external signing profile |
| CAPABILITY-DEC-007 | RFC 9110 | HTTP origin, method, and digest tests | Not assessed: local transport profile |
| CAPABILITY-DEC-008 | RFC 9110 adjacent idempotency semantics | memory and PostgreSQL atomic-use tests | Not assessed: local replay state machine |
| CAPABILITY-DEC-009 | RFC 9110 adjacent authorization semantics | revocation boundary tests | Not assessed: local revocation policy |
| CAPABILITY-DEC-010 | RFC 2104 key guidance | key lifecycle and resolver tests | Not assessed: local resolver lifecycle |
| CAPABILITY-DEC-011 | RFC 9110 status semantics | HTTP middleware boundary tests | Not assessed: local adapter response policy |

The machine-readable bindings live in `decisions.json`, `conformance.json`,
`monitoring.json`, and the append-only `decision-history.json`. Peer agreement
is evidence, not authority; unassessed lanes remain explicit.
