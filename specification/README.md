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
