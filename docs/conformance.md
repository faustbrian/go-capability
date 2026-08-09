# Conformance

The package conforms to its local capability v1 and signed-URL profiles, not to
JWT, PASETO, Macaroons, OAuth access tokens, HTTP Message Signatures, or a
provider signed-URL protocol.

The [decision register](specification-decisions.md) maps every material
standards interpretation and package policy to executable evidence. The
[source manifest](../specification/manifest.tsv) pins the exact standards,
digests, and roles used by those decisions.

`make conformance` validates the manifest shape, stable decision inventory,
RFC 4231 HMAC-SHA-256 and RFC 8032 Ed25519 vectors, deterministic token and URL
behavior, and the independent Python HMAC token. `make interoperability`
reproduces the HMAC token without importing the Go package.

Conformance does not prove application authorization, durable replay ownership,
revocation propagation, proxy configuration, or side-effect ordering. Those
remain deployment contracts documented by the decision register and threat
model.
