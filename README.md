# capability

[![CI](https://github.com/faustbrian/go-capability/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/faustbrian/go-capability/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-required-blue)](https://github.com/faustbrian/go-capability/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Mutation](https://img.shields.io/badge/mutation-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Documentation](https://img.shields.io/badge/docs-checked_in_CI-blue)](docs/)
[![Go Reference](https://pkg.go.dev/badge/github.com/faustbrian/go-capability.svg)](https://pkg.go.dev/github.com/faustbrian/go-capability)
[![Release](https://img.shields.io/github/v/release/faustbrian/go-capability?sort=semver)](https://github.com/faustbrian/go-capability/releases)
[![Go](https://img.shields.io/badge/go-1.26.6-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`capability` issues and verifies narrowly scoped, tamper-evident, expiring Go
capabilities and signed URLs. It is designed for downloads, uploads,
invitations, callbacks, one-time actions, delegated access, and
service-to-service handoffs.

The module is not an authentication system, a policy engine, a session format,
a JWT or PASETO replacement, payload encryption, DRM, or legal
non-repudiation. Applications remain responsible for authenticating callers
and authorizing each attempted use of a verified grant.

## Install

```sh
go get github.com/faustbrian/go-capability@v1
```

The core module has no non-standard-library runtime dependencies.

Run `make clean-consumer` to compile the complete public surface from a fresh
external module with no repository workspace assistance.
`make interoperability` reproduces the HMAC golden token with Python's
independent standard-library implementation.

## Issue and verify

```go
key := []byte("a 32-byte-or-longer secret belongs outside source")
signer, _ := capability.NewHMACSHA256Signer("2026-08", key)
verifier, _ := capability.NewHMACSHA256Verifier(key)

payload := capability.Payload{
    Version: 1,
    Issuer: "https://issuer.example",
    Audiences: []string{"download-service"},
    Bearer: true,
    Resource: "documents/report-42",
    Operation: "download",
    IssuedAt: now,
    NotBefore: now,
    ExpiresAt: now.Add(5 * time.Minute),
    ID: "cap-42",
    MaxUses: 1,
}
token, _ := capability.Issue(ctx, payload, signer, capability.DefaultLimits())

keys, _ := capability.NewKeySet([]capability.Key{{ID: "2026-08", Verifier: verifier}})
grant, _ := capability.Verify(ctx, token, keys, capability.VerifyOptions{
    Now: now, Skew: time.Minute, Limits: capability.DefaultLimits(),
})

err := grant.Authorize(capability.Use{
    Audience: "download-service",
    Resource: "documents/report-42",
    Operation: "download",
})
```

`Parse` only establishes canonical structure. `Verify` authenticates the token,
checks time, key lifecycle, and optional revocation policy. `Authorize` checks
the concrete resource operation. A bounded capability must additionally call
`Grant.Consume` against an atomic store before performing the protected side
effect.

## Signed URLs

Signed URLs use the same capability payload and key policy. The URL profile
fixes schemes, authorities, allowed query names, the signature parameter, the
method, and whether a SHA-256 body digest is required. Duplicate parameters,
fragments, traversal segments, encoded slashes, userinfo, authority changes,
and insecure scheme changes are rejected.

```go
profile := capability.URLProfile{
    Name: "download-v1",
    SignatureParameter: "cap",
    AllowedSchemes: []string{"https"},
    AllowedAuthorities: []string{"files.example"},
    QueryParameters: []string{"download"},
}

payload.Resource = ""
payload.Operation = ""
signed, _ := capability.SignURL(ctx, payload, capability.URLRequest{
    Method: "GET",
    RawURL: "https://files.example/report/42?download=1",
}, profile, signer, capability.DefaultLimits())
```

Absolute URL schemes and authorities are allowlisted. Relative URLs are
accepted only when `AllowRelative` is explicit. Query names and values are
encoded with `url.Values.Encode`; exactly one value per query name is allowed.

## Replay and revocation

`MaxUses == 0` means reusable. Positive limits require a `ConsumptionStore`
whose `Consume` operation atomically commits only while the count remains below
the signed maximum. Any storage error has an unknown outcome and is returned as
`ErrConsumptionUnknown`; do not retry the business side effect blindly.

`memory.ConsumptionStore` and `memory.Revocations` are process-local adapters.
They are suitable only when one process owns all decisions. They do not provide
cluster coordination or instant global revocation.

Revocation checks can match capability ID, signing key ID, subject, exact
issuer/tenant/resource, or an issuer-wide issued-before cutoff. Remote stores
must document their consistency and maximum stale-acceptance window.

## Key rotation and remote resolution

`KeySet` binds every key ID to exactly one algorithm and preserves explicit
disabled, revoked, not-before, and not-after state. Include old and new keys
during a planned overlap, issue only with the new signer, then disable or
remove the old verifier after all old capabilities expire.

`BoundedResolver` constrains a caller-provided remote source by algorithm,
key-ID length, and deadline. The source must honor context cancellation. Key
material must never be placed in tokens, URLs, errors, logs, traces, fixtures,
or metrics.

## Canonical v1 contract

Tokens use canonical JSON, unpadded base64url, explicit algorithms and key IDs,
bounded parsing, and byte-preserving UTF-8 semantics. See the
[protocol and threat model](docs/protocol.md) for the complete wire contract.

## Documentation

Use the [documentation index](docs/README.md) for the protocol, API,
deployment, conformance, replay, revocation, security, and adoption guidance.
Material standards interpretations and local protocol policy are recorded in
the [specification decision register](docs/specification-decisions.md).

## License

MIT. See [LICENSE](LICENSE).
