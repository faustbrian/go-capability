# capability

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
go get github.com/faustbrian/golib/pkg/capability@v1
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

- Tokens are `cap1.<header>.<payload>.<signature>` using unpadded base64url.
- The protected header is canonical JSON containing version, type, algorithm,
  and key ID. The algorithm is checked against the trusted resolved verifier.
- Payload JSON uses a fixed field order and Unix seconds. Audiences are sorted
  and unique. Caveat object keys use Go's deterministic JSON map ordering.
- Missing optional strings and empty caveats are absent. `bearer` is present
  only when true; `sub` and `bearer` are mutually exclusive. `max_uses` is
  absent when reusable.
- UTF-8 is preserved byte-for-byte and is never normalized. NFC and NFD spellings
  therefore identify different authority strings. Control characters are
  rejected.
- Parser limits bound token size, field size, audiences, caveats, lifetime, and
  maximum use count before authority is returned.

See [protocol and threat model](docs/protocol.md) for the complete field, URL,
clock, failure, proxy, and deployment semantics.

## Documentation

- [Protocol and threat model](docs/protocol.md)
- [Specification decisions](docs/specification-decisions.md)
- [Conformance](docs/conformance.md)
- [API reference](docs/api.md)
- [Deployment profiles](docs/deployment-profiles.md)
- [Replay, revocation, and failure modes](docs/replay-and-revocation.md)
- [Security review](docs/security-review.md)
- [Adoption, migration, and FAQ](docs/adoption.md)
- [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).

## Ecosystem

Use the [Golib documentation portal](https://github.com/faustbrian/golib/blob/main/docs/index.md)
to choose companion packages, supported stacks, recipes, and operations guidance.
