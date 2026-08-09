# Protocol and threat model

## Threat model

A capability is a bearer secret unless `sub` binds it to an independently
authenticated subject. Theft permits every encoded operation until expiry,
revocation, or exhaustion. TLS, secret-safe storage, referrer and access-log
redaction, short lifetimes, narrow resources, narrow audiences, and atomic use
limits are deployment requirements, not properties supplied by the signature.

The format defends against payload tampering, capability widening, algorithm
downgrade, parser differentials, URL parameter smuggling, authority
substitution, traversal ambiguity, and bounded replay when a suitable store is
used. It does not hide payload contents, authenticate a human, decide business
policy, guarantee global revocation consistency, or prove who signed a token in
a legal sense.

## Payload v1

| JSON field | Required | Semantics |
| --- | --- | --- |
| `v` | yes | Integer `1`; any other version is rejected. |
| `iss` | yes | Exact issuer namespace. |
| `aud` | yes | Non-empty, sorted, unique exact audience strings. |
| `sub` | subject mode | Exact independently authenticated subject. |
| `bearer` | bearer mode | Literal `true`; mutually exclusive with `sub`. |
| `resource` | yes | Exact application-owned resource name or canonical URL. |
| `operation` | yes | One exact application operation or canonical HTTP method. |
| `iat` | yes | Unix second when issued. |
| `nbf` | yes | First valid Unix second; may precede `iat` for planned skew. |
| `exp` | yes | Exclusive expiry after both `iat` and `nbf`. |
| `id` | yes | Unique public nonce/capability identifier. |
| `tenant` | no | Exact tenant boundary; absence means the empty boundary. |
| `correlation` | no | Diagnostic correlation only; never authorizes use. |
| `max_uses` | no | Absent/zero is reusable; positive values require atomic consume. |
| `caveats` | no | Bounded exact string pairs interpreted by the application. |

Unknown JSON fields, duplicate fields, alternate field order, insignificant
whitespace, trailing data, padded base64, malformed UTF-8, control characters,
and non-canonical arrays are rejected. JSON strings preserve their UTF-8 bytes.
There is no Unicode normalization or case folding.

The canonical signing input is the ASCII concatenation
`cap1.<base64url(header)>.<base64url(payload)>`. Signatures use unpadded
base64url. HMAC-SHA-256 requires at least 32 secret bytes and compares MACs in
constant time. Ed25519 requires standard-library key sizes. No algorithm is
accepted unless it belongs to the built-in set and matches the trusted
verifier returned for the protected key ID.

## Time

`VerifyOptions.Now` is the application-selected wall clock. Negative skew is
invalid. A capability is not yet valid when `now + skew` is before `iat` or
`nbf`. It is expired when `now - skew` is at or after `exp`. Expiration is
exclusive. Key activation intervals are checked against unskewed `now`; a
`NotAfter` boundary is also exclusive.

## Signed URL canonicalization

Profiles are immutable policy and should be versioned by name. Methods are
case-sensitive uppercase HTTP tokens. Only `http` and `https` can be enabled;
schemes and allowlisted authorities are lowercase. Default ports 80 and 443 are
removed. Other numeric ports remain covered. Userinfo, fragments, opaque URLs,
empty authorities, trailing-dot hosts, non-ASCII hosts, invalid ports, and
unlisted schemes or authorities are rejected.

Paths are absolute. Empty path becomes `/`. Each decoded segment is re-encoded
with `url.PathEscape`. Dot segments, backslashes, interior empty segments,
percent-encoded `/`, and percent-encoded backslash are rejected. Unicode path
bytes are UTF-8 percent encoded. A verifier requires the received path, scheme,
authority, and complete query to already be in canonical form.

Queries use `url.QueryUnescape` followed by `url.Values.Encode`. Names are
profile allowlisted, sorted by canonical encoding, and limited to one value
each. Empty values are allowed; empty names, empty fields, malformed escapes,
duplicates, and duplicate signature parameters are rejected. The signature
parameter is excluded from the signed resource and carries exactly one token.

Relative URLs require `AllowRelative`. They cover the absolute path and query
but no authority. Deployments behind a proxy should reconstruct an absolute
external URL only from trusted static configuration or trusted proxy metadata
that was validated before calling this package. Never trust arbitrary
`Forwarded` or `X-Forwarded-*` request headers as signing input.

When a profile requires a body digest, callers supply exactly 32 SHA-256 bytes.
The package does not read or rewind bodies. Digest mismatches are compared in
constant time and fail as `ErrURLBinding`.

## Separation of responsibilities

Parsing produces no authority. Verification proves the canonical token,
validity interval, trusted key lifecycle, and configured revocation result.
Authorization then compares audience, subject/bearer mode, resource,
operation, tenant, and all caveats. Consumption is a fourth explicit step for
bounded-use grants. Middleware may carry a verified `Grant`, but applications
must keep the final authorization and protected side effect visible.
