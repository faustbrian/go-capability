# Proof custody and identity contracts

`NewService(ServiceConfig)` returns the canonical `Service`. Explicitly provide
a trusted issuer, signer, resolver, fast local clock and validated limits (normally
`DefaultLimits`, including its 16 KiB token bound). A negative skew or missing
configuration fails with `ErrInvalidConfiguration`. Revocations may be nil only
when the application's security policy permits that. The service copies its
configuration, not its collaborators; signer, resolver, revocation source and
clock must support concurrent use when shared. No clock or callback runs under
the proof's private custody lock. The service owns no goroutines.

Select `ServiceConfig.Issuer` from trusted deployment policy. Issuance refuses a
different payload issuer; verification binds the selected issuer to both signed
payload and independently owned resolver key. Retained preparation codecs pin
that same issuer. Neither parsing nor a payload echo selects trusted authority.

`Issue` requires explicit expiry. Only zero issuance/not-before timestamps are
filled using the configured clock at UTC-second precision. Nonzero timestamps
retain existing canonical token semantics, including planned not-before skew.
The old `Issue`, `Parse`, `Verify`, caveat map encoding and HTTP APIs are unchanged.

`NewPurpose` accepts 1..128 ASCII bytes matching
`[A-Za-z0-9][A-Za-z0-9._-]*`. Periods and separators are literal punctuation,
not hierarchy. Matching is byte-exact; prefixes, case changes, wildcards, slashes
and cross-purpose substitutions never grant authority. Its zero value is invalid.

`NewReference` validates a 1..256-byte UTF-8 capability ID without ASCII controls
(C0 and DEL),
validated purpose, nonzero digest and positive UTC-second expiry. References
are mutable metadata values, not authority or authenticated existence claims.
The constructor cannot prove the caller-supplied digest's preimage. Service
issuance derives a SHA-256 digest of this exact framing:

```text
ASCII("golib/capability/reference/v1") || NUL ||
uint64-big-endian(canonical-token-byte-length) || canonical-token-bytes
```

The independent Python golden token is 367 bytes; its digest is
`24fb006ca781cebe17a9084536afcb51c829958f47d369fb5cf79fd151508a3a`.
Do not reinterpret existing stored data. Consumers may replace local facades
with these additive APIs without changing capability v1 wire bytes.

## Secret ownership

`ParseProof` uses existing `Parse` and configured bounds before copying bytes.
It proves structural validity only, never signature, expiry or authority.
Zero values and failed parsing have no secret state. Proof copies share one
private lifetime; no implicit fmt, structured logging, JSON or text operation
discloses the bytes. Fmt and structured log hooks emit only redacted labels.

`Proof.ValidateBounds(minimum, maximum)` admits an inclusive canonical byte
range without copying or exposing bearer bytes or consuming custody. Both
bounds must be positive and ordered (`ErrInvalidConfiguration` otherwise).
Zero, transferred and out-of-range proofs return `ErrInvalidToken`. A consumer
may require 32..4096 bytes while configured parser limits retain their 16 KiB
default. Success is only a synchronized custody/size observation, not signature,
expiry or use authority; a concurrent transfer may invalidate it immediately.

`Proof.CommandDigest(key, fieldPath, maximumBytes)` computes a read-only secret
binding for coordinator intent without transferring custody or authenticating
authority. Supply a trusted nonzero versioned 32-byte key, 1..4096-byte valid
UTF-8 path and positive consumer maximum. It preserves exact original token
bytes, including the signature, using HMAC-SHA-256 over this existing frame:

```text
ASCII("identity-command-secret-v1") ||
uint32-big-endian(path-byte-length) || path-bytes ||
uint64-big-endian(token-byte-length) || canonical-token-bytes
```

No clock, resolver or revocation check runs: expired or forged structural input
still has command intent, never permission to execute. Invalid configuration
returns a zero digest and `ErrInvalidConfiguration`; zero/transferred/oversized
proofs return zero and `ErrInvalidToken`. Explicit maxima do not alter parser
limits, including larger configured profiles. The private snapshot is cleared;
one acquired before transfer may finish, but later observations deny. Do not
log the sensitive digest or expose a public digest oracle. The coordinator owns
the outer fingerprint, retained key version and recovery; protected effects
still require independent validation and atomic reservation/finalization.

`Transfer` is the sole explicit transport handoff. Nil context/callback fails
with `ErrInvalidConfiguration`; zero/transferred values fail with
`ErrInvalidToken`. Pre-cancellation leaves custody unchanged. Transfer detaches
and invalidates every alias before one synchronous callback outside locks.
The callback borrows the complete byte allocation only until it returns;
all exposed capacity is cleared after success, error or panic. Errors/panics
become `ErrProofTransferFailed`, retaining only safe cancellation/deadline
classification. Failed transport is not retried automatically or proof of a
successful delivery. Caller-created transport copies retain caller-owned
custody. These APIs do not prevent malicious copying, clear arbitrary runtime
memory or erase immutable strings already supplied by callers.

## Verification and protected effects

`Service.Verify` snapshots proof custody, checks signature, key lifecycle,
time and configured revocations, and binds exact purpose and audience. An
already-acquired snapshot may finish after transfer; later verification fails.
All verification failures return zero grants. Revocation-source failures fail
closed with existing redacted errors. Verification never consumes authority.

Applications still call `Grant.Authorize` for the complete resource/subject/
tenant/caveat decision. The protected transaction owner must atomically consume
or reserve/finalize one-time use with the domain effect. Existing explicit
`Grant.Consume` remains unchanged: exhaustion/conflict are terminal; unknown
outcomes require reconciliation rather than blind retry. Memory consumption is
process-local, not transaction-enlisted or cluster-wide authority. PostgreSQL
transaction participation belongs to the separate adapter contract.
