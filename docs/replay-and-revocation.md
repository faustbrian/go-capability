# Replay, revocation, and failure modes

## Atomic consumption

`ConsumptionStore.Consume` owns the synchronization for one capability ID. It
must atomically compare the persisted identity, expiry, signed maximum, and
current count, then increment only when the result remains within the maximum.
`false then insert`, leases, local mutexes in a multi-process deployment, and
read-then-write operations without a lock are not valid implementations.

`ErrReplayExhausted` and `ErrReplayConflict` are known no-consume outcomes. Any
other store error is exposed as `ErrConsumptionUnknown` because a timeout or
connection loss may happen after commit. Fail closed. Do not retry the business
side effect merely because consumption returned an error. Put consumption and
the protected side effect in one database transaction when both can share the
same durable owner; otherwise design the action to be idempotent and reconcile
unknown outcomes explicitly.

Expired records may be deleted after `exp` plus the maximum accepted verifier
clock skew and any store replication delay. Cleanup is operational maintenance,
not part of correctness for a live capability.

The memory adapter is atomic only inside one process. Restart loses all state.
It is not suitable for horizontally scaled one-time actions.

## Revocation

Revocation checks occur only after signature and time validation. Boundaries
are exact capability ID, issuer/key ID, issuer/subject, issuer/tenant/resource,
and issuer-wide issued-before time. Issued-before is strict: a capability with
`iat == cutoff` is not revoked.

A revocation checker error fails verification closed as
`ErrRevocationUnknown`. Remote or replicated adapters must document read
consistency, propagation, caching, outage behavior, and the maximum interval in
which a revoked capability might still be accepted. This module never labels
eventual revocation as instantaneous.

The memory checker has a zero stale window for later reads in the same process
after a revocation method returns; other processes never observe that state and
therefore cannot use it for cluster revocation. For an external checker with a
declared propagation-and-cache bound `S`, the remaining stale-acceptance window
at revocation time is at most the smaller of `S` and the capability's remaining
`exp + skew` verifier window. A deployment that cannot state and exercise a
finite `S` must not depend on revocation for its acceptance bound.

## Key failures

Unknown, disabled, revoked, not-yet-active, expired, and algorithm-mismatched
keys are distinct policy failures. Remote resolution is bounded by caller
context, key-ID size, algorithm allowlist, and the configured adapter timeout.
`BoundedResolver` does not cache and preserves trusted unknown-key and
algorithm-mismatch categories. The remote source must honor cancellation, must
bound any cache staleness it introduces, and must not return secret material in
its errors.
