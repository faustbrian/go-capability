# Replay, revocation, and failure modes

## Atomic consumption

`ConsumptionStore.Consume` owns synchronization for the exact authenticated
`(Issuer, CapabilityID)` tuple. Missing issuer fails closed. `Grant.Consume`
forwards the authenticated issuer rather than accepting a caller-selected one. It
must atomically compare the persisted identity, expiry, signed maximum, and
current count, then increment only when the result remains within the maximum.
`false then insert`, leases, local mutexes in a multi-process deployment, and
read-then-write operations without a lock are not valid implementations.

`ErrReplayExhausted`, `ErrReplayConflict`, and `ErrCapacity` are known no-consume
outcomes. Custom adapters are trusted to assert these classifications only when
no use committed. Any other store error is exposed as `ErrConsumptionUnknown`
because a timeout or
connection loss may happen after commit. Fail closed. Do not retry the business
side effect merely because consumption returned an error. Put consumption and
the protected side effect in one database transaction when both can share the
same durable owner; otherwise design the action to be idempotent and reconcile
unknown outcomes explicitly.

At the `Grant.Consume` boundary, replay-policy errors are normalized as well:
`errors.Is` preserves their safe policy and context classifications without
retaining arbitrary store diagnostic text or causes. Bare replay-policy
sentinels keep their identity; callers must not depend on the original wrapped
store error. Direct adapter calls do not provide this redaction boundary.

## Finite process-local admission

Both `adapters/memory` and the retained `memory` facade use finite defaults:
10,000 records and 4 MiB of retained key-string bytes **per store**.
`DefaultStoreLimits` returns those budgets; `NewConsumptionStoreWithLimits`
and `NewRevocationsWithLimits` accept explicit positive `StoreLimits`.
The original constructor signatures remain available with the finite defaults.
Invalid limits return `ErrInvalidConfiguration`; limits are copied at construction.

Replay entries count one exact issuer/ID tuple and the sum of its two string
lengths. Revocations count every entry across **all five maps** in one aggregate
record allowance; each retained occurrence of issuer/value, issuer/tenant/resource,
or cutoff issuer charges its own string lengths. Newly admitted strings are
cloned; repeats and in-place count/cutoff updates do not borrow new caller backing
storage. This bounds retained records and owned string bytes, not exact heap
usage: map, record, allocator overhead and caller-owned input are additional.

Before copying or hashing strings, each operation's input lengths must fit
`MaxStringBytes`. A `Check` query sums issuer, capability ID, key ID, subject,
tenant and resource, so a small query budget can reject an otherwise ordinary
valid grant. `Verify` turns that checker error into `ErrRevocationUnknown` and
returns no grant; it does not expose the checker capacity classification.

A new replay record or revocation at capacity returns `ErrCapacity` without
eviction or state insertion. Replay refusal returns a zero result and commits
no use; `Grant.Consume` preserves its safe classification without arbitrary
diagnostics or causes. Existing live replay counts and conflict/exhaustion
semantics do not change. Duplicate revocations and later/equal/earlier updates
to an existing issued-before cutoff consume no further admission; the cutoff
can only advance. Revocations are never evicted and have no removal API.
Trusted administrative writers **must handle every insertion error**; a refused
write does not revoke its target, and the store does not latch an unrelated
permanent failure to compensate for ignored errors.

Replay cleanup releases exactly the removed count and key-string charges.
Expired entries remain charged until cleanup or same-tuple expiry replacement;
there is no automatic unrelated-entry eviction. The trusted cleanup owner must
choose a cutoff beyond every applicable acceptance window, including verifier
skew and clock disagreement. Removing live state can reset its allowance.
Store lifecycle, issuance/admission rates and overload handling remain application
responsibilities; do not replace an active ledger simply to recover capacity.

Expired records may be deleted after `exp` plus the maximum accepted verifier
clock skew and any store replication delay. Cleanup is operational maintenance,
not part of correctness for a live capability.

The memory adapter is atomic only inside one process. Restart loses all state.
It is not suitable for horizontally scaled one-time actions.

PostgreSQL uses the database transaction clock and rejects requests at or beyond
expiry with `ErrReplayExhausted` before loading or writing quota state. This
prevents fresh allowance for an expired identical grant whether its old row
remains or was cleaned. A genuinely future-expiry replacement can renew an
expired row; a changed expiry or maximum on a live row remains a conflict.
Verification skew does not extend store acceptance. Valkey likewise rejects
expired requests using its server clock, while memory retains its existing
invalid-configuration classification for expired direct requests.

Durable upgrades require explicit single-legacy-issuer ownership and fencing
all old writers; no adapter silently infers ownership or resets allowances.
PostgreSQL schema version 2 is a caller-owned transaction migration. Valkey's
mandatory `LegacyIssuer` retains that owner's exact old key. See the
[migration and retirement requirements](adoption.md#issuer-scoped-replay-next-major).

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
