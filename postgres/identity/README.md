# Identity capability PostgreSQL participant

`RetireEmailVerificationGrants` is callable only by the exact original native
email-removal Apply after the kernel locks/prepares its full directory partition.
It uses the same Work, not a new transaction or authority. Revoke only unused
issued/reserved grants with that retained signed identifier target; preserve
consumed/other-target history and all reservation/origin metadata. Live
unclassified legacy grants deny removal, never guess targets or bulk-retire a
subject. Propagate every error to roll back the complete protected mutation.

Optional Go 1.27 module implementing capability-owned reservation and recovery
through the sole identity PostgreSQL Coordinator. This is a storage adapter,
not a workflow, signing service or independently committable store.

The module path is
`github.com/faustbrian/go-capability/postgres/identity`. Supply the trusted
deployment issuer in `IssuerConfig.Crypto.Issuer` and in verifier-key ownership;
issuance and verification must not select that trust from a parsed token.
Existing `cap1` wire bytes and this adapter's separate coordinator ledger stay
unchanged. The root capability store's explicit legacy-issuer migration applies
only to its own consumption tables, never this adapter's identity tables.

## Quick start and API

`IssuerConfig.RetainEmailVerificationTargets` explicitly selects migration 005.
It retains the exact authenticated signed identifier resource during the same
original issuance transaction, including signup and unselected managed links.
Enable it on every native verification issuer before selecting email removal.
False preserves the prior issuance SQL and does not require the new column.
The populated upgrade never guesses a target or rewrites retained origin/use
history. Active original verification grants without target classification must
make removal fail closed; originless grants cannot safely be assigned even to
a subject. Expired or terminal history remains unchanged. Do not backfill targets
from current addresses or unsigned caller annotations.

The removal storage transition revokes only unused issued/reserved verification
grants with the exact tenant, subject and retained identifier. It preserves
consuming-command/generation, original provenance, expiry and replay metadata.
Exact reserved-but-unused revoked evidence remains negative for native recovery;
unanimous noncommit reconciliation preserves revocation rather than reactivating
or converting it into usable proof. The public native removal orchestration
and its complete lifecycle are still unfinished; these storage prerequisites
are not an independently executable removal API.

`ManagedEmailScopeFromPayload` projects the stable bounded family of a
management-v1 identifier-verification grant. An explicitly selected fifth
`email.supersession` caveat must match that family. Fresh commands, times,
callbacks, key versions and observed authority cannot escape predecessor
invalidation. This metadata is not authentication or permission to resend.

Install migration 004 after the unchanged 003 history before selected management
supersession. Issuance reuses the existing family columns and one-use participant;
replacement commit invalidates older unused selected grants, while rollback
retains predecessor validity and original recovery custody. Selected inspection
and managed consumption deny superseded rows. Consumed, unselected and other
families remain untouched. The native email workflow must acquire the same
family fence before identity/factor/capability locks and enforce current pending
state, fresh primary/factor/risk authority and 30s..10m cooldown (reference 60s).
It must commit pending-generation changes, encrypted delivery and replacement
issuance together. These adapter seams do not yet supply that public resend path.

`issuer.PrepareManagedVerificationConsumption(ctx, confirmationBinding, proof,
originalEnvelope, originalReplayVersion)` prepares the exact management-v1
email link for `identity.email.verification-confirm.managed-v1`. Signup links
and change-confirm schemas deny. The signed purpose, subject/resource, intent
caveats, expiry and retained replay identity are unchanged. This performs no
SQL, signing or consumption. The native email owner still authenticates the
original encrypted request and current credential/account/factor/risk authority;
the existing Participant consumes proof atomically with the protected effect.
This seam does not issue sessions or provide a primary-address change workflow.

`issuer.PrepareMFAContinuation(ctx, consumeBinding, payload)` signs one
`identity.mfa.complete` child for the closed anonymous magic-link consumption
profile. Supply the canonical challenge ID and exact MFA profile/scope caveats
already frozen by the native owner. The child is bounded to five minutes;
kernel staging additionally enforces the original primary expiry and complete
scope. This method grants no factor or session authority. Original encrypted
preparation binds the MFA subject and preserves signed bytes, ID and expiry
across retries without renewing disclosure. Real native factor persistence and
completion remain required before a public MFA login can use this profile.

`issuer.PrepareMFAConsumption(ctx, factorBinding, recipientUserID,
continuationID, scopeDigest, configuredIssuer, proof, originalEnvelope,
originalReplayVersion)` verifies that same child for the closed anonymous
TOTP, OTP, recovery-code or security-key completion operation. Supply original
authenticated continuation and issuance metadata, never request-selected
identity or current-key defaults. The exact signed child/profile/scope, tenant,
recipient, issuer, audience and one-use bounds must match; signed purpose stays
`identity.mfa.complete`, not the factor operation. It preserves original
envelope, expiry and replay identity without transfer, signing or SQL.

This is not factor proof or permission to issue a session. The MFA owner still
checks original browser/primary/remember scope, allowed factor, current policy,
account/factor authority and shared attempts, and verifies the actual factor.
The sole coordinator consumes the original child atomically with successful
factor replay, continuation completion, session and audit/lifecycle effects.
No public MFA authentication workflow is supplied by this capability seam.

`issuer.ReadMFAMagicLinkParent(ctx, primaryPool, originalChild,
originalParentID, originalParentEnvelope, originalParentExpiry)` resolves the
already-consumed parent from authenticated continuation custody. The parent's
consumer command/fingerprint/generation must equal the child's original
issuance tuple. `Bindings` supplies the original request and primary identities
and signed times, not the parent's decoded payload or access authority.
The magic-link owner reconstructs its entire original payload using existing
request custody and must call `parent.MatchPayload(payload)` before using that
metadata. The opaque retained digest rejects changed or incomplete reconstruction.
No primary bearer, new intent table, signing, use or expiry renewal is involved.
Current browser, account, factor, policy and child authority still need their
native protected-transaction checks. Install the complete existing capability
adapter history, including original issuance and magic-link supersession.

`issuer.PrepareMagicLinkConsumption(ctx, consumeBinding, recipientUserID,
identifierID, proof, originalEnvelope, originalReplayVersion)` verifies original
proof custody for anonymous `identity.magic-link.consume` / `magic-link-consume`
version one. Supply the authenticated envelope and replay version from original
durable issuance, not client input or current-key defaults. Signed tenant,
recipient, `identity.magiclink/<identifierID>` resource, identifier caveat,
audience and one-use limit must match; an alternate valid envelope denies.
No reservation, consumption, transfer, signing or expiry renewal occurs.

The resulting plan is not login permission. The native owner must authenticate
the complete original payload and encrypted intent, callback/pre-auth custody
and current recipient/factor/risk authority, then enlist this module's existing
Participant with all session/audit/lifecycle effects in the sole transaction.
Bounded signature/revocation verification applies; failed or cancelled calls
return a zero plan and redacted typed error. Retained replay keys remain usable
after active-key rotation without changing the original consuming identity.

`issuer.PrepareMagicLinkRecipient(ctx, originalRequestBinding, recipientUserID,
payload)` prepares one `identity.magic-link.consume` grant for the exact anonymous
`identity.magic-link.request` / `magic-link-request` version-one profile. It uses
the existing signer and opaque proof custody; it is not recipient eligibility or
authentication. Before staging, the native `identity/magiclink/postgres` owner
must call the kernel's `RequireMagicLinkRecipient` with the original verified
email snapshot and supply its documented `magiclink.*` signed scope caveats.
Original command scope remains anonymous. Ordinary, signup and password-reset
preparation cannot borrow this selection.

For selected resend behavior, project `MagicLinkScopeFromPayload` from the
authenticated/reconstructed original `magiclink.*` payload. It binds the exact
issuer, audience, tenant, recipient, identifier, callback, intent and browser
flow/profile; token IDs, dates and observed authority versions do not change
that scope. Set signed `magiclink.supersession` to lowercase hex of `Digest()`.
This is metadata, not authentication or recipient eligibility. Install migration
003 before using this selection. Historical rows without it remain unchanged.

The native request and consume feature **must** call
`LockMagicLinkSupersession` in their exact Apply invocation before account,
factor or browser row locks. Do not hold the fence across signing, risk/provider
preparation or callbacks. Selected issuer persistence registers the new scope
and invalidates earlier issued/reserved unused links in that same transaction.
Consumption acquires the same fence before capability row locks and rejects
superseded rows. Recovery and terminal release preserve original command,
generation and use evidence. A consume already holding the fence can commit;
resend then leaves its consumed evidence intact. This native contract still
requires the complete workflow's scope reconstruction and HTTP composition.

`issuer.ReadMagicLinkOrigin(ctx, primaryPool, proof)` also returns an authenticated
superseded flag from that same original-issuance read. It requires the stored
scope to match the signed claim and returns zero metadata on failure.
`ValidateIssuedProof` denies superseded links; historical origin remains readable
for command retries, not reusable authority. A workflow must check browser scope
before exposing distinctions publicly and repeat admission atomically: a read
cannot prevent a subsequent resend or establish a committed command outcome.

Use the existing `IssuancePreparationCodec` for encrypted durable retry custody.
Its magic-link-specific authenticated context binds the selected recipient while
leaving older profiles byte-identical. Restoration preserves the original grant,
replay key, expiry and ciphertext; it cannot reveal a bearer again. Issuance and
encrypted delivery enlist in the sole coordinator transaction. Recovery reports
absent issuance as not committed only under the original recovery fence when the
grant, keyed replay identity and originating-command rows are all absent;
conflicting evidence remains unknown. Neither preparation nor origin inspection
implements resend/supersession, factor policy, consume or session orchestration.

`issuer.PreparePasswordResetConsumption(ctx, originalResetCommand,
originalReplayVersion)` derives a one-use consumption plan directly from the
paired opaque proof retained by `identity.NewFeaturePasswordResetInputCommand`
or `identity.NewFeaturePasswordResetCommand`. Use the original input form to
prepare the same plan before authoritative admission and password hashing.
There is no substitute proof argument. The exact reset descriptor and signed
`identity.password/<credentialID>` resource must match the command, along with
tenant and user. The issuer rechecks configured signature, audience, time and
revocation policy and uses the explicitly retained issuance key version, not
the active default. Repeated preparation preserves envelope, expiry and replay
identity; it performs no SQL, signing, transfer, reservation or consumption.

This plan alone cannot reset a password. The native password workflow must
authenticate durable original issuance intent and its closed recovery profile,
check current identifier/factor eligibility and HIBP/risk, and compose password
mutation and required session effects with capability use in the sole kernel
transaction. Obtain the original replay version from authenticated issuance
provenance. Retain that key through recovery; expired or transferred custody
cannot be renewed through preparation. Errors return a zero plan and redacted
typed classification. Earlier deadlines and the issuer timeout bound work.

`issuer.ReadIssuanceOrigin(ctx, primaryPool, proof, trustedPurpose)` reads exact
original provenance for an explicitly selected one-use purpose, including
password reset. `issuer.ValidateIssuedProof` has the same arguments and also
requires issued, unused, primary-unexpired state in that read. Both preserve
original replay-key version, signed envelope and timestamps. Retain replay keys
until their original credentials no longer need them; never substitute the
active version on a retry. Neither method reserves or consumes a proof.

These are trusted adapter seams, not public scanner responses or reset
permission. The owning workflow must validate its closed purpose-specific
payload and encrypted original intent, current account/factor/risk eligibility,
exact tenant/subject/callback and transactional one-use effects. Do not expose
their sensitive grant/command projections publicly. Historical origin lookup
can observe terminal provenance but still enforces configured signature,
audience, time and revocation policy; it does not make that proof reusable.
Earlier cancellation and the issuer timeout bound one indexed primary read
and crypto. Failure returns zero metadata; pools and opaque proof custody are
borrowed. Registration-specific methods retain their stricter closed profile.

`issuer.PrepareRegistrationVerificationConsumption(ctx, binding, proof,
originalEnvelope, originalReplayVersion)` prepares the anonymous signup profile
for the current native email confirmation action. The signed purpose remains
`identity.identifier.verify`; the current binding identifies the actual caller,
tenant, user and signed identifier, without introducing session caveats. The
email owner must authorize the original mailbox/redirect/version commitment
first. This rechecks configured crypto/time/revocation and preserves original
envelope/expiry/replay metadata, but performs no SQL, reservation, consumption or
signing. A plan is not current authority or a usable confirmation transaction;
native kernel atomic confirmation composition remains in development.

`issuer.ReadRegistrationOrigin(ctx, primaryPool, proof)` authenticates a
registration-profile signup proof and matches its exact original positive
issuance, returning the grant, original command and retained replay-key version.
It is bounded and read-only: repeated or concurrent reads cannot reserve,
consume, issue, deliver or renew a credential. Key rotation must retain the
original replay key; unavailable retained keys fail closed.

This lookup is a trusted composition seam, not public email validation or a
signup receipt. The origin owner must authenticate the original encrypted
signup input and email intent. Confirmation must separately check current
account/identifier and capability state and consume atomically with the
protected mutation. Historical provenance remains readable independently of
the row's consuming state; it never grants permission to use a terminal token.

For a privacy-export command, use
`issuer.PreparePrivacyExportConsumption(ctx, command, proof, originalReplayVersion)`.
It authenticates the original opaque proof under the same configured verification
and retained-key derivation as identifier consumption. Even another trusted
signature over identical payload metadata is distinct custody and is rejected.
The returned plan alone cannot enable privacy reservation or execution: the
kernel must still compose current native session/policy checks, atomic durable
proof use, all 23 captured cuts, audit/lifecycle and terminal receipt recovery.
Preparation does not transfer or consume bearer custody and cannot renew its
lifetime. Snapshot integrity and current authority remain their owners' concerns.

Before a protected identifier transaction, call
`issuer.PrepareIdentifierConsumption(ctx, command, proof, originalReplayVersion)`
to obtain the capability plan. `command` is the immutable core identifier
command; `proof` must be the exact original opaque signed envelope. Preparation
rechecks the configured signature, audience, time and revocation policy; it
never transfers or consumes the proof. The version comes from trusted original
issuance metadata or server policy, never a bearer-selected default. Keep the
original version after replay-key rotation: selecting the current key produces
different metadata which cannot match the issued durable record. The native
participant still owns exact durable matching and coordinator-only atomic use.
This method is not current session/policy/ceremony admission or a commit receipt.

Install `Migrations()` through your migration backend with a separate adapter
ledger. Compose the real kernel, audit and outbox before coordinator construction:

```go
participant := identitycapability.NewParticipant()
registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{
    repository, auditContributor, lifecycleContributor, participant,
})
```

Only the coordinator may invoke phases using its frozen registry and sealed
handles. Registration grants neither cryptographic validation nor current
identity/session authority. No pool, transaction, callbacks, keys or goroutines
are retained; instances are immutable and concurrent-safe across independent
commands. Each handle is serial-use. Nil/zero participants and fabricated,
foreign or stale authority fail before writes. Cancellation/deadlines and
conflicts remain typed; SQL errors never expose diagnostics or private values.

- `NewParticipant`: stateless default-schema instance, without I/O.
- `Descriptor`: `capability/postgres`, `capability.one-use`, version 1.
- `ReserveCapability`: existing issued to reserved, without consumption.
- `RebindCapability`: CAS exact command/fingerprint/prior generation with live
  primary expiry. Missing, terminal or changed input cannot be reserved.
- `ApplyCapability`: provisionally consume the exact reserved current generation
  only below the original signed maximum. Row locking precedes primary expiry
  evaluation, so waiting cannot carry positive validity beyond its expiry.
- `FinalizeCapability`: recheck original primary expiry and mark that exact
  consumed reservation finalized, in the same protected transaction. Neither
  method closes a transaction or determines the command outcome.
- `RecoverParticipant`: exact frozen primary evidence. Missing/conflicting
  evidence stays unknown; participant commit evidence is not a command receipt.
- `ReleaseCapability`: only unanimous non-commit authority permits terminal
  release. It never makes a bearer reusable. Expiry alone cannot release it.
- `Migrations`: additive embedded SQL independent of legacy consumption rows.

## Adoption, compatibility and tradeoffs

The root `go-capability/v2/postgres.ConsumptionStore` remains a separate store
with its own documented issuer-ownership migration. It owns separate transactions
and cannot provide atomic
identity mutations. This optional nested module avoids a dependency cycle:
identity consumes capability, so the core must not depend on identity/postgres.
There are no permanent replacements or mandatory root dependencies on this
module. No legacy row is imported, reset or removed; missing records are never
inserted during reserve. Mixed binaries retain the separate legacy schema.
Downgrade and time-based deletion are unsupported because erasing one-time
evidence permits replay. Never reinterpret legacy consumed bearers as issued.

## Security and unfinished scope

Application roles must not own tables or have DDL, TRUNCATE, DELETE or
trigger-disable authority. Raw bearers and cryptographic keys are not stored;
retained keyed digests, opaque IDs, proof/command fingerprints and generations
are sensitive correlation metadata. Restrict them to trusted composition.
Participant formatting is redacted and JSON export rejected. Status and release
accept the exact original expiry even after it passes, without renewing authority.

Native consumption/apply and finalization SQL are implemented;
revocation, tombstone cleanup/key retirement and complete identifier
orchestration remain unfinished. Do not
deploy this as a complete workflow. Tests seed issued metadata explicitly as
fixtures, not a production issuer or session/risk authority. The current
coordinator still rejects capability-bearing domain `Begin`.

Real PostgreSQL tests exercise the private SQL operation delegated to by the
phase methods, including rollback, maximum-use contention, unchanged binding
and expiry during a lock wait or between apply/finalize. These tests do not
fabricate coordinator handles or prove successful public domain execution.
Closed phase custody is tested by identity/postgres; successful native callback
composition remains required when its complete authorized domain path is ready.

## FAQ and examples

**Can lease or token expiry release a reservation?** No: every frozen participant
must prove non-commit. **Can released evidence be reused?** No: retry needs newly
issued evidence. **Does status replace cryptographic verification?** No: trusted
composition validates the proof before preparing independently keyed metadata.

The compile-checked example demonstrates registration identity; integration
tests use the real coordinator, audit, outbox and capability participants with
disposable PostgreSQL. Exact coverage/mutation and release gates remain pending.
See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Original issuance

### Durable preparation custody

`NewIssuancePreparationCodec(issuer, config)` selects a deployment-bound local
keyring and concrete HMAC/Ed25519 verification keys. It does not reuse potentially
remote signing resolvers or revocation callbacks during restoration. Configure a
bounded local clock; retain original envelope, signing-verification and replay
keys for the command journal's recovery lifetime. Keys are copied, not borrowed.

Use `codec.CheckpointPreparation(ctx, prepared, originalGeneration, encrypt)`
**instead of** calling `TransferForDelivery` separately. Each original proof is
transferred once into encrypted journal custody and, optionally, the synchronous
delivery-encryption callback. The callback must honor cancellation, must not send
or reveal, and must not retain borrowed token bytes. Failure or panic destroys the
whole batch. Prepared values and their aliases require serial use; independent
batches and the immutable codec support concurrent calls. A same-generation
retry returns the original encrypted record without invoking the callback.

Retain this record and the native delivery checkpoint in the workflow's existing
preparation output, under its original generation. There is no additional journal
or transaction owner. Records are bounded to 512 KiB. Do not log ciphertext or
retain it beyond the workflow's secret-retention policy.

`codec.RestorePreparation(ctx, binding, originalGeneration, immutablePlan, wire)`
authenticates the full command, deployment, audience, generation and original
issuance plan, then verifies the original tokens locally. It never signs,
consumes, renews expiry, invokes delivery, opens SQL or acquires fresh entropy.
Missing keys, changed metadata and expired grants fail closed. Restoration
returns staging-only custody: `issuer.Stage` still requires current native Work
authority, and `TransferForDelivery` cannot reopen any restored bearer. Restore
encrypted messages through the existing delivery contributor separately.

This adapter contract does not itself implement the password signup service or
prove the complete journal-retention/restart journey.

### Anonymous registration

For an existing verified recipient, use
`issuer.PrepareResetRecipient(ctx, originalBinding, userID, payload)` under the
exact anonymous `identity.password.reset-request` / `password-reset-request`
profile. It prepares exactly one `identity.password.reset-complete` grant and
freezes `ResetRecipientUserID` without replacing the originating command's
anonymous scope. Signup selection is mutually exclusive. The issuer preparation
codec authenticates this target while preserving old ordinary/signup custody.
Native staging additionally requires the exact invocation's primary verified
email and password-credential fence, with matching original grant scope and
versions. Preparation is not recovery eligibility: current factor policy,
durable request orchestration, complete reset caveats and atomic completion /
session effects remain workflow responsibilities.

For this exact single-grant reset-request profile, recovery can prove issuer
non-commit only when the grant identity, replay identity and every grant for
the original command are absent under the coordinator's locked recovery scope.
Nonmatching origin rows remain conflicting evidence, not absence. This vote
does not certify delivery/audit/lifecycle owners or reconstruct success.
Ordinary and signup missing-evidence recovery remains unchanged.

Use `issuer.PrepareRegistration(ctx, originalBinding, newUserID, payloads)` for
the exact anonymous `identity.password.signup` / `password-signup` v1 profile.
Every payload must target that prospective user, the original tenant and the
configured audience, with purpose `identity.identifier.verify`. The original
binding must retain its anonymous flow and have no user or record identity.
This method is bounded by the same preparation timeout as `Prepare`; typed
validation, cancellation and unavailable errors carry no secrets. Inputs are
borrowed during the call, returned plans are defensive copies, and prepared
proof aliases share the existing reveal-once lifetime.

`RegistrationUserID` is frozen into the returned plan. Enlist the native
password-signup phase and issuer; the native phase must apply the exact
`PasswordRegistrationDomain` intent before `issuer.Stage` in the same Work.
Preparation never creates a user or authorizes registration. The kernel checks
the actual newly registered active user before any grant is staged. A missing
registration, foreign target or changed proof metadata aborts the entire
transaction. Persistence stores the signed new-user subject but retains the
original anonymous command, fingerprint and generation as issuance origin.

Encrypted delivery remains scoped to the original anonymous flow, not a forged
user-bound command. Render/encrypt through `TransferForDelivery` before the
transaction and stage native delivery alongside registration and issuance;
only the post-commit worker may send. Neither preparation nor an unknown commit
permits a replacement token or a second disclosure. Historical recovery reads
the frozen target and never signs again. Partial evidence does not reconstruct
a committed command receipt; missing/conflicting issuance stays unresolved.

The module pins identity and identity/postgres at the matching committed kernel
revision. Deploy compatible readers before enabling new signup plans: earlier
strict decoders fail closed on their new frozen field. Existing ordinary plan
bytes, schemas and user-bound APIs remain unchanged. The integration fixture
proves native registration, issuance, audit/outbox and encrypted delivery with
a bounded local sender; it is not yet the complete password/HIBP/email workflow.

### Existing user-bound commands

`NewIssuer(IssuerConfig)` constructs the separate `capability.issuance` v1
participant. Enlist it after the base participants and before optional delivery.
Its crypto configuration uses the existing capability service, not a new token
format. Provision replay keys independently of signing keys. The active replay
version must be retained; keys are copied and duplicate material rejected.
Retained versions are required for historical metadata and recovery.

`Prepare` signs and verifies fresh random IDs outside every database transaction,
then freezes immutable Grants and exact full-envelope fingerprints. It accepts
only one-use, subject-bound tokens for the configured audience and original
command tenant/user. Callers supply future-operation payload policy, never IDs
or replay digests. Replay identity is HMAC-SHA-256 over the ASCII domain
`golib/capability/identity-replay/v1` plus NUL, big-endian uint32-length-prefixed
tenant and purpose, and the authenticated 32-byte full-envelope SHA-256 digest.
This intentionally differs from the core public Reference domain. Payloads,
audience/origin/authority caveats and signatures are committed by that envelope;
the adapter stores an additional canonical payload digest, never raw payloads.

`PreparedIssuance.Plan` returns a defensive declaration; `Issuer.Stage` binds it
to the exact original command and issuer instance. The sealed persistence phase
rederives every replay binding before native absent-to-issued SQL. Schema 002
adds nullable grouped original command/fingerprint/generation, subject, signing
key and signed-time metadata without changing historical rows or migration 001.
Origin remains distinct from later consuming-command custody. Duplicate inserts
conflict rather than update any issued, reserved or terminal record; exact
original-command replay is handled by the sole coordinator, without resigning.

`TransferForDelivery` shares the core one-transfer lifetime and permits only
trusted synchronous authenticated encryption admission, not sending or response
disclosure before commit. It grants no receipt. Copies cannot disclose twice;
failed callbacks cannot retry. There is no synchronous reveal or end-user flow
API here yet. Retain prepared custody through the same command retry; never
prepare replacement credentials after unknown commit. Recovery reads exact
origin evidence and never issues or reveals replacements; absence stays unknown.

Real PostgreSQL tests compose the native issuer, identity repository, audit and
outbox to prove original commit/rollback, unchanged replay, cryptographic
metadata mismatch denial and multi-grant insertion. A public native delivery
composition also transfers each original proof into template rendering and
authenticated encryption before the transaction, commits issued state and
ciphertext atomically, and denies missing effects and mismatched metadata.
The native worker delivers the original signed credential after commit; the
test sender verifies its signature. Terminal ciphertext is erased without a
second send. These checks use a bounded local
sender callback, not a live email provider. They do not yet prove
recovery invocation, expiry races,
populated-state migration or complete identity workflows. Release gates remain
pending; this is not a deployable complete one-time workflow.

### Read-only registration validation

`Issuer.ValidateRegistrationProof(ctx, pool, proof)` combines authenticated
original issuance with an indexed primary check for issued, unused and
exclusively unexpired state. Repeated validation does not reserve, consume,
renew or mutate the proof. Reserved and terminal states deny without returning
grant or correlation metadata. `ReadRegistrationOrigin` remains a historical
reader, including after consumption, and must not be used as usable validation.

Both are trusted composition seams: successful grant metadata is sensitive.
The email workflow must additionally bind original address/redirect and current
account state, returning only bounded public scanner metadata. Validation is
not an execution ticket; confirmation repeats current admission and atomically
consumes the original proof with the protected address transition.

## Integration fixtures

Integration tests create and remove their own PostgreSQL container by default.
Select `CAPABILITY_POSTGRES_VERSION` from the digest-pinned
`testdata/postgres-images.tsv` matrix (default 18). Updating an image requires
reviewing its version and immutable digest, then rerunning the affected tests.
An explicit `IDENTITY_CAPABILITY_TEST_DSN` must select `identity_test` and only
loopback primary/fallback hosts; use a disposable cluster, never a shared one.

The test-only `testdata/legacy_consumptions.sql` is an unchanged copy of
`postgres/migrations/001_capability_consumptions.sql` from capability source
`caab644d2fec`, SHA-256
`a66bda3ba57407aeb6bc68724a6623e46ac83a1459a2c3bef6043232ff4ca9b0`.
It retains the repository license and allows the independently downloaded
module to exercise the root store's explicit legacy migration without reading
outside its source archive. Refresh it only against that owning migration.
