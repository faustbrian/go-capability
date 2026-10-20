# Changelog

## Unreleased

- Prepare canonical phone-password-reset capability consumption directly from
  the exact sealed joint input or generated command. Preserve original replay
  key, envelope, absolute expiry and password/SMS/TOTP/browser custody without
  converting the phone profile into emailed reset. Existing user-bound issuance
  and coordinator-only one-use storage remain the owners; no migration is needed.

- Admit the exact username-signin origin for original MFA child issuance.
  Preserve its distinct command/schema and encrypted restoration binding;
  password and magic-link preparations cannot be restored as username signin.
  This adds no authentication or session authority and needs no migration.

- Permit the exact username-signup origin to prepare a registration-verification
  grant without relabeling its command. Preserve existing password origins and
  deny mixed schemas or ordinary anonymous subject overrides; the native kernel
  still owns same-transaction identity creation and issuance.

- Prepare original organization-invitation proof consumption with exact signed
  recipient, organization, role and identifier-version scope. Preserve original
  envelope, expiry and retained replay identity without consuming or granting
  membership; native invitation transaction admission remains separately owned.

- Preserve separately consumed registration-verification parent custody for
  explicitly selected TOTP challenges. Protected completion repeats original
  grant and committed-history checks without consuming the parent again.

- Expose exact-target verification-grant retirement only within the original
  kernel-prepared email-removal Apply. Preserve reserved/consumed provenance
  and deny live unclassified legacy grants rather than guessing their target.

- Use supported secret-envelope v2 for original issuance preparation, preserving
  provider/entropy diagnostic containment and existing ciphertext/key formats.
  Public byte-key configuration and sole-transaction custody stay unchanged.

- Make native framing bounds explicit at count, length, index and expiry
  conversions. Preserve original encrypted preparation and replay-HMAC bytes;
  larger custom cryptographic limits do not expand the native token frame.

- Reject original issuance preparation when its final successful authority
  lookup returns after cancellation or the preparation deadline. Return the
  typed context error and destroy every acquired proof instead of retaining
  transferable custody. Later transactional authorization remains separate.

- Adopt the capability-v2 engine in the independently versioned optional
  `go-capability/postgres/identity` module. Its physical directory precedes
  any module-local major version, not the root engine's `/v2`. Require a
  trusted configured cryptographic issuer for original
  issuance and verification without changing `cap1` bytes or coordinator replay
  history. Root-store legacy issuer migration remains separate from this ledger.

- Add opt-in authenticated verification-target retention with forward migration
  005; default issuance remains unchanged. This supplies exact-address removal
  storage without guessing targets in populated history. Revoked unused original
  reservations preserve noncommit recovery and terminal reconciliation without
  reactivation. Complete public removal orchestration remains required.

- Prepare exact native primary-email-change consumption without rewriting signed
  identifier purpose or retained replay custody. Verification-only/signup proofs
  cannot select it; the existing managed-family fence applies to both closed
  confirmation actions, and the sole identity transaction still owns all effects.

- Check selected email resend cooldown against actual committed family issuance
  creation time under the protected native transaction, never signed proof time.
  Missing family history and unavailable authority deny without another store.

- Add explicitly selected management mailbox supersession using the existing
  one-use family/recovery rows. The signed family conserves issuer, audience,
  tenant, recipient, identifier and confirmation action across fresh requests;
  malformed or substituted families deny. Older unused selected grants are
  invalidated only with committed replacement issuance. Install forward migration
  004 after 003; signup and unselected management shapes remain unchanged.

- Prepare original managed-email verification consumption under its distinct
  native schema. Reject signup/change aliases and preserve signed intent,
  envelope, expiry and retained replay-key identity. Preparation grants no
  mutation authority; existing transactional reservation/finalization owns use.

- Admit the closed anonymous password-signin origin for original MFA child
  issuance. Preserve the exact child ID, scope, expiry and encrypted custody;
  wrong schemas, authenticated-subject overrides and other operations deny.
  Protected password provenance and final MFA completion remain native owners.

- Keep prospective signup resends in the original mailbox/browser/policy
  supersession family despite newly prepared account IDs. Each token's full
  creation digest remains signed and independently checked at consumption;
  existing-recipient scope bytes are unchanged. Expire previously issued
  experimental prospective grants before adopting the corrected v2 family.

- Recover exact consumed magic-link parent provenance from an authenticated
  original MFA child without retaining or resubmitting the primary bearer.
  Match original command custody and the complete canonical reconstructed
  payload; preserve request identity and signed times without consumption or
  lifetime renewal. This is historical metadata, not factor/session authority.

- Prepare consumption of the exact original MFA child for closed anonymous
  factor-completion operations. Preserve signed purpose, envelope, expiry and
  retained replay identity; reject foreign profiles and scope/issuer overrides.
  Preparation does not verify a factor, consume a token or authorize a session.

- Add original MFA continuation issuance for the closed anonymous magic-link
  consumption profile. Preserve the challenge ID and exact encrypted retry
  custody; reject retargeting or lifetime expansion. Issuance is not completed
  MFA or session authority and still requires the kernel's protected staging.

- Preserve explicitly selected cryptographic limits when validating issued
  metadata, persisting payloads and restoring encrypted preparation custody.
  A profile admitted by its signer no longer fails an unrelated default
  caveat-count policy; narrower selected verification policies still deny.

- Add issuer-owned prospective signup-by-link custody with frozen creation and
  mailbox-policy binding, original encrypted restoration and distinct resend
  scope. Existing-recipient preparation rejects the prospective marker. Staging
  requires the kernel's native unused-recipient fence; request-time issuance
  creates no account or verification and does not authorize consumption.

- Use the public `signup-if-allowed` intent for magic-link supersession scopes;
  reject the noncontractual signup alias and keep signin scopes unchanged.

- Add bounded, opaque magic-link resend scope projection over the exact original
  browser flow and recipient. Replacement token IDs, times and observed authority
  versions do not change that scope. Projection alone grants no authorization;
  atomic supersession and workflow composition remain required separately.

- Add optional signed magic-link supersession metadata and a native transaction
  fence. New selected issuance invalidates earlier unused links in the same
  exact scope without erasing reserved command/generation recovery. Consumption
  serializes on that scope before row locks and rejects superseded evidence.
  Install migration 003 and acquire the native feature fence before account,
  factor or browser locks; legacy unselected scopes retain their interpretation.

- Authenticate original magic-link supersession status with complete signed
  issuance provenance in one primary read. Inspection denies invalidated links,
  while historical origin and recovery custody remain available. Foreign stored
  scopes and cancelled/unavailable reads expose no status or grant metadata.

- Prepare original magic-link consumption for the exact anonymous login command
  without rewriting its signed recipient or identifier scope. Preserve the
  authenticated envelope, exclusive expiry and retained replay-key version;
  reject foreign, reusable or terminal proof custody. Native login/session
  admission and atomic persistence remain required separately.

- Prepare one verified-email magic-link grant under its original anonymous
  request with a distinct kernel recipient fence and encrypted-custody binding.
  Preserve original bytes across retries/restoration without renewed disclosure;
  reset and signup profiles remain separate. Complete passwordless login and
  supersession/session composition remain workflow-owned.

- Reconcile absent native reset-request issuance under the original coordinator
  recovery fence only when grant, replay and originating-command identities are
  all absent. Conflicting rows remain unknown; ordinary/signup missing-evidence
  recovery retains its existing conservative behavior.

- Accept the original raw-input reset command when preparing consumption, so
  workflows can reserve the unchanged proof before authorized password hashing.
  Generated-command preparation retains the same scope and replay identity.

- Prepare one existing-recipient password-reset grant under the unchanged
  anonymous request, independently of signup selection. Bind that recipient in
  encrypted preparation custody, native issuance and recovery; ordinary/signup
  custody remains unchanged. Requires the reset-recipient kernel contract.
  Current recovery-factor policy and complete password/session effects remain
  owned by the password workflow.

- Prepare password-reset consumption from the exact paired original command,
  using configured proof verification and the trusted retained issuance replay
  key. Preserve original expiry and envelope without signing, transferring or
  consuming custody. Requires the reset-capable identity command contract;
  recovery eligibility and atomic password/session effects remain workflow-owned.

- Add purpose-explicit original issuance lookup and read-only issued-proof
  inspection for reset and other one-use workflows. Preserve original command,
  envelope and retained replay-key version; inspection never reserves, consumes
  or renews a proof. Registration readers retain their closed profile. Workflow
  scope and current account/factor/risk checks remain separately required.

- Validate original registration proofs without reservation or consumption.
  Require issued, unused, primary-unexpired state alongside authenticated
  provenance. Terminal or reserved proofs deny without sensitive projections;
  historical origin lookup remains available and does not imply usable authority.

- Add read-only anonymous registration confirmation consumption preparation.
  Match the current native email action and exact signed identifier while
  preserving the original identifier-verification purpose, envelope, expiry
  and replay version. Recheck configured crypto and reject session-profile
  substitution; durable matching and atomic mutation/use remain kernel-owned.

- Add bounded read-only registration-origin lookup from the authenticated
  opaque proof and exact original issuance. Preserve original replay-key
  versions across rotation and deny missing or mismatched evidence without
  consuming or renewing credentials. Existing APIs and storage remain compatible;
  current identity admission and atomic email confirmation remain separate.

- Add encrypted original-issuance checkpoints with bounded local verification
  and original command/generation/plan binding. Checkpointing transfers proof
  custody once; restoration permits transaction staging, never repeat delivery
  or replacement signing. Retained envelope, verification and replay keys are
  required for recovery. Existing issuance and transfer APIs remain supported.

- Add anonymous password-signup verification issuance for the exact new user
  registered in the same protected transaction. Preserve the original flow,
  command, fingerprint and generation while freezing the prospective token
  subject. Existing user-bound issuance and consumption stay unchanged. Adopt
  the matching kernel contract; old decoders cannot reconcile new signup plans.
  Complete password/email workflow orchestration and release gates stay pending.

- Add privacy-export consumption preparation that reauthenticates the original
  opaque proof and derives retained-key replay metadata without renewal or
  custody transfer. Another valid signed envelope cannot replace that proof.
  Adopt the additive identity privacy contract; legacy storage and identifier
  behavior remain compatible. Complete protected export admission stays pending.

- Add read-only identifier consumption preparation using configured proof
  verification and the retained original replay-key version. Consumers no
  longer derive replay digests; exact envelope matching prevents substitution.
  Durable reservation and atomic consumption remain coordinator-owned.

- Pin the native encrypted delivery adapters for original-issuance composition.
  Native worker processing preserves the original signed credential and erases
  terminal ciphertext; complete identity workflows and release gates remain
  pending.

- Add original subject-bound signed-token preparation with independent keyed
  replay identity and coordinator-only absent-to-issued persistence. A forward
  migration retains origin separately from consuming commands while preserving
  historical rows. Exact command replay does not resign; conflicting inserts
  never update or resurrect state. Prepared proof transfer is reveal-once
  encrypted-delivery admission, not synchronous disclosure or a commit receipt.
  Complete workflows, revocation/cleanup and release verification remain pending.

- Add coordinator-only provisional consumption and terminal finalization with
  exact current-generation binding and exclusive primary expiry checked after
  row-lock acquisition. Rollback restores unused custody; duplicate use and
  terminal-state reactivation conflict. Adopt the committed execution-handle
  dependency without changing installed migration bytes or the legacy store.
  This supersedes the prior unfinished consumption/finalization note below;
  issuance and complete authorized domain composition remain unfinished.

- Preserve the consumed authorization contracts when an application already
  requires the released v1.1.0 API by pinning the additive source above that
  release in Go's minimal version selection order.

- Add an optional identity Coordinator participant with durable exact-input
  reservation, predecessor-generation takeover, primary evidence and terminal
  non-commit release. Its additive independent schema preserves the legacy store
  and module dependency direction. Issuance, consumption/finalization and full
  workflow/release verification remain unfinished.
