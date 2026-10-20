package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// IssuerConfig pins signing/verification policy and a separate versioned replay
// key set. Replay keys must never be signing keys; deployment key custody owns
// that separation. Maps contain 1..32 nonzero unique keys and are copied. Keep
// every referenced version until bearer validation and retained authority no
// longer require it. Audience is one exact target, PreparationTimeout is 1..30s.
// Crypto collaborators must support concurrent bounded calls; Clock is local.
type IssuerConfig struct {
	// Crypto pins the trusted issuer, signing and verification policy and local clock.
	Crypto capability.ServiceConfig
	// Audience is the single exact audience admitted for every prepared grant.
	Audience string
	// CurrentReplayKeyVersion selects a nonzero retained key for new replay bindings.
	CurrentReplayKeyVersion uint32
	// RetainedReplayKeys holds 1..32 distinct nonzero keys, copied at construction.
	// Retain referenced versions for the full lifetime of original command recovery.
	RetainedReplayKeys map[uint32][32]byte
	// PreparationTimeout bounds each signing and verification phase to 1..30 seconds.
	PreparationTimeout time.Duration
	// RetainEmailVerificationTargets selects migration 005 and retains the
	// authenticated signed Resource for identifier verification. Enable before
	// issuing signup/management links when native email removal is selected.
	// False preserves the existing installation and issuance SQL contract.
	RetainEmailVerificationTargets bool
}

// Issuer prepares original signed credentials before the transaction, then
// inserts immutable metadata solely through coordinator-issued phase custody.
// It owns no pool, transaction, command result or provider. Immutable instances
// support concurrent commands; each prepared batch and Work is serial-use.
type Issuer struct {
	issuer              string
	service             capability.Service
	limits              capability.Limits
	audience            string
	current             uint32
	keys                map[uint32][32]byte
	timeout             time.Duration
	verificationTargets bool
}

// NewIssuer snapshots configuration without I/O. Zero keys, duplicate key
// material, unknown active version or invalid crypto policy fail closed.
func NewIssuer(c IssuerConfig) (*Issuer, error) {
	if c.CurrentReplayKeyVersion == 0 || len(c.RetainedReplayKeys) < 1 || len(c.RetainedReplayKeys) > 32 || !issuerText(c.Audience) || c.PreparationTimeout < time.Second || c.PreparationTimeout > 30*time.Second {
		return nil, invalid()
	}
	keys := make(map[uint32][32]byte, len(c.RetainedReplayKeys))
	for version, key := range c.RetainedReplayKeys {
		if version == 0 || key == ([32]byte{}) {
			return nil, invalid()
		}
		for _, existing := range keys {
			if key == existing {
				return nil, invalid()
			}
		}
		keys[version] = key
	}
	if keys[c.CurrentReplayKeyVersion] == ([32]byte{}) {
		return nil, invalid()
	}
	s, err := capability.NewService(c.Crypto)
	if err != nil {
		return nil, invalid()
	}
	return &Issuer{issuer: c.Crypto.Issuer, service: s, limits: c.Crypto.Limits, audience: c.Audience, current: c.CurrentReplayKeyVersion, keys: keys, timeout: c.PreparationTimeout, verificationTargets: c.RetainEmailVerificationTargets}, nil
}

// Descriptor identifies the separate capability.issuance v1 original producer.
// It does not grant permission to invoke any coordinator phase.
func (*Issuer) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}
}

type preparedIssuance struct {
	owner                *Issuer
	binding              identity.CommandBinding
	plan                 identitypostgres.CapabilityIssuancePlan
	grants               []capability.Grant
	proofs               []capability.Proof
	checkpointGeneration uint64
	checkpointWire       []byte
	checkpointOwner      *IssuancePreparationCodec
	checkpointStarted    bool
	preparationFailed    bool
}

// PreparedIssuance is original request-memory custody, not authorization or a
// commit receipt. All copies share the proofs' one-transfer lifetime. Plan
// snapshots are owned; no method exposes raw bearer strings or signing keys.
type PreparedIssuance struct{ state *preparedIssuance }

// Plan returns a defensive metadata-only declaration. Retain the same prepared
// batch across retries; never sign replacement credentials after unknown commit.
func (p PreparedIssuance) Plan() (identitypostgres.CapabilityIssuancePlan, error) {
	if p.state == nil || p.state.preparationFailed {
		return identitypostgres.CapabilityIssuancePlan{}, invalid()
	}
	v := p.state.plan
	v.Grants = append([]identitypostgres.CapabilityPlan(nil), v.Grants...)
	return v, nil
}

// Prepare creates 1..16 new random capability IDs, signs and authenticates each
// original envelope, and derives independent keyed replay metadata. Caller IDs,
// subjectless bearers, foreign subject/tenant, multiple/foreign audiences or
// non-one-use payloads fail. Exact purpose, resource, caveats and timestamps
// remain subject to core crypto policy. Whole-second UTC expiry is required.
// This bounded pre-transaction phase grants no authority and persists nothing.
// Caller input is borrowed only during the call. Failure destroys all acquired
// proof custody; collaborators' diagnostics/panics are redacted.
func (i *Issuer) Prepare(ctx context.Context, b identity.CommandBinding, inputs []capability.Payload) (out PreparedIssuance, err error) {
	return i.prepare(ctx, b, "", "", "", inputs)
}

func (i *Issuer) prepare(ctx context.Context, b identity.CommandBinding, registration, resetRecipient, magicLinkRecipient identity.UserID, inputs []capability.Payload) (out PreparedIssuance, err error) {
	plan := identitypostgres.CapabilityIssuancePlan{RegistrationUserID: registration, ResetRecipientUserID: resetRecipient, MagicLinkRecipientUserID: magicLinkRecipient}
	return i.preparePlan(ctx, b, plan, inputs, false)
}

func (i *Issuer) preparePlan(ctx context.Context, b identity.CommandBinding, plan identitypostgres.CapabilityIssuancePlan, inputs []capability.Payload, fixedChallengeID bool) (out PreparedIssuance, err error) {
	registration, resetRecipient, magicLinkRecipient, mfaSubject := plan.RegistrationUserID, plan.ResetRecipientUserID, plan.MagicLinkRecipientUserID, plan.MFAContinuationUserID
	subject, valid := issuerPlanSubject(b, plan)
	if i == nil || i.service == nil || ctx == nil || !valid || len(inputs) == 0 || len(inputs) > 16 || (resetRecipient != "" || magicLinkRecipient != "" || mfaSubject != "") && len(inputs) != 1 || fixedChallengeID != (mfaSubject != "") {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	if err = issuerContext(ctx); err != nil {
		return out, err
	}
	plan.Contributor = i.Descriptor()
	p := &preparedIssuance{owner: i, binding: b, plan: plan}
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			out = PreparedIssuance{}
		}
		if err != nil {
			for _, proof := range p.proofs {
				_ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			}
		}
	}()
	for _, v := range inputs {
		if !fixedChallengeID && v.ID != "" || fixedChallengeID && !mfaIssuancePayload(v) || v.Subject != string(subject) || registration != "" && v.Operation != "identity.identifier.verify" || resetRecipient != "" && v.Operation != "identity.password.reset-complete" || magicLinkRecipient != "" && v.Operation != "identity.magic-link.consume" || v.Tenant != string(b.TenantID) || v.Bearer || v.MaxUses != 1 || len(v.Audiences) != 1 || v.Audiences[0] != i.audience || v.ExpiresAt.Location() != time.UTC || v.ExpiresAt.Nanosecond() != 0 || v.ExpiresAt.Unix() <= 0 {
			return out, invalid()
		}
		if _, e := i.verificationTarget(v); e != nil {
			return out, e
		}
		if !fixedChallengeID {
			id, e := identity.NewSubjectID()
			if e != nil {
				return out, identity.UnavailableError{}
			}
			v.ID = string(id)
		}
		proof, _, e := i.service.Issue(ctx, v)
		if e != nil {
			return out, issuerFailure(ctx)
		}
		p.proofs = append(p.proofs, proof)
		grant, e := i.service.Verify(ctx, proof, capability.Purpose(v.Operation), i.audience)
		if e != nil {
			return out, issuerFailure(ctx)
		}
		cp, e := i.grantPlan(b, subject, grant, i.current)
		if e != nil {
			return out, e
		}
		p.grants = append(p.grants, grant)
		p.plan.Grants = append(p.plan.Grants, cp)
	}
	if err = issuerContext(ctx); err != nil {
		return out, err
	}
	return PreparedIssuance{state: p}, nil
}

// PrepareRegistration prepares new-user verification under the unchanged
// original anonymous signup command. Preparation grants no creation authority;
// staging still requires the kernel's same-Work registration of this exact user.
func (i *Issuer) PrepareRegistration(ctx context.Context, b identity.CommandBinding, user identity.UserID, inputs []capability.Payload) (PreparedIssuance, error) {
	if user == "" {
		return PreparedIssuance{}, invalid()
	}
	return i.prepare(ctx, b, user, "", "", inputs)
}

// PrepareResetRecipient prepares exactly one reset-complete grant for an
// existing user under the unchanged anonymous password-reset-request command.
// The bounded, pre-transaction call grants no recovery eligibility, performs no
// SQL and does not prove current account, credential or factor authority. The
// kernel requires this exact recipient's primary fence before staging; the
// workflow owns the complete reset profile and current recovery-factor policy.
// Retain the returned original custody across retries and unknown outcomes.
func (i *Issuer) PrepareResetRecipient(ctx context.Context, b identity.CommandBinding, user identity.UserID, input capability.Payload) (PreparedIssuance, error) {
	if user == "" {
		return PreparedIssuance{}, invalid()
	}
	return i.prepare(ctx, b, "", user, "", []capability.Payload{input})
}

// PrepareMagicLinkRecipient prepares exactly one magic-link consume grant for
// an existing recipient under the unchanged anonymous magic-link request. This
// bounded pre-transaction call signs original custody but grants no current
// eligibility, authentication or factor permission. The kernel requires its
// same-invocation primary verified-email fence and exact signed recipient scope
// before staging. The native workflow owns original flow, callback and factor/
// risk policy. Retain original custody across retries and unknown outcomes;
// encrypted preparation restoration never renews bearer disclosure or expiry.
func (i *Issuer) PrepareMagicLinkRecipient(ctx context.Context, b identity.CommandBinding, user identity.UserID, input capability.Payload) (PreparedIssuance, error) {
	if _, prospective := input.Caveats["magiclink.prospective"]; prospective {
		return PreparedIssuance{}, invalid()
	}
	if user == "" {
		return PreparedIssuance{}, invalid()
	}
	return i.prepare(ctx, b, "", "", user, []capability.Payload{input})
}

// PrepareMagicLinkProspectiveRecipient signs exactly one prospective signup
// grant under the original anonymous request, without creating an account or
// proving mailbox possession. Its explicit profile binds future creation and
// policy; kernel staging still requires the same invocation's unused-recipient
// fence. Preserve returned original custody across retries and recovery. This
// bounded call performs no SQL or delivery and renews no stored validity.
func (i *Issuer) PrepareMagicLinkProspectiveRecipient(ctx context.Context, b identity.CommandBinding, user identity.UserID, input capability.Payload) (PreparedIssuance, error) {
	if user == "" || !prospectiveMagicLinkProfile(input) {
		return PreparedIssuance{}, invalid()
	}
	return i.prepare(ctx, b, "", "", user, []capability.Payload{input})
}

// TransferForDelivery irreversibly transfers one proof only to synchronous
// authenticated encryption admission, never to a sender or response before
// commit. The trusted workflow owns that destination. Aliases are invalidated
// before the callback and borrowed bytes cleared after all exits. It is not a
// synchronous reveal API, a transport receipt or permission to retry disclosure.
func (p PreparedIssuance) TransferForDelivery(ctx context.Context, index uint16, encrypt func(context.Context, []byte) error) error {
	if p.state == nil || p.state.checkpointStarted || p.state.preparationFailed || int(index) >= len(p.state.proofs) {
		return invalid()
	}
	return p.state.proofs[index].Transfer(ctx, encrypt)
}

// Stage binds immutable original grants to this exact owner in the admitted
// original command. It neither signs, persists nor exposes bearer bytes.
func (i *Issuer) Stage(ctx context.Context, w identitypostgres.Work, p PreparedIssuance) error {
	if i == nil || i.service == nil || ctx == nil || p.state == nil || p.state.preparationFailed || p.state.owner != i {
		return invalid()
	}
	if err := issuerContext(ctx); err != nil {
		return err
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	if b != p.state.binding {
		return invalid()
	}
	for index, grant := range p.state.grants {
		if err := w.StageCapabilityIssuanceFor(i, uint16(index), grant); err != nil {
			return err
		}
	}
	return nil
}

// ValidateCapabilityIssuance checks retained-key and metadata shape without I/O.
// Exact cryptographic provenance is rederived from Grants in the sealed phase.
func (i *Issuer) ValidateCapabilityIssuance(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) error {
	_, valid := issuerPlanSubject(b, p)
	if i == nil || i.service == nil || !valid || p.Contributor != i.Descriptor() || len(p.Grants) == 0 || len(p.Grants) > 16 || (p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "") && len(p.Grants) != 1 {
		return invalid()
	}
	for n, v := range p.Grants {
		if p.RegistrationUserID != "" && v.Purpose != "identity.identifier.verify" || p.ResetRecipientUserID != "" && v.Purpose != "identity.password.reset-complete" || p.MagicLinkRecipientUserID != "" && v.Purpose != "identity.magic-link.consume" || p.MFAContinuationUserID != "" && v.Purpose != "identity.mfa.complete" {
			return invalid()
		}
		if i.keys[v.ReplayKeyVersion] == ([32]byte{}) || v.MaxUses != 1 || v.ProofFingerprint == ([32]byte{}) || v.ExpiresAt.Location() != time.UTC || v.ExpiresAt.Nanosecond() != 0 || v.ExpiresAt.Unix() <= 0 {
			return invalid()
		}
		if _, err := capability.NewReference(v.CapabilityID, v.Purpose, v.ReplayDigest, v.ExpiresAt); err != nil {
			return invalid()
		}
		for _, prior := range p.Grants[:n] {
			if prior.CapabilityID == v.CapabilityID || prior.ReplayKeyVersion == v.ReplayKeyVersion && prior.ReplayDigest == v.ReplayDigest {
				return invalid()
			}
		}
	}
	return nil
}

func (i *Issuer) grantPlan(b identity.CommandBinding, subject identity.UserID, g capability.Grant, version uint32) (identitypostgres.CapabilityPlan, error) {
	v := g.Payload()
	digest := g.EnvelopeDigest()
	key := i.keys[version]
	if key == ([32]byte{}) || digest == ([32]byte{}) || v.Subject != string(subject) || v.Tenant != string(b.TenantID) || v.Bearer || v.MaxUses != 1 || len(v.Audiences) != 1 || v.Audiences[0] != i.audience || v.ExpiresAt.Location() != time.UTC || v.ExpiresAt.Nanosecond() != 0 {
		return identitypostgres.CapabilityPlan{}, invalid()
	}
	if _, err := capability.CanonicalPayload(v, i.limits); err != nil {
		return identitypostgres.CapabilityPlan{}, invalid()
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("golib/capability/identity-replay/v1\x00"))
	var framed [4]byte
	for _, field := range []string{v.Tenant, v.Operation} {
		size := len(field)
		if size < 1 || size > 128 {
			return identitypostgres.CapabilityPlan{}, invalid()
		}
		binary.BigEndian.PutUint32(framed[:], uint32(size))
		_, _ = mac.Write(framed[:])
		_, _ = mac.Write([]byte(field))
	}
	_, _ = mac.Write(digest[:])
	var replay [32]byte
	copy(replay[:], mac.Sum(nil))
	return identitypostgres.CapabilityPlan{CapabilityID: v.ID, Purpose: capability.Purpose(v.Operation), ReplayKeyVersion: version, ReplayDigest: replay, ProofFingerprint: digest, ExpiresAt: v.ExpiresAt, MaxUses: 1}, nil
}

// PersistCapabilityIssuance authenticates every frozen envelope/replay binding
// before absent-to-issued inserts. Primary time and all origin fields are part
// of the coordinator transaction. Conflict never updates or resurrects a row.
// The method retains no handle, calls no signer/provider and closes no transaction.
func (i *Issuer) PersistCapabilityIssuance(ctx context.Context, w identitypostgres.CapabilityIssuanceWork) error {
	if i == nil || i.service == nil || ctx == nil {
		return invalid()
	}
	if err := issuerContext(ctx); err != nil {
		return err
	}
	b, err := w.Binding(i)
	if err != nil {
		return err
	}
	if err := i.ValidateCapabilityIssuance(b.Command, b.Plan); err != nil {
		return err
	}
	subject, _ := issuerPlanSubject(b.Command, b.Plan)
	grants, err := w.Grants(i)
	if err != nil {
		return err
	}
	if len(grants) != len(b.Plan.Grants) {
		return invalid()
	}
	for n, g := range grants {
		if b.Plan.MFAContinuationUserID != "" && !mfaIssuancePayload(g.Payload()) {
			return invalid()
		}
		expected, err := i.grantPlan(b.Command, subject, g, b.Plan.Grants[n].ReplayKeyVersion)
		if err != nil || expected != b.Plan.Grants[n] {
			return invalid()
		}
		if encoded, selected := g.Payload().Caveats["magiclink.supersession"]; selected {
			scope, scopeErr := MagicLinkScopeFromPayload(g.Payload())
			if b.Plan.MagicLinkRecipientUserID == "" || b.Command.OperationID != "identity.magic-link.request" || scopeErr != nil || encoded != fmt.Sprintf("%x", scope.digest) {
				return invalid()
			}
		}
		if _, selected := g.Payload().Caveats["email.supersession"]; selected {
			v := g.Payload()
			_, scopeErr := ManagedEmailScopeFromPayload(v)
			action := b.Command.OperationID
			schema := b.Command.SchemaID
			native := schema == action+".native-v1" || action == "identity.email.verification-send" && schema == action+".resend-v1"
			confirm := "identity.email.verification-confirm"
			if action == "identity.email.change-request" {
				confirm = "identity.email.change-confirm"
			}
			if scopeErr != nil || (action != "identity.email.verification-send" && action != "identity.email.change-request") || !native || b.Command.SchemaVersion != 1 || b.Command.UserID == "" || string(b.Command.ActorID) != string(b.Command.UserID) || b.Command.ActorKind != "user" || v.Resource != b.Command.RecordID || v.Caveats["email.confirm_operation"] != confirm {
				return invalid()
			}
		}
	}
	for n, g := range grants {
		v := g.Payload()
		target, err := i.verificationTarget(v)
		if err != nil {
			return err
		}
		canonical, err := capability.CanonicalPayload(v, i.limits)
		if err != nil {
			return invalid()
		}
		digest := sha256.Sum256(canonical)
		clear(canonical)
		cp := b.Plan.Grants[n]
		args := inputArgs(identitypostgres.CapabilityReservationBinding{Command: b.Command, Plan: cp})
		args = append(args, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), string(subject), v.IssuedAt, v.NotBefore, g.Header().KeyID, digest[:])
		sql := issueSQL
		if target != "" {
			sql = issueVerificationTargetSQL
			args = append(args, string(target))
		}
		count, err := w.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if count != 1 {
			return identity.ConflictError{}
		}
		if encoded, selected := v.Caveats["magiclink.supersession"]; selected {
			scope, err := MagicLinkScopeFromPayload(v)
			if err != nil || encoded != fmt.Sprintf("%x", scope.digest) {
				return invalid()
			}
			if err := persistMagicLinkSupersession(ctx, string(b.Command.TenantID), string(b.Command.CommandID), cp.CapabilityID, scope, w.Exec); err != nil {
				return err
			}
		}
		if _, selected := v.Caveats["email.supersession"]; selected {
			scope, err := ManagedEmailScopeFromPayload(v)
			if err != nil {
				return invalid()
			}
			if err := persistManagedEmailSupersession(ctx, string(b.Command.TenantID), string(b.Command.CommandID), cp.CapabilityID, scope, w.Exec); err != nil {
				return err
			}
		}
	}
	return nil
}

// RecoverParticipant reads original issuance evidence under the coordinator's
// frozen prior generation. Missing, partial or conflicting ordinary/signup
// rows remain unknown. The exact single-grant reset-request profile can prove
// non-commit only when neither original identity nor replay identity nor any
// grant of that originating command exists under the coordinator recovery
// fence. No expiry, timeout or consuming state is rewritten as rollback.
func (i *Issuer) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if i == nil || i.service == nil || ctx == nil {
		return identitypostgres.RecoveryUnknown, invalid()
	}
	b, err := w.CapabilityIssuanceBinding(i)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	if err := i.ValidateCapabilityIssuance(b.Command, b.Plan); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	subject, _ := issuerPlanSubject(b.Command, b.Plan)
	for _, cp := range b.Plan.Grants {
		args := inputArgs(identitypostgres.CapabilityReservationBinding{Command: b.Command, Plan: cp})
		args = append(args, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), string(subject))
		rows, err := w.Query(ctx, issuanceStatusSQL, args...)
		if err != nil {
			return identitypostgres.RecoveryUnknown, err
		}
		found := rows.Next()
		if found {
			var one int
			err = rows.Scan(&one)
			if err == nil && (one != 1 || rows.Next()) {
				err = identity.UnavailableError{}
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return identitypostgres.RecoveryUnknown, err
		}
		if !found {
			if b.Plan.ResetRecipientUserID != "" || b.Plan.MagicLinkRecipientUserID != "" || b.Plan.MFAContinuationUserID != "" {
				return i.recoverAbsentRecipientIssuance(ctx, w, b.Command, cp)
			}
			return identitypostgres.RecoveryUnknown, nil
		}
	}
	return identitypostgres.RecoveryCommitted, nil
}

// RecoveryWork excludes the old command writer and relevant tenant mutation.
// A nonmatching retained row is conflicting evidence, never absence. This
// bounded primary read neither deletes issuance nor releases a consuming proof.
// Native reset and magic-link request each have one frozen grant. Absence proves
// producer performed no durable mutation; every other owner still votes itself.
func (i *Issuer) recoverAbsentRecipientIssuance(ctx context.Context, w identitypostgres.RecoveryWork, b identity.CommandBinding, cp identitypostgres.CapabilityPlan) (identitypostgres.RecoveryStatus, error) {
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3) OR EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose=$2 AND replay_key_version=$4 AND replay_digest=$5) OR EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$6)`, string(b.TenantID), string(cp.Purpose), cp.CapabilityID, int64(cp.ReplayKeyVersion), cp.ReplayDigest[:], string(b.CommandID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	defer rows.Close()
	var present bool
	if !rows.Next() || rows.Scan(&present) != nil || rows.Next() || rows.Err() != nil {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if present {
		return identitypostgres.RecoveryUnknown, nil
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

func issuerText(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for n := range len(v) {
		if v[n] < 0x21 || v[n] > 0x7e {
			return false
		}
	}
	return true
}
func issuerBinding(b identity.CommandBinding) bool {
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	return err == nil && len(id) == 16 && base64.RawURLEncoding.EncodeToString(id) == string(b.CommandID) && issuerText(string(b.UserID)) && issuerText(string(b.TenantID))
}

// Subject selection changes only the prospective credential, never its original
// command scope. The kernel independently proves actual same-Work registration.
func issuerSubject(b identity.CommandBinding, registration identity.UserID) (identity.UserID, bool) {
	if registration == "" {
		return b.UserID, issuerBinding(b)
	}
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if b.OperationID == "identity.username.signup" {
		op.Owner, op.OperationID, op.SchemaID = "identity/username", "identity.username.signup", "username-signup"
	}
	return registration, issuerText(string(registration)) && b.UserID == "" && b.AnonymousFlowID != "" && b.ValidateFor(op) == nil
}

// Reset selection is not a general anonymous subject override. Keep signup's
// historical rules intact and bind the independent existing-recipient profile.
func issuerPlanSubject(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) (identity.UserID, bool) {
	if p.MFAContinuationUserID != "" {
		if b.OperationID == "identity.email.verification-signin" {
			return p.MFAContinuationUserID, p.RegistrationUserID == "" && p.ResetRecipientUserID == "" && p.MagicLinkRecipientUserID == "" && verificationMFAIssuerBinding(b, p.MFAContinuationUserID)
		}
		op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
		if b.OperationID == "identity.password.signin" {
			op.Owner, op.OperationID, op.SchemaID = "identity/password", "identity.password.signin", "password-signin"
		}
		if b.OperationID == "identity.username.signin" {
			op.Owner, op.OperationID, op.SchemaID = "identity/username", "identity.username.signin", "username-signin"
		}
		if b.OperationID == "identity.phone.password-signin" {
			op.Owner, op.OperationID, op.SchemaID = "identity/phone", "identity.phone.password-signin", "phone-password-signin"
		}
		return p.MFAContinuationUserID, p.RegistrationUserID == "" && p.ResetRecipientUserID == "" && p.MagicLinkRecipientUserID == "" && issuerText(string(p.MFAContinuationUserID)) && b.UserID == "" && b.AnonymousFlowID != "" && b.ValidateFor(op) == nil
	}
	if p.MagicLinkRecipientUserID != "" {
		op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.request", SchemaID: "magic-link-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
		return p.MagicLinkRecipientUserID, p.RegistrationUserID == "" && p.ResetRecipientUserID == "" && issuerText(string(p.MagicLinkRecipientUserID)) && b.UserID == "" && b.AnonymousFlowID != "" && b.ValidateFor(op) == nil
	}
	if p.ResetRecipientUserID == "" {
		return issuerSubject(b, p.RegistrationUserID)
	}
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	return p.ResetRecipientUserID, p.RegistrationUserID == "" && issuerText(string(p.ResetRecipientUserID)) && b.UserID == "" && b.AnonymousFlowID != "" && b.ValidateFor(op) == nil
}
func issuerContext(ctx context.Context) error {
	if ctx.Err() == context.Canceled {
		return identity.CancelledError{}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return identity.DeadlineExceededError{}
	}
	return nil
}
func issuerFailure(ctx context.Context) error {
	if err := issuerContext(ctx); err != nil {
		return err
	}
	return identity.UnavailableError{}
}

// Format hides keys, bearer custody and correlation metadata.
func (*Issuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.Issuer(redacted)"))
}

// MarshalJSON rejects serialization of signing and replay configuration.
func (*Issuer) MarshalJSON() ([]byte, error) { return nil, invalid() }

// Format hides prepared credential custody and immutable metadata.
func (PreparedIssuance) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.PreparedIssuance(redacted)"))
}

// MarshalJSON rejects serialization of prepared credential custody.
func (PreparedIssuance) MarshalJSON() ([]byte, error) { return nil, invalid() }

const issueSQL = `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::numeric,$12,$13,$14,$15,$16,clock_timestamp() WHERE $7>clock_timestamp() AND $13<=clock_timestamp() AND $14<=clock_timestamp() ON CONFLICT DO NOTHING`
const issuanceStatusSQL = `SELECT 1 FROM public.capability_identity_one_use WHERE ` + issuedInputSQL + ` AND origin_command_id=$9 AND origin_fingerprint=$10 AND origin_generation=$11::numeric AND subject_id=$12 FOR UPDATE`

var _ identitypostgres.CapabilityIssuanceContributor = (*Issuer)(nil)
