package identitycapability

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// MFAVerificationParentBindings is historical provenance for three distinct
// commands: original signup issuance, committed verification, and subsequent MFA
// challenge. It conveys no current authentication, factor or session authority.
type MFAVerificationParentBindings struct {
	// TenantID is the tenant shared by the original parent and MFA child.
	TenantID identity.TenantID
	// UserID is their authenticated original recipient, not current authority.
	UserID identity.UserID
	// CapabilityID identifies the already-consumed registration grant.
	CapabilityID string
	// RequestCommandID identifies the original signup issuance.
	RequestCommandID identity.CommandID
	// VerificationCommandID identifies the separately committed parent use.
	VerificationCommandID identity.CommandID
	// ChallengeCommandID identifies the subsequent pending MFA issuance.
	ChallengeCommandID identity.CommandID
	// ReplayKeyVersion retains the parent's original replay-key identity.
	ReplayKeyVersion uint32
	// IssuedAt is the original parent grant's signed issuance time.
	IssuedAt time.Time
	// NotBefore is its original signed lower validity bound.
	NotBefore time.Time
	// ExpiresAt is its original signed deadline, never renewed by this read.
	ExpiresAt time.Time
}

// MFAVerificationParent owns opaque original-payload custody. It cannot be used
// as a magic-link parent or manufactured from projected bindings. Zero denies;
// immutable copies support concurrent local matching and retain no bearer.
type MFAVerificationParent struct{ original MFAMagicLinkParent }

// Bindings projects exact committed-parent routing and original deadlines.
// Projections cannot reconstruct payload custody or authorize factor completion.
func (p MFAVerificationParent) Bindings() (MFAVerificationParentBindings, error) {
	b, err := p.original.Bindings()
	if err != nil {
		return MFAVerificationParentBindings{}, err
	}
	return MFAVerificationParentBindings{TenantID: b.TenantID, UserID: b.UserID, CapabilityID: b.CapabilityID, RequestCommandID: b.RequestCommandID, VerificationCommandID: b.PrimaryCommandID, ChallengeCommandID: p.original.challenge, ReplayKeyVersion: b.ReplayKeyVersion, IssuedAt: b.IssuedAt, NotBefore: b.NotBefore, ExpiresAt: b.ExpiresAt}, nil
}

// MatchPayload requires exact canonical reconstruction of the original issued
// registration-verification grant, including all native signup/callback caveats.
// It performs no signing, disclosure, IO, consumption or validity renewal. The
// native completion owner must repeat live account, browser and factor fences.
func (p MFAVerificationParent) MatchPayload(v capability.Payload) error {
	return p.original.matchPayload(v, "identity.identifier.verify")
}

// ReadMFAVerificationParent authenticates the child and its already-consumed
// registration grant without recovering a reusable primary bearer. Parent
// identity/digest/expiry must come from the authenticated durable continuation.
// The signed child's correlation identifies the separate confirmation command;
// its exact committed journal fingerprint/generation must match consumption.
// The native owner separately checks the challenge journal's declared parent.
// Earlier caller deadlines and the issuer timeout bound all primary reads.
// Borrowed pool/child remain caller-owned; errors return zero redacted custody.
// No callback, goroutine, signing, consumption or freshness renewal occurs.
func (i *Issuer) ReadMFAVerificationParent(ctx context.Context, pool *database.Pool, child capability.Proof, parentID string, parentEnvelope [32]byte, parentExpiry time.Time) (MFAVerificationParent, error) {
	p, err := i.readMFAParent(ctx, pool, child, parentID, parentEnvelope, parentExpiry, true)
	if err != nil {
		return MFAVerificationParent{}, err
	}
	return MFAVerificationParent{original: p}, nil
}

// Format redacts correlated parent custody.
func (MFAVerificationParent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.MFAVerificationParent(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (MFAVerificationParent) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit textual custody export.
func (MFAVerificationParent) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts structured diagnostics.
func (MFAVerificationParent) LogValue() slog.Value {
	return slog.StringValue("identitycapability.MFAVerificationParent(redacted)")
}

// Verification consumes the parent before the challenge exists. Its immutable
// receipt must be proven independently; comparing parent use to child issuance
// would incorrectly invent same-transaction consumption as in magic-link login.
const mfaVerificationParentSQL = `SELECT p.origin_command_id,p.replay_key_version,p.signed_issued_at,p.signed_not_before,p.expires_at,p.payload_digest,p.supersession_scope
FROM public.capability_identity_one_use c
JOIN identity.commands v ON v.tenant_id=c.tenant_id AND v.purpose='identity.email.verification-confirm' AND v.command_id=$12
JOIN identity.identity_command_id_claims k ON k.command_id=v.command_id AND k.tenant_id=v.tenant_id AND k.purpose=v.purpose
JOIN public.capability_identity_one_use p ON p.tenant_id=c.tenant_id
 AND p.purpose='identity.identifier.verify' AND p.capability_id=$4
 AND p.subject_id=c.subject_id AND p.command_id=$13
 AND p.command_fingerprint=k.fingerprint AND p.generation=v.generation
WHERE c.tenant_id=$1 AND c.purpose='identity.mfa.complete' AND c.capability_id=$2
 AND c.origin_command_id=$3 AND c.subject_id=$5 AND c.proof_fingerprint=$6
 AND c.payload_digest=$7 AND c.state IN ('issued','finalized')
 AND c.signed_issued_at=$8 AND c.signed_not_before=$8 AND c.expires_at=$9
 AND c.expires_at>clock_timestamp()
 AND v.state='committed' AND NOT k.retired
 AND p.proof_fingerprint=$10 AND p.expires_at=$11 AND p.expires_at>=c.expires_at
 AND p.expires_at>clock_timestamp() AND p.signed_issued_at<=c.signed_issued_at
 AND p.signed_not_before<=c.signed_issued_at
 AND p.state='finalized' AND p.uses=p.max_uses AND p.max_uses=1
 AND p.origin_command_id IS NOT NULL AND p.origin_command_id<>c.origin_command_id
 AND p.superseded_by_command_id IS NULL`
