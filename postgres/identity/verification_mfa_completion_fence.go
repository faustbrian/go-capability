package identitycapability

import (
	"context"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireVerificationMFATOTPParent repeats original parent/child custody under
// the exact native TOTP owner's preparation, Apply or final-check Work. Parent
// must come from ReadMFAVerificationParent and be matched to the owner's actual
// continuation before this call. This read-only fence neither authenticates a
// factor nor consumes the child. It locks original confirmation and challenge
// history and both grants until the caller's sole transaction closes; original
// expiry cannot be renewed. Foreign/returned handles and changed custody deny.
// Every error must abort the protected operation. All IO retains the earlier
// caller deadline and issuer timeout; rows are closed on every path.
func (i *Issuer) RequireVerificationMFATOTPParent(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, parent MFAVerificationParent) error {
	if ctx == nil || i == nil || owner == nil {
		return invalid()
	}
	b, f, life, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	if err != nil || !ok || !cookie || !code || s.Binding != b || !verificationTOTPParentOperation(f.Operation) || s.Operation != f.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || life.EventType != "session.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 0 {
		return identity.ForbiddenError{}
	}
	return i.requireVerificationMFATOTPParent(ctx, w, b, parent)
}

// RequireVerificationMFATOTPParentAttempt applies the same immutable parent
// fence in the sealed counted-attempt callback, before code comparison or debit.
// The live callback's frozen child and subject must match opaque parent custody.
// This cannot charge an attempt, consume a factor or create a session. Copies
// share the caller's bounded transaction lifetime and every error must propagate.
func (i *Issuer) RequireVerificationMFATOTPParentAttempt(ctx context.Context, w kernel.MFATOTPAttemptWork, owner kernel.MFATOTPAttemptContributor, parent MFAVerificationParent) error {
	if ctx == nil || i == nil || owner == nil {
		return invalid()
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	command, err := w.NativeCommand(owner)
	if err != nil {
		return err
	}
	s, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	p := parent.original
	if !ok || !cookie || !code || s.Binding != b.Command || !verificationTOTPParentOperation(s.Operation) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || string(b.Plan.ID) != p.child.id || b.Plan.UserID != p.bindings.UserID {
		return identity.ForbiddenError{}
	}
	return i.requireVerificationMFATOTPParent(ctx, w, b.Command, parent)
}

func verificationTOTPParentOperation(op identity.FeatureOperation) bool {
	return op == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow})
}

type verificationParentQuery interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
}

func (i *Issuer) requireVerificationMFATOTPParent(ctx context.Context, q verificationParentQuery, b identity.CommandBinding, parent MFAVerificationParent) error {
	p := parent.original
	v := p.bindings
	c := p.child
	if !p.valid || p.issuer != i.issuer || p.audience != i.audience || b.TenantID != v.TenantID || b.CommandID == p.challenge || b.CommandID == v.PrimaryCommandID || b.CommandID == v.RequestCommandID || c.id == "" || c.envelope == ([32]byte{}) || c.payload == ([32]byte{}) || p.parentEnvelope == ([32]byte{}) || p.payload == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	confirmation, err := base64.RawURLEncoding.Strict().DecodeString(string(v.PrimaryCommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(string(p.challenge))
	if err != nil {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, i.timeout)
	defer stop()
	rows, err := q.Query(bounded, `SELECT 1 FROM public.capability_identity_one_use c
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.purpose='identity.email.verification-signin' AND j.command_id=$4
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
JOIN identity.commands v ON v.tenant_id=c.tenant_id AND v.purpose='identity.email.verification-confirm' AND v.command_id=$5
JOIN identity.identity_command_id_claims vk ON vk.command_id=v.command_id AND vk.tenant_id=v.tenant_id AND vk.purpose=v.purpose
JOIN public.capability_identity_one_use p ON p.tenant_id=c.tenant_id AND p.purpose='identity.identifier.verify' AND p.capability_id=$6 AND p.subject_id=c.subject_id
WHERE c.tenant_id=$1 AND c.purpose='identity.mfa.complete' AND c.capability_id=$2 AND c.subject_id=$3
 AND c.origin_command_id=$7 AND c.origin_fingerprint=k.fingerprint AND c.origin_generation=j.generation
 AND j.state='committed' AND NOT k.retired AND v.state='committed' AND NOT vk.retired
 AND c.proof_fingerprint=$8 AND c.payload_digest=$9 AND c.signed_issued_at=$10 AND c.signed_not_before=$10 AND c.expires_at=$11
 AND c.expires_at>clock_timestamp() AND c.superseded_by_command_id IS NULL
 AND (c.state='issued' OR (c.state IN ('reserved','finalized') AND c.command_id=$12))
 AND p.origin_command_id=$13 AND p.command_id=$14 AND p.command_fingerprint=vk.fingerprint AND p.generation=v.generation
 AND p.proof_fingerprint=$15 AND p.payload_digest=$16 AND p.signed_issued_at=$17 AND p.signed_not_before=$18 AND p.expires_at=$19
 AND p.expires_at>clock_timestamp() AND p.expires_at>=c.expires_at AND p.superseded_by_command_id IS NULL
 AND p.state='finalized' AND p.uses=p.max_uses AND p.max_uses=1
FOR SHARE OF c,p,j,k,v,vk`, string(v.TenantID), c.id, string(v.UserID), challenge, confirmation, v.CapabilityID, string(p.challenge), c.envelope[:], c.payload[:], c.issued, c.expires, string(b.CommandID), string(v.RequestCommandID), string(v.PrimaryCommandID), p.parentEnvelope[:], p.payload[:], v.IssuedAt, v.NotBefore, v.ExpiresAt)
	if err != nil {
		return issuerFailure(bounded)
	}
	defer rows.Close()
	var one int
	if !rows.Next() || rows.Scan(&one) != nil || one != 1 || rows.Next() || rows.Err() != nil {
		if bounded.Err() != nil {
			return issuerFailure(bounded)
		}
		return identity.ForbiddenError{}
	}
	return bounded.Err()
}
