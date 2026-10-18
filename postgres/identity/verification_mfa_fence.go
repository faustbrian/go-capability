package identitycapability

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireVerificationMFAParent fences the genuine registration grant consumed
// by the separately committed confirmation. It is read-only and available only
// to the exact native email challenge participant during preparation, Apply or
// final admission. Grant must be actual verified capability custody; original
// signup and confirmation come from authenticated native history, never a client
// assertion. The row and confirmation journal must retain their exact original
// fingerprint/generation. This neither consumes again nor grants factor/session
// authority. Locks share the caller's sole Work; every error must propagate.
func (i *Issuer) RequireVerificationMFAParent(ctx context.Context, w kernel.Work, owner kernel.EmailVerificationMFAChallengeContributor, grant capability.Grant, signup identity.CommandID) error {
	if ctx == nil || i == nil || owner == nil {
		return invalid()
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || f.Operation.OperationID != "identity.email.verification-signin" || f.Operation.Owner != "identity/email" || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || life.EventType != "mfa.challenge.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return invalid()
	}
	if _, err := identity.ParseCommandID(string(signup)); err != nil {
		return invalid()
	}
	confirmation, err := identity.ParseCommandID(b.RecordID)
	if err != nil || confirmation == b.CommandID || confirmation == signup {
		return invalid()
	}
	v := grant.Payload()
	if !registrationOriginProfile(v) || v.Operation != "identity.identifier.verify" || grant.EnvelopeDigest() == ([32]byte{}) || v.Tenant != string(b.TenantID) || v.Subject != string(b.UserID) || v.Issuer != i.issuer {
		return identity.ForbiddenError{}
	}
	wire, err := capability.CanonicalPayload(v, i.limits)
	defer clear(wire)
	if err != nil {
		return identity.ForbiddenError{}
	}
	digest, envelope := sha256.Sum256(wire), grant.EnvelopeDigest()
	confirmationBytes, _ := base64.RawURLEncoding.Strict().DecodeString(string(confirmation))
	bounded, stop := context.WithTimeout(ctx, i.timeout)
	defer stop()
	rows, err := w.Query(bounded, `SELECT 1 FROM public.capability_identity_one_use p
JOIN identity.commands j ON j.tenant_id=p.tenant_id AND j.purpose='identity.email.verification-confirm' AND j.command_id=$4
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
WHERE p.tenant_id=$1 AND p.purpose='identity.identifier.verify' AND p.capability_id=$2 AND p.subject_id=$3
 AND p.origin_command_id=$5 AND p.command_id=$6 AND p.command_fingerprint=k.fingerprint AND p.generation=j.generation
 AND j.state='committed' AND NOT k.retired AND p.state='finalized' AND p.uses=p.max_uses AND p.max_uses=1
 AND p.proof_fingerprint=$7 AND p.payload_digest=$8 AND p.signed_issued_at=$9 AND p.signed_not_before=$10 AND p.expires_at=$11
 AND p.expires_at>clock_timestamp() AND p.superseded_by_command_id IS NULL
FOR SHARE OF p,j,k`, v.Tenant, v.ID, v.Subject, confirmationBytes, string(signup), string(confirmation), envelope[:], digest[:], v.IssuedAt, v.NotBefore, v.ExpiresAt)
	if err != nil {
		return issuerFailure(bounded)
	}
	defer rows.Close()
	var one int
	matched := rows.Next() && rows.Scan(&one) == nil && !rows.Next() && rows.Err() == nil && one == 1
	if !matched {
		if bounded.Err() != nil {
			return issuerFailure(bounded)
		}
		return identity.ForbiddenError{}
	}
	return bounded.Err()
}
