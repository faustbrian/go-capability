package identitycapability

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PrepareSSOSAMLIDPConfirmationConsumption reauthenticates the original
// unsolicited SAML confirmation proof for the exact user-targeted
// identity.sso.saml-idp-init/sso-enterprise-saml-idp-init-v1 v1 binding. The
// trusted native adapter supplies the service-account actor, pending record,
// user and correlation. originalEnvelope, replayKeyVersion and originalCutoff
// must come from authenticated durable origin custody, never request input or
// current issuance defaults. Retain that replay key for the original lifetime.
// The signed grant must be non-bearer, one-use and exclusively addressed to this
// issuer's audience, with at most five minutes of original validity. Its exact
// UTC whole-second expiry cannot exceed originalCutoff, which is not rounded;
// configured verification skew never extends either deadline.
//
// This read-only seam borrows proof custody and returns only the existing
// capability plan. It does not sign, renew, transfer, reserve, consume, perform
// SQL or grant login/session authority. The native confirmation owner must
// separately authenticate browser cookie and synchronizer, original provider
// intent, current policy and pending state, then match durable issuance and
// atomically consume with session effects through the existing participant.
//
// Calls may overlap. PreparationTimeout and the earlier caller deadline bound
// verification. Invalid composition returns InvalidInput; foreign or expired
// proof returns Forbidden; verification uncertainty, invalid clock or panic
// returns Unavailable. Context errors remain classified and every failure
// returns a zero plan with redacted errors.
func (i *Issuer) PrepareSSOSAMLIDPConfirmationConsumption(ctx context.Context, b identity.CommandBinding, proof capability.Proof, originalEnvelope [32]byte, replayKeyVersion uint32, originalCutoff time.Time) (out kernel.CapabilityPlan, err error) {
	op := identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init", SchemaID: "sso-enterprise-saml-idp-init-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || originalEnvelope == ([32]byte{}) || originalCutoff.IsZero() || b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectServiceAccount {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = kernel.CapabilityPlan{}, issuerFailure(ctx)
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, capability.Purpose(op.OperationID))
	if err != nil {
		return out, err
	}
	p := grant.Payload()
	if grant.EnvelopeDigest() != originalEnvelope || p.Issuer != i.issuer || p.Tenant != string(b.TenantID) || p.Subject != string(b.UserID) || p.Resource != b.RecordID || p.CorrelationID != b.CorrelationID || p.Operation != op.OperationID || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != i.audience {
		return out, identity.ForbiddenError{}
	}
	// PROTOCOL_BASELINES.md's unsolicited SAML profile keeps the original
	// confirmation deadline. Wire seconds may end before its stored precision.
	if p.ExpiresAt.Location() != time.UTC || p.ExpiresAt.Nanosecond() != 0 || p.ExpiresAt.After(originalCutoff) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute || p.ExpiresAt.Sub(p.NotBefore) > 5*time.Minute {
		return out, identity.ForbiddenError{}
	}
	now := i.clock()
	if err := issuerContext(ctx); err != nil {
		return out, err
	}
	if now.IsZero() {
		return out, identity.UnavailableError{}
	}
	if !now.Before(originalCutoff) || !now.Before(p.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(b, b.UserID, grant, replayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	if err := issuerContext(ctx); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	return out, nil
}
