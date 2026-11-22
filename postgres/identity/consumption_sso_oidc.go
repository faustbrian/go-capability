package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareSSOOIDCSigninConsumption reauthenticates an original enterprise OIDC
// callback-state proof against its exact identity.sso.signin-start.oidc-v1
// start binding. The anonymous flow remains the signed subject, RecordID must
// be the original start command ID, and tenant, correlation, callback purpose
// and original validity of at most ten minutes must match. replayKeyVersion
// comes from trusted original issuance custody, never a request or the current
// issuance default. Retain that key for the original proof's durable lifetime.
// The returned plan preserves the original envelope, expiry and keyed replay
// identity; the participant must still compare it with durable issuance.
// Configured verification skew never extends the original signed expiry.
//
// This bounded read-only phase does not sign, transfer, reserve, consume or
// persist proof, and grants no exchange, account or session authority. The
// enterprise adapter must separately authenticate its full signed RP-binding
// caveat, browser, provider and current policy, then reserve through the native
// registered Participant before decrypting PKCE or exchanging a code. Native
// enterprise callback admission is a separate kernel composition requirement.
// Social OAuth starts and callback proofs cannot select this profile.
//
// Calls may overlap and borrow original proof custody. PreparationTimeout and
// the earlier caller deadline bound verification. Invalid composition returns
// InvalidInput; malformed, foreign, expired or revoked proof returns Forbidden;
// unavailable verification, an invalid clock or panic returns Unavailable.
// Cancellation remains classified, errors are redacted and every failure
// returns a zero plan.
func (i *Issuer) PrepareSSOOIDCSigninConsumption(ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	subject, ok := ssoOIDCIssuanceSubject(originalStart, identitypostgres.CapabilityIssuancePlan{})
	if i == nil || i.service == nil || ctx == nil || !ok || i.keys[replayKeyVersion] == ([32]byte{}) {
		return out, invalid()
	}
	ctx, stop := context.WithTimeout(ctx, i.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = identitypostgres.CapabilityPlan{}, identity.UnavailableError{}
		}
	}()
	if err := issuerContext(ctx); err != nil {
		return out, err
	}
	grant, err := i.verifyConsumptionProof(ctx, proof, "identity.sso.oidc-callback")
	if err != nil {
		return out, err
	}
	now := i.clock()
	if err := issuerContext(ctx); err != nil {
		return out, err
	}
	if now.IsZero() {
		return out, identity.UnavailableError{}
	}
	if !now.Before(grant.Payload().ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantSubjectPlan(originalStart, subject, grant, replayKeyVersion)
	if err != nil {
		return identitypostgres.CapabilityPlan{}, identity.ForbiddenError{}
	}
	if err := issuerContext(ctx); err != nil {
		return identitypostgres.CapabilityPlan{}, err
	}
	return out, nil
}
