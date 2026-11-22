package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareSSOOAuth2SigninConsumption reauthenticates an original enterprise
// OAuth2 callback-state proof for the exact anonymous
// identity.sso.signin-start.oauth2-v1 start binding. The original service-account
// actor and pre-auth flow must remain valid, RecordID must equal the start
// command ID, and the signed identity.sso.oauth-callback purpose, tenant,
// subject, resource, correlation and original validity of at most ten minutes
// must match. OIDC, social OAuth and member-link starts cannot select this
// profile. Configured verification skew never extends signed expiry.
//
// replayKeyVersion comes from trusted original issuance custody, never request
// input or the current issuance default. Retain that key for the proof's durable
// lifetime. The returned plan preserves the original envelope, one-use policy,
// expiry and keyed replay identity; the participant must still compare it with
// durable issuance. Calls may overlap and borrow original proof custody without
// signing, transfer, SQL, reservation or consumption.
//
// A plan grants no callback, code-exchange, account or session authority. The
// enterprise owner must separately authenticate full signed RP intent, browser,
// provider and current policy, and reserve through the existing Participant
// before decrypting PKCE or exchanging a code. Native callback admission remains
// a separate kernel composition requirement.
//
// PreparationTimeout and the earlier caller deadline bound verification.
// Invalid composition returns InvalidInput; malformed, foreign, expired or
// revoked proof returns Forbidden; unavailable verification, an invalid clock
// or panic returns Unavailable. Cancellation remains classified, errors are
// redacted and every failure returns a zero plan.
func (i *Issuer) PrepareSSOOAuth2SigninConsumption(ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	if originalStart.SchemaID != "identity.sso.signin-start.oauth2-v1" {
		return out, invalid()
	}
	subject, ok := ssoIssuanceSubject(originalStart, identitypostgres.CapabilityIssuancePlan{})
	if !ok {
		return out, invalid()
	}
	return i.prepareSSOConsumption(ctx, originalStart, subject, proof, replayKeyVersion)
}

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
	subject, ok := ssoOIDCSigninSubject(originalStart)
	if !ok {
		return out, invalid()
	}
	return i.prepareSSOConsumption(ctx, originalStart, subject, proof, replayKeyVersion)
}

// PrepareSSOOIDCExplicitLinkConsumption reauthenticates original member-bound
// enterprise OIDC callback state for identity.sso.signin-start.oidc-link-v1 v1.
// Only the exact self-user actor/subject with no anonymous flow is accepted;
// RecordID must equal the original start command ID. The original signed
// subject, tenant, transaction, correlation, one-use envelope, expiry and keyed
// replay identity are preserved. replayKeyVersion must come from trusted
// original issuance custody, not request input or the current issuance default.
//
// Like PrepareSSOOIDCSigninConsumption, this bounded, concurrent-safe phase
// borrows proof custody and performs no signing, transfer, SQL, reservation or
// consumption. The enterprise owner must separately authenticate full signed
// consent/RP intent, current member/session/factor/organization policy and then
// reserve atomically through the existing Participant. A plan grants no link,
// callback, code-exchange or session authority. Anonymous sign-in and social
// OAuth state cannot select this profile. Configured skew never renews expiry.
//
// PreparationTimeout and the earlier caller deadline bound verification.
// Invalid composition returns InvalidInput; malformed, foreign, expired or
// revoked proof returns Forbidden; verification uncertainty, invalid clocks
// and panic return Unavailable. Cancellation remains classified; errors are
// redacted and every failure returns a zero plan.
func (i *Issuer) PrepareSSOOIDCExplicitLinkConsumption(ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	subject, ok := ssoOIDCExplicitLinkSubject(originalStart)
	if !ok {
		return out, invalid()
	}
	return i.prepareSSOConsumption(ctx, originalStart, subject, proof, replayKeyVersion)
}

func (i *Issuer) prepareSSOConsumption(ctx context.Context, originalStart identity.CommandBinding, subject string, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) {
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
	grant, err := i.verifyConsumptionProof(ctx, proof, ssoIssuancePurpose(originalStart))
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
