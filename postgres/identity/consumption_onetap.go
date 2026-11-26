package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareOneTapCallbackConsumption reauthenticates an original One Tap callback
// grant for the closed anonymous native start profile. originalStart must come
// from authenticated original native custody, not callback input. Its service
// actor is structurally checked, not independently authenticated by the proof.
// Native PrepareRequestKey's command correlation, signed flow, tenant, record,
// callback purpose, configured audience and one-use scope must match. Original
// whole-second UTC validity is at most five minutes; skew never extends expiry.
//
// replayKeyVersion comes from trusted original durable issuance, never request
// input or the current default. Retain that key through the original recovery
// lifetime. The plan preserves the signed envelope, expiry and keyed replay
// identity. The existing Participant remains the sole reservation, consumption
// and recovery owner and must compare this plan with original durable issuance.
// Native owners must still authenticate browser, CSRF, provider, nonce and
// current identity/session policy; preparation grants none of that authority.
//
// Concurrent calls borrow original proof custody, bounded by PreparationTimeout
// and the earlier caller deadline, without signing, SQL, storage, transfer,
// reservation or consumption. Invalid composition returns InvalidInput;
// malformed, foreign, expired or revoked proof returns Forbidden; verification
// uncertainty, an invalid clock or panic returns Unavailable. Cancellation
// stays classified, diagnostics are redacted and failures return a zero plan.
func (i *Issuer) PrepareOneTapCallbackConsumption(ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	subject, valid := oneTapIssuanceSubject(originalStart, identitypostgres.CapabilityIssuancePlan{})
	// The native One Tap start's PrepareRequestKey uses its command ID as signed
	// correlation. Requiring that closed profile also binds the original command.
	if i == nil || i.service == nil || ctx == nil || !valid || originalStart.CorrelationID != string(originalStart.CommandID) || i.keys[replayKeyVersion] == ([32]byte{}) {
		return out, invalid()
	}
	ctx, stop := context.WithTimeout(ctx, i.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = identitypostgres.CapabilityPlan{}, identity.UnavailableError{}
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, oneTapCallbackPurpose)
	if err != nil {
		return out, err
	}
	use := capability.Use{Issuer: i.issuer, Audience: i.audience, Subject: subject, Resource: originalStart.RecordID, Operation: string(oneTapCallbackPurpose), Tenant: string(originalStart.TenantID)}
	if grant.Authorize(use) != nil {
		return out, identity.ForbiddenError{}
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
