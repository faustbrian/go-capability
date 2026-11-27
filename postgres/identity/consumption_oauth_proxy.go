package identitycapability

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareOAuthProxyForwardConsumption reauthenticates original proxy state for
// the exact anonymous identity.oauth.proxy-forward.native-v1 callback. Supply
// callback, its distinct canonical initiating origin, bindingDigest and retained
// replayKeyVersion from authenticated original native custody, never callback
// assertions or current-key defaults. The service actor is structurally checked,
// not independently authenticated by this proof. The callback flow must equal
// its record, and callback correlation and signed correlation must equal origin.
// Exactly one identity.oauth.proxy.binding caveat binds the raw-URL-base64 digest.
// The non-bearer, one-use grant must match tenant, flow, resource, proxy purpose,
// trusted issuer and sole configured audience. Original UTC whole-second
// validity is at most five minutes; verification skew never extends it.
//
// Calls may overlap and borrow proof custody under PreparationTimeout and the
// earlier caller deadline. This read-only preparation does not sign, transfer,
// renew, reserve, consume, perform SQL or grant provider/account/session authority.
// It preserves the original fingerprint, expiry and keyed replay identity. The
// existing Participant remains the sole reservation, consumption and recovery
// owner and must match original durable issuance. Native owners must separately
// authenticate original environment/provider/browser intent and current policy.
//
// Invalid composition returns InvalidInput; foreign, malformed, revoked or
// expired proof returns Forbidden; verification uncertainty, invalid clock or
// panic returns Unavailable. Cancellation remains classified, diagnostics are
// redacted and every failure returns a zero plan.
func (i *Issuer) PrepareOAuthProxyForwardConsumption(ctx context.Context, callback identity.CommandBinding, origin identity.CommandID, bindingDigest [32]byte, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || bindingDigest == ([32]byte{}) {
		return out, invalid()
	}
	// Mirror the native kernel's closed proxy-forward descriptor without changing
	// the optional adapter's pinned dependency or adding another authority route.
	op := identity.FeatureOperation{Owner: "identity/oauth/proxy", OperationID: "identity.oauth.proxy-forward", SchemaID: "identity.oauth.proxy-forward.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if callback.ValidateFor(op) != nil || callback.ActorKind != authorization.SubjectServiceAccount || callback.UserID != "" || callback.AnonymousFlowID != callback.RecordID {
		return out, invalid()
	}
	parsedOrigin, parseErr := identity.ParseCommandID(string(origin))
	if parseErr != nil || parsedOrigin != origin || callback.CommandID == origin || callback.CorrelationID != string(origin) {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = identitypostgres.CapabilityPlan{}, issuerFailure(ctx)
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, capability.Purpose(op.OperationID))
	if err != nil {
		return out, err
	}
	p := grant.Payload()
	if p.Issuer != i.issuer || p.Tenant != string(callback.TenantID) || p.Subject != callback.AnonymousFlowID || p.Resource != callback.RecordID || p.Operation != op.OperationID || p.CorrelationID != string(origin) {
		return out, identity.ForbiddenError{}
	}
	if p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != i.audience || len(p.Caveats) != 1 || p.Caveats["identity.oauth.proxy.binding"] != base64.RawURLEncoding.EncodeToString(bindingDigest[:]) {
		return out, identity.ForbiddenError{}
	}
	// The native proxy profile retains its original five-minute state deadline;
	// a verifier's clock skew must not create earlier or longer callback authority.
	if p.IssuedAt.Location() != time.UTC || p.IssuedAt.Unix() <= 0 || p.IssuedAt.Nanosecond() != 0 || p.NotBefore.Location() != time.UTC || !p.NotBefore.Equal(p.IssuedAt) {
		return out, identity.ForbiddenError{}
	}
	if p.ExpiresAt.Location() != time.UTC || p.ExpiresAt.Nanosecond() != 0 || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute {
		return out, identity.ForbiddenError{}
	}
	now := i.clock()
	if err := issuerContext(ctx); err != nil {
		return out, err
	}
	if now.IsZero() {
		return out, identity.UnavailableError{}
	}
	if now.Before(p.NotBefore) || !now.Before(p.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantSubjectPlan(callback, callback.AnonymousFlowID, grant, replayKeyVersion)
	if err != nil {
		return identitypostgres.CapabilityPlan{}, identity.ForbiddenError{}
	}
	if err := issuerContext(ctx); err != nil {
		return identitypostgres.CapabilityPlan{}, err
	}
	return out, nil
}
