package identitycapability

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareOAuthCallbackConsumption reauthenticates the canonical callback-state
// proof against its original RP initiation binding and named retained replay key.
// Only the closed user link-start or anonymous signin-start profiles are accepted;
// an anonymous flow remains a string subject, never a fabricated local user.
// The returned metadata preserves the exact original grant, expiry and replay
// identity. The native callback must additionally authenticate its full signed
// RP-binding caveat, browser, provider and current policy, then reserve through
// the registered Participant before decrypting PKCE or exchanging a code.
//
// This bounded read-only phase neither signs, transfers, reserves, consumes nor
// persists anything. It does not retarget the grant's RP resource to a final
// account record. Concurrent calls share only immutable issuer configuration;
// proof custody retains its original lifetime. Malformed composition is invalid
// input, foreign/expired/revoked proof is forbidden, and verification uncertainty
// or panic is unavailable. Context cancellation remains classified.
func (i *Issuer) PrepareOAuthCallbackConsumption(ctx context.Context, b identity.CommandBinding, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	subject, ok := oauthRPIssuanceSubject(b, identitypostgres.CapabilityIssuancePlan{})
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
	grant, err := i.verifyConsumptionProof(ctx, proof, "identity.oauth.callback")
	if err != nil {
		return out, err
	}
	if !oauthRPIssuancePayload(b, grant.Payload()) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantSubjectPlan(b, subject, grant, replayKeyVersion)
	if err != nil {
		return identitypostgres.CapabilityPlan{}, identity.ForbiddenError{}
	}
	if err := issuerContext(ctx); err != nil {
		return identitypostgres.CapabilityPlan{}, err
	}
	return out, nil
}

func oauthRPIssuanceOperation(b identity.CommandBinding) bool {
	return b.OperationID == "identity.account.link-start" || b.OperationID == "identity.oauth.signin-start"
}

// The native RP owner freezes these two schemas before preparation. Callback
// state targets the original RP transaction and actual user or pre-auth flow;
// it is not the separately authorized final account-link grant.
func oauthRPIssuanceSubject(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) (string, bool) {
	if p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "" {
		return "", false
	}
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	subject := string(b.UserID)
	actor := b.ActorKind == authorization.SubjectUser && string(b.ActorID) == subject
	if b.OperationID == "identity.oauth.signin-start" {
		op.OperationID, op.SchemaID, op.SubjectRequirement = "identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1", identity.FeatureSubjectAnonymousFlow
		subject = b.AnonymousFlowID
		actor = b.ActorKind == authorization.SubjectServiceAccount
	}
	return subject, actor && b.ValidateFor(op) == nil
}

func oauthRPIssuancePayload(b identity.CommandBinding, p capability.Payload) bool {
	return p.Operation == "identity.oauth.callback" && p.Resource == b.RecordID && p.IssuedAt.Location() == time.UTC && p.IssuedAt.Nanosecond() == 0 && p.IssuedAt.Unix() > 0 && p.NotBefore.Equal(p.IssuedAt) && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= 10*time.Minute
}
