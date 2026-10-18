package identitycapability

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareMFAContinuation signs one original challenge under an anonymous
// magic-link consume, password-signin or username-signin command. The native
// owner allocates the canonical ID and freezes the full scope before this
// bounded call; this method preserves
// that ID, scope and expiry. It performs no SQL, consumption or authentication.
// Kernel staging still requires the same-Work native primary and exact frozen
// challenge scope. Retain original encrypted custody across retries; never sign
// replacements to resolve unknown commit. Restoration cannot renew disclosure.
func (i *Issuer) PrepareMFAContinuation(ctx context.Context, b identity.CommandBinding, input capability.Payload) (PreparedIssuance, error) {
	if !mfaIssuancePayload(input) || b.OperationID != "identity.magic-link.consume" && b.OperationID != "identity.password.signin" && b.OperationID != "identity.username.signin" {
		return PreparedIssuance{}, invalid()
	}
	plan := identitypostgres.CapabilityIssuancePlan{MFAContinuationUserID: identity.UserID(input.Subject)}
	return i.preparePlan(ctx, b, plan, []capability.Payload{input}, true)
}

// PrepareVerificationMFAContinuation signs one original challenge for the
// explicit recipient of a separately committed registration verification.
// Binding retains that confirmation's command ID in RecordID, not an anonymous
// primary or a same-transaction consumption. Structural checks do not prove the
// parent or browser; the exact native owner must fence both before kernel
// staging. This bounded call performs no SQL, authentication or session issuance.
// Retain encrypted preparation across retries; restore original bytes without
// extending expiry or signing replacements after an unknown commit.
func (i *Issuer) PrepareVerificationMFAContinuation(ctx context.Context, b identity.CommandBinding, input capability.Payload) (PreparedIssuance, error) {
	if !verificationMFAIssuerBinding(b, identity.UserID(input.Subject)) || !mfaIssuancePayload(input) || input.CorrelationID != b.RecordID {
		return PreparedIssuance{}, invalid()
	}
	plan := identitypostgres.CapabilityIssuancePlan{MFAContinuationUserID: b.UserID}
	return i.preparePlan(ctx, b, plan, []capability.Payload{input}, true)
}

func verificationMFAIssuerBinding(b identity.CommandBinding, user identity.UserID) bool {
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	_, err := identity.ParseCommandID(b.RecordID)
	return err == nil && b.RecordID != string(b.CommandID) && b.UserID == user && issuerText(string(user)) && b.AnonymousFlowID == "" && b.ValidateFor(op) == nil
}

func mfaIssuancePayload(p capability.Payload) bool {
	if _, err := identity.ParseCommandID(p.ID); err != nil {
		return false
	}
	if p.Operation != "identity.mfa.complete" || p.Resource != "mfa/continuations/"+p.ID || len(p.Caveats) != 2 || p.Caveats["mfa.profile"] != "identity-mfa-continuation-v1" || p.IssuedAt.Location() != time.UTC || p.IssuedAt.Nanosecond() != 0 || p.IssuedAt.Unix() <= 0 || !p.NotBefore.Equal(p.IssuedAt) || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute {
		return false
	}
	scope := p.Caveats["mfa.scope"]
	if len(scope) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(scope)
	if err != nil || hex.EncodeToString(decoded) != scope {
		return false
	}
	var nonzero byte
	for _, b := range decoded {
		nonzero |= b
	}
	return nonzero != 0
}
