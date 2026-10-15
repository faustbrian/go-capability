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
// magic-link consume or password-signin command. The native owner allocates the canonical ID
// and freezes the full scope before this bounded call; this method preserves
// that ID, scope and expiry. It performs no SQL, consumption or authentication.
// Kernel staging still requires the same-Work native primary and exact frozen
// challenge scope. Retain original encrypted custody across retries; never sign
// replacements to resolve unknown commit. Restoration cannot renew disclosure.
func (i *Issuer) PrepareMFAContinuation(ctx context.Context, b identity.CommandBinding, input capability.Payload) (PreparedIssuance, error) {
	if !mfaIssuancePayload(input) {
		return PreparedIssuance{}, invalid()
	}
	plan := identitypostgres.CapabilityIssuancePlan{MFAContinuationUserID: identity.UserID(input.Subject)}
	return i.preparePlan(ctx, b, plan, []capability.Payload{input}, true)
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
