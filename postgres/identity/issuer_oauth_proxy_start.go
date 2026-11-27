package identitycapability

import (
	"encoding/base64"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

const oauthProxyForwardPurpose capability.Purpose = "identity.oauth.proxy-forward"

func oauthProxyStartIssuanceOperation(b identity.CommandBinding) bool {
	return b.OperationID == "identity.oauth.proxy-start"
}

func oauthProxyStartIssuanceSubject(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) (string, bool) {
	if p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "" {
		return "", false
	}
	// Mirror the native kernel's validOAuthProxyStartBinding and descriptor
	// without changing the pinned dependency. The kernel authenticates the request.
	op := identity.FeatureOperation{Owner: "identity/oauth/proxy", OperationID: "identity.oauth.proxy-start", SchemaID: "identity.oauth.proxy-start.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != b.AnonymousFlowID {
		return "", false
	}
	if _, err := identity.ParsePreAuthTransactionID(b.AnonymousFlowID); err != nil {
		return "", false
	}
	return b.AnonymousFlowID, b.CorrelationID == string(b.CommandID) && b.RecordID != b.CorrelationID
}

// Only the original native proxy start may issue forward state. Consumption
// uses its separate callback binding and does not enter this issuance gate.
func oauthProxyStartIssuancePurposeAllowed(b identity.CommandBinding, purpose capability.Purpose) bool {
	if purpose != oauthProxyForwardPurpose {
		return true
	}
	_, valid := oauthProxyStartIssuanceSubject(b, identitypostgres.CapabilityIssuancePlan{})
	return valid
}

func oauthProxyStartIssuancePayload(b identity.CommandBinding, p capability.Payload) bool {
	if p.Operation != string(oauthProxyForwardPurpose) || p.Resource != b.RecordID || p.CorrelationID != b.CorrelationID || len(p.Caveats) != 1 {
		return false
	}
	// Match the native proxy's original five-minute forward-state deadline.
	// Issuance rejects precision loss rather than silently rounding caller intent.
	if p.IssuedAt.Location() != time.UTC || p.IssuedAt.Unix() <= 0 || p.IssuedAt.Nanosecond() != 0 || p.NotBefore.Location() != time.UTC || !p.NotBefore.Equal(p.IssuedAt) || p.ExpiresAt.Location() != time.UTC || p.ExpiresAt.Nanosecond() != 0 || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute {
		return false
	}
	encoded := p.Caveats["identity.oauth.proxy.binding"]
	if len(encoded) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return false
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest != ([32]byte{})
}
