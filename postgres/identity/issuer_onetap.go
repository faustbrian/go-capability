package identitycapability

import (
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

const oneTapCallbackPurpose capability.Purpose = "identity.oauth.onetap-callback"

func oneTapIssuanceOperation(b identity.CommandBinding) bool {
	return b.OperationID == "identity.oauth.onetap-start"
}

func oneTapIssuanceSubject(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) (string, bool) {
	if p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "" {
		return "", false
	}
	// Mirror identity/postgres.OneTapStartOperation without changing its pinned
	// dependency. The native owner separately binds browser and provider policy.
	op := identity.FeatureOperation{Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-start", SchemaID: "oauth-onetap-start-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	return b.AnonymousFlowID, b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == b.AnonymousFlowID && b.ValidateFor(op) == nil
}

// The callback purpose is exclusive to its original native start, including
// restored or retained issuance; a generic user command cannot borrow it.
func oneTapIssuancePurposeAllowed(b identity.CommandBinding, purpose capability.Purpose) bool {
	if purpose != oneTapCallbackPurpose {
		return true
	}
	_, valid := oneTapIssuanceSubject(b, identitypostgres.CapabilityIssuancePlan{})
	return valid
}

func oneTapIssuancePayload(b identity.CommandBinding, p capability.Payload) bool {
	// Match identity/postgres.oneTapStartGrantSubject's original five-minute
	// pre-auth callback validity. Recovery must not renew that deadline.
	return p.Operation == string(oneTapCallbackPurpose) && p.Resource == b.RecordID && p.CorrelationID == b.CorrelationID && p.IssuedAt.Location() == time.UTC && p.IssuedAt.Unix() > 0 && p.IssuedAt.Nanosecond() == 0 && p.NotBefore.Location() == time.UTC && p.NotBefore.Equal(p.IssuedAt) && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= 5*time.Minute
}
