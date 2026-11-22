package identitycapability

import (
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func ssoOIDCIssuanceOperation(b identity.CommandBinding) bool {
	return b.OperationID == "identity.sso.signin-start"
}

// Match the kernel's sso OIDC-start owner, not the social OAuth RP profile.
// Its preauth flow is an opaque capability subject, never a local user override.
func ssoOIDCIssuanceSubject(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) (string, bool) {
	if p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "" {
		return "", false
	}
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	return b.AnonymousFlowID, b.UserID == "" && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(b.CommandID) && b.ValidateFor(op) == nil
}

func ssoOIDCIssuancePayload(b identity.CommandBinding, p capability.Payload) bool {
	// The kernel's oauthRPInitiationGrantSubject fixes the original RP state
	// lifetime at ten minutes; checkpoint recovery cannot renew that deadline.
	return p.Operation == "identity.sso.oidc-callback" && p.Resource == b.RecordID && p.CorrelationID == b.CorrelationID && p.IssuedAt.Location() == time.UTC && p.IssuedAt.Nanosecond() == 0 && p.IssuedAt.Unix() > 0 && p.NotBefore.Location() == time.UTC && p.NotBefore.Equal(p.IssuedAt) && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= 10*time.Minute
}
