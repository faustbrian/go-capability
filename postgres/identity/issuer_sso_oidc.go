package identitycapability

import (
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func ssoIssuanceOperation(b identity.CommandBinding) bool {
	return b.OperationID == "identity.sso.signin-start" || b.OperationID == "identity.sso.saml-start"
}

// Match only native enterprise start schemas, not the social OAuth RP profile.
// Each preserves its original subject namespace and exact callback purpose.
func ssoIssuanceSubject(b identity.CommandBinding, p identitypostgres.CapabilityIssuancePlan) (string, bool) {
	if p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "" {
		return "", false
	}
	switch b.SchemaID {
	case "identity.sso.saml-start.v1":
		// Mirror identity/postgres.SSOSAMLSigninStartOperation without changing
		// the pinned dependency; SAML retains its native operation and ACS purpose.
		op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.saml-start", SchemaID: "identity.sso.saml-start.v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
		return b.AnonymousFlowID, b.UserID == "" && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(b.CommandID) && b.ValidateFor(op) == nil
	case "identity.sso.signin-start.oauth2-v1":
		op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oauth2-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
		return b.AnonymousFlowID, b.UserID == "" && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(b.CommandID) && b.ValidateFor(op) == nil
	case "identity.sso.signin-start.oidc-link-v1":
		return ssoOIDCExplicitLinkSubject(b)
	case "identity.sso.signin-start.oidc-v1":
		return ssoOIDCSigninSubject(b)
	default:
		return "", false
	}
}

func ssoIssuancePurpose(b identity.CommandBinding) capability.Purpose {
	switch b.SchemaID {
	case "identity.sso.saml-start.v1":
		return "identity.sso.saml-acs"
	case "identity.sso.signin-start.oauth2-v1":
		return "identity.sso.oauth-callback"
	case "identity.sso.signin-start.oidc-v1", "identity.sso.signin-start.oidc-link-v1":
		return "identity.sso.oidc-callback"
	default:
		return ""
	}
}

func ssoOIDCSigninSubject(b identity.CommandBinding) (string, bool) {
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	return b.AnonymousFlowID, b.UserID == "" && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(b.CommandID) && b.ValidateFor(op) == nil
}

func ssoOIDCExplicitLinkSubject(b identity.CommandBinding) (string, bool) {
	// Mirror identity/postgres.SSOOIDCExplicitLinkStartOperation without changing
	// the pinned dependency. Its native owner still proves session and consent.
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-link-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	subject := string(b.UserID)
	selfActor := b.ActorKind == authorization.SubjectUser && string(b.ActorID) == subject
	return subject, selfActor && b.AnonymousFlowID == "" && b.RecordID == string(b.CommandID) && b.ValidateFor(op) == nil
}

func ssoIssuancePayload(b identity.CommandBinding, p capability.Payload) bool {
	// The kernel's oauthRPInitiationGrantSubject limits SAML RelayState to five
	// minutes and OAuth/OIDC state to ten; recovery cannot renew either deadline.
	maximumLifetime := 10 * time.Minute
	if b.SchemaID == "identity.sso.saml-start.v1" {
		maximumLifetime = 5 * time.Minute
	}
	purpose := ssoIssuancePurpose(b)
	return purpose != "" && p.Operation == string(purpose) && p.Resource == b.RecordID && p.CorrelationID == b.CorrelationID && p.IssuedAt.Location() == time.UTC && p.IssuedAt.Nanosecond() == 0 && p.IssuedAt.Unix() > 0 && p.NotBefore.Location() == time.UTC && p.NotBefore.Equal(p.IssuedAt) && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= maximumLifetime
}
