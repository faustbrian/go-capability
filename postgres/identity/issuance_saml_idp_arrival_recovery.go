package identitycapability

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Mirror identity/postgres.SSOSAMLIDPArrivalOperation without changing the
// pinned kernel. Its sole original confirmation grant can select the existing
// fenced absence proof; this does not verify a grant or decide command outcome.
func (i *Issuer) samlIDPArrivalAbsenceProfile(b identity.CommandBinding, p kernel.CapabilityIssuancePlan) bool {
	op := identity.FeatureOperation{
		Owner:              "sso/saml",
		OperationID:        "identity.sso.saml-idp-prepare",
		SchemaID:           "sso-enterprise-saml-idp-prepare-v1",
		SchemaVersion:      1,
		RecordRequirement:  identity.FeatureRecordRequired,
		SubjectRequirement: identity.FeatureSubjectUser,
	}
	if b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != string(b.CommandID) {
		return false
	}
	if p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || p.MagicLinkRecipientUserID != "" || p.MFAContinuationUserID != "" {
		return false
	}
	if len(p.Grants) != 1 || p.Grants[0].Purpose != "identity.sso.saml-idp-init" {
		return false
	}
	return i.ValidateCapabilityIssuance(b, p) == nil
}
