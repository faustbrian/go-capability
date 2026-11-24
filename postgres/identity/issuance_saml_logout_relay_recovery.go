package identitycapability

import (
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The native SSOSAMLLogoutRelayIssueOperation binds one remote issue to its
// distinct original local logout. Only its sole settle grant may select the
// existing fenced absence proof; selection itself decides no durable outcome.
func (i *Issuer) samlLogoutRelayAbsenceProfile(b identity.CommandBinding, p kernel.CapabilityIssuancePlan) bool {
	_, valid := ssoSAMLLogoutRelaySubject(b)
	if !valid || len(p.Grants) != 1 || p.Grants[0].Purpose != ssoSAMLLogoutRelaySettlePurpose {
		return false
	}
	return i.ValidateCapabilityIssuance(b, p) == nil
}
