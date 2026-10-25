package identitycapability

import (
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The original invitation-send producer has exactly one accept-purpose grant.
// As with the anonymous-upgrade producer, only sealed coordinator recovery can
// use this selection: absence of every original identity is negative evidence
// for this participant, not a command outcome or permission to reissue a proof.
func (i *Issuer) organizationInvitationAbsenceProfile(b identity.CommandBinding, p kernel.CapabilityIssuancePlan) bool {
	op := identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.invitation-send", SchemaID: "organization-invitation-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	return b.ValidateFor(op) == nil && b.ActorKind == authorization.SubjectUser && p.RegistrationUserID == "" && p.ResetRecipientUserID == "" && p.MagicLinkRecipientUserID == "" && p.MFAContinuationUserID == "" && len(p.Grants) == 1 && p.Grants[0].Purpose == capability.Purpose("identity.organization.invitation.accept") && i.ValidateCapabilityIssuance(b, p) == nil
}
