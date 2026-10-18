package identitycapability

import (
	"context"
	"fmt"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// OrganizationInvitationScope is original trusted invitation metadata, not
// authorization or HTTP input. Resolve it from authenticated durable invitation
// custody. Versions are positive; string fields are exact 1..128-byte visible
// ASCII identifiers. The organization owner alone decides whether that role is
// currently permitted. Copies are immutable and safe for concurrent reads.
type OrganizationInvitationScope struct {
	// OrganizationID identifies the organization bound by original issuance.
	OrganizationID string
	// InvitationVersion is the positive version signed into the invitation.
	InvitationVersion uint64
	// Role is the exact signed role; current role admission remains external.
	Role string
	// RecipientIdentifierID identifies the originally verified recipient.
	RecipientIdentifierID identity.IdentifierID
	// RecipientIdentifierVersion binds that recipient's original version.
	RecipientIdentifierVersion uint64
}

// Format hides correlated invitation and recipient metadata.
func (OrganizationInvitationScope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.OrganizationInvitationScope(redacted)"))
}

// MarshalJSON rejects automatic export of trusted scope custody.
func (OrganizationInvitationScope) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MarshalText rejects automatic export of trusted scope custody.
func (OrganizationInvitationScope) MarshalText() ([]byte, error) { return nil, invalid() }

// PrepareOrganizationInvitationConsumption reauthenticates one original opaque
// invitation proof for the closed organization invitation-accept command. The
// authenticated recipient is both UserID and ActorID; RecordID is the invitation,
// not the organization or capability ID. Expected scope, original envelope and
// replay-key version come from authenticated retained issuance, never caller
// claims. Signed tenant, recipient, invitation, issuer, audience, exact purpose,
// role, invitation version and verified-recipient identifier version must match.
//
// This bounded read-only preparation performs no SQL, signing, reservation,
// consumption, delivery or renewal. It grants neither membership nor current
// recipient authority. The native organization owner must fence the original
// verified recipient, current session, organization, policy and limits in the
// same coordinator Work as atomic one-use consumption, membership and audit.
// No proof custody is transferred; concurrent calls borrow its shared lifetime.
//
// Invalid composition returns InvalidInput; foreign or expired proof returns
// Forbidden; unavailable verification or collaborator panic returns Unavailable.
// Earlier caller cancellation wins. Every failure returns a zero plan, and
// retained key rotation never replaces the original replay identity or expiry.
func (i *Issuer) PrepareOrganizationInvitationConsumption(ctx context.Context, binding identity.CommandBinding, proof capability.Proof, originalEnvelope [32]byte, replayKeyVersion uint32, expected OrganizationInvitationScope) (out kernel.CapabilityPlan, err error) {
	op := identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.invitation.accept", SchemaID: "organization-invitation-accept", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || originalEnvelope == ([32]byte{}) || binding.ValidateFor(op) != nil || binding.ActorKind != authorization.SubjectUser || string(binding.ActorID) != string(binding.UserID) || !issuerText(expected.OrganizationID) || !issuerText(expected.Role) || !issuerText(string(expected.RecipientIdentifierID)) || expected.InvitationVersion == 0 || expected.RecipientIdentifierVersion == 0 {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = kernel.CapabilityPlan{}, identity.UnavailableError{}
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, capability.Purpose(op.OperationID))
	if err != nil {
		return out, err
	}
	p := grant.Payload()
	if grant.EnvelopeDigest() != originalEnvelope || p.Issuer != i.issuer || p.Tenant != string(binding.TenantID) || p.Subject != string(binding.UserID) || p.Resource != binding.RecordID || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != i.audience || len(p.Caveats) != 5 || p.Caveats["organization.id"] != expected.OrganizationID || p.Caveats["organization.invitation-version"] != strconv.FormatUint(expected.InvitationVersion, 10) || p.Caveats["organization.role"] != expected.Role || p.Caveats["organization.recipient-identifier"] != string(expected.RecipientIdentifierID) || p.Caveats["organization.recipient-identifier-version"] != strconv.FormatUint(expected.RecipientIdentifierVersion, 10) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(binding, binding.UserID, grant, replayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if err = issuerContext(ctx); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	return out, nil
}
