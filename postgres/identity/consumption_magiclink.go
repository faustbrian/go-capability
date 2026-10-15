package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PrepareMagicLinkConsumption reauthenticates the original one-use proof for
// the exact anonymous identity.magic-link.consume/magic-link-consume v1 binding.
// recipient and identifier are trusted original issuance selections, not a
// customer-selected user override. originalEnvelope and replayKeyVersion must
// come from authenticated durable origin custody; neither an alternate valid
// signature nor the current replay-key default may replace them. Tenant, signed
// recipient, identity.magiclink identifier resource, audience and original
// envelope must match. The anonymous command scope remains unchanged.
//
// This read-only adapter seam is not login permission or a public inspection
// response. The native owner must additionally validate all original caveats,
// callback/pre-auth intent, current recipient/factor/risk policy and session
// effects. The existing capability participant matches durable issuance and
// consumes atomically in the sole coordinator transaction. No SQL, signing,
// reservation, consumption, renewal, transfer or goroutine occurs here.
//
// Calls may overlap and borrow the upstream shared proof lifetime. Preparation
// is bounded by PreparationTimeout and the earlier caller deadline. Invalid
// composition returns InvalidInput; invalid proof/scope returns Forbidden;
// unavailable verification or collaborator panic returns Unavailable. Context
// errors stay classified. Every failure returns a zero plan with no secrets.
func (i *Issuer) PrepareMagicLinkConsumption(ctx context.Context, binding identity.CommandBinding, recipient identity.UserID, identifier identity.IdentifierID, proof capability.Proof, originalEnvelope [32]byte, replayKeyVersion uint32) (out kernel.CapabilityPlan, err error) {
	op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || originalEnvelope == ([32]byte{}) || !issuerText(string(recipient)) || !issuerText(string(identifier)) || binding.ValidateFor(op) != nil {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = kernel.CapabilityPlan{}, identity.UnavailableError{}
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, "identity.magic-link.consume")
	if err != nil {
		return out, err
	}
	payload := grant.Payload()
	if grant.EnvelopeDigest() != originalEnvelope || payload.Tenant != string(binding.TenantID) || payload.Subject != string(recipient) || payload.Resource != "identity.magiclink/"+string(identifier) || payload.Caveats["magiclink.identifier"] != string(identifier) || payload.Bearer || payload.MaxUses != 1 || len(payload.Audiences) != 1 || payload.Audiences[0] != i.audience {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(binding, recipient, grant, replayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if err = issuerContext(ctx); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	return out, nil
}
