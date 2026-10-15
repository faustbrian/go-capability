package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PreparePasswordResetConsumption authenticates the original opaque proof
// retained inside the exact password-reset input or generated command. The
// input form allows authoritative preparation admission before hashing; both
// forms produce the same original plan. No alternate proof or
// caller-built envelope is accepted. The signed tenant, subject and password
// resource must match the immutable binding. replayKeyVersion is trusted
// original issuance metadata from ReadIssuanceOrigin, not the current version
// or a client-selected default. Original envelope, expiry and replay identity
// are preserved under the issuer's configured signature/time/revocation policy.
//
// Preparation is bounded by PreparationTimeout and the earlier caller deadline.
// It performs no SQL, signing, transfer, reservation, consumption or renewal;
// copies of the proof retain their upstream shared lifetime. Calls may overlap.
// Invalid composition returns InvalidInput, invalid scope/proof returns Forbidden,
// unavailable verification or collaborator panic returns Unavailable, and
// cancellation remains typed. Every failure returns a zero plan with no secrets.
//
// A plan is not reset permission. The password owner must validate original
// durable issuance intent, closed recovery profile, current identifier/factors,
// risk/HIBP and verifier policy. The sole coordinator and capability participant
// must match durable provenance and atomically consume with password/session
// effects. Preparation cannot make a terminal proof usable or establish commit.
func (i *Issuer) PreparePasswordResetConsumption(ctx context.Context, command identity.Command, replayKeyVersion uint32) (out kernel.CapabilityPlan, err error) {
	spec, metadata := command.PasswordResetFeature()
	_, proof, custody := command.PasswordResetCustody()
	if !metadata {
		spec, metadata = command.PasswordResetInputFeature()
		_, proof, custody = command.PasswordResetInputCustody()
	}
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-complete", SchemaID: "password-reset-complete", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || !metadata || !custody || spec.Operation != op || spec.Binding.ValidateFor(op) != nil {
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
	payload := grant.Payload()
	if payload.Resource != "identity.password/"+spec.Binding.RecordID || payload.Tenant != string(spec.Binding.TenantID) || payload.Subject != string(spec.Binding.UserID) || payload.Bearer || payload.MaxUses != 1 || len(payload.Audiences) != 1 || payload.Audiences[0] != i.audience {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(spec.Binding, spec.Binding.UserID, grant, replayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if err = issuerContext(ctx); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	return out, nil
}
