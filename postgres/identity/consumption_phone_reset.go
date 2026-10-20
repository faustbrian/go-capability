package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PreparePhonePasswordResetConsumption authenticates only the original signed
// proof retained by a sealed joint phone-reset input or generated command. The
// exact identity/phone native-v1 descriptor, signed password resource, tenant,
// user, configured audience and one-use bound must match. The original password
// or hash, SMS code, independent TOTP and browser cookie remain in their joint
// command custody; no generic command conversion or alternate proof is accepted.
//
// replayKeyVersion is trusted original issuance metadata from ReadIssuanceOrigin,
// not a request-selected version or the active issuance default. Retain that key
// through recovery. Configured signature, time and revocation policy apply.
// Repeated preparation preserves the original envelope, absolute expiry and
// replay identity; it performs no SQL, signing, transfer, reservation or use.
// Calls may overlap and are bounded by PreparationTimeout and earlier deadlines.
// Invalid composition returns InvalidInput, invalid scope/proof Forbidden,
// unavailable verification or collaborator panic Unavailable, and cancellation
// remains typed. Every failure returns a zero plan and redacted error.
//
// This plan is not recovery permission. The native owner must authenticate the
// complete original durable phone reset profile and current phone/password,
// browser, independent-factor and completion-risk authority. The sole identity
// coordinator must consume capability, OTP and risk with the canonical password
// replacement and required session effects. Preparation cannot establish commit,
// renew expired custody or make terminal evidence usable.
func (i *Issuer) PreparePhonePasswordResetConsumption(ctx context.Context, command identity.Command, replayKeyVersion uint32) (out kernel.CapabilityPlan, err error) {
	spec, metadata := command.PhonePasswordResetFeature()
	_, proof, _, _, custody := command.PhonePasswordResetCustody()
	if !metadata {
		spec, metadata = command.PhonePasswordResetInputFeature()
		_, proof, _, _, custody = command.PhonePasswordResetInputCustody()
	}
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
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
