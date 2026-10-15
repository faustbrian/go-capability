package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PrepareManagedVerificationConsumption reauthenticates an original management-v1
// link for identity.email.verification-confirm.managed-v1 version1. Signed
// tenant/user/resource, exact profile/caveats, original envelope and retained
// replay-key version must match. Signup proofs, change-confirm and alternate
// schemas deny. No original session is inferred or required by this seam.
//
// The native email owner must authenticate original encrypted mailbox intent
// and current caller/account/factor/risk authority. Returned metadata grants no
// mutation authority; the existing capability participant matches durable
// issuance and consumes/finalizes in the sole protected coordinator transaction.
// Original signed purpose, expiry and replay identity are conserved unchanged.
// This method performs no SQL, signing, consumption, transfer or session work,
// owns no goroutines and is concurrent-safe. PreparationTimeout and earlier
// cancellation bound verification. Errors are typed/redacted; failures return
// zero plans. Proof custody is borrowed and must remain immutable during calls.
func (i *Issuer) PrepareManagedVerificationConsumption(ctx context.Context, binding identity.CommandBinding, proof capability.Proof, envelope [32]byte, replayKeyVersion uint32) (kernel.CapabilityPlan, error) {
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if envelope == ([32]byte{}) || binding.ValidateFor(op) != nil {
		return kernel.CapabilityPlan{}, invalid()
	}
	return i.prepareConsumptionProfile(ctx, binding, envelope, proof, replayKeyVersion, "management-v1")
}

// PrepareManagedChangeConsumption authenticates only change-confirm.managed-v1
// and its original management-v1 change grant. It conserves signed identifier
// purpose, envelope, expiry and retained replay identity. Verification-only
// schemas/proofs deny. Original intent/current admission and atomic old notice,
// primary/session effects remain the native email/kernel transaction's duty.
// Ownership, bounded verification and error semantics match the verification
// seam; no SQL, signing, consumption, session or custody transfer occurs.
func (i *Issuer) PrepareManagedChangeConsumption(ctx context.Context, binding identity.CommandBinding, proof capability.Proof, envelope [32]byte, replayKeyVersion uint32) (kernel.CapabilityPlan, error) {
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-confirm", SchemaID: "identity.email.change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if envelope == ([32]byte{}) || binding.ValidateFor(op) != nil {
		return kernel.CapabilityPlan{}, invalid()
	}
	return i.prepareConsumptionProfile(ctx, binding, envelope, proof, replayKeyVersion, "management-v1")
}
