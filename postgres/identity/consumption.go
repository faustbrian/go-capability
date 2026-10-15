package identitycapability

import (
	"context"
	"errors"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// PrepareIdentifierConsumption authenticates the original proof with this
// issuer's configured verification policy and derives metadata for the exact
// immutable identifier command. replayKeyVersion is the trusted original
// issuance version, not the current issuance default or a bearer-selected
// value. Retain that key until its credentials and durable custody expire.
// The participant subsequently matches all metadata against durable issuance;
// this read-only preparation is neither reservation nor mutation authority.
// It does not consume or transfer proof custody, resign, extend expiry or open
// a transaction. Calls are concurrent-safe and bounded by PreparationTimeout
// and the caller's earlier deadline. Invalid composition returns InvalidInput;
// invalid/foreign/expired proof returns Forbidden; collaborator failure or
// panic returns Unavailable. Cancellation remains classified and redacted.
func (i *Issuer) PrepareIdentifierConsumption(ctx context.Context, command identity.Command, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	spec, ok := command.ChangeIdentifier()
	if !ok || spec.Proof.EnvelopeDigest() == ([32]byte{}) {
		return out, invalid()
	}
	return i.prepareConsumption(ctx, spec.Binding, spec.Proof.EnvelopeDigest(), proof, replayKeyVersion)
}

// PreparePrivacyExportConsumption reauthenticates the exact original opaque
// proof for an immutable privacy request and derives the capability-owned
// consumption plan. replayKeyVersion is trusted retained issuance metadata,
// never a current default or a bearer-selected version. Configured signature,
// audience, time and revocation policy apply; another valid signed envelope
// cannot replace the command's original proof. Calls are concurrent-safe and
// bounded by PreparationTimeout and the caller's earlier deadline.
//
// Preparation does not transfer, resign, renew, reserve or consume the proof,
// begin a transaction, or authorize a session/export. The sole coordinator
// must still enforce primary expiry, session/policy eligibility, exact durable
// issuance and atomic use with all snapshot/effect owners. Invalid composition
// returns InvalidInput; invalid/foreign proof returns Forbidden; verification
// availability failures and panics return Unavailable. Cancellation stays
// classified and all errors are redacted. No raw proof material is returned.
func (i *Issuer) PreparePrivacyExportConsumption(ctx context.Context, command identity.Command, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	spec, ok := command.RequestPrivacyExport()
	if !ok || spec.Proof.EnvelopeDigest() == ([32]byte{}) {
		return out, invalid()
	}
	return i.prepareConsumption(ctx, spec.Binding, spec.Proof.EnvelopeDigest(), proof, replayKeyVersion)
}

// Both workflows use the same issuer-owned verification and retained replay
// derivation. A workflow-specific constructor binds its full signed intent;
// this phase may only authenticate that original envelope, never replace it.
func (i *Issuer) prepareConsumption(ctx context.Context, binding identity.CommandBinding, envelope [32]byte, proof capability.Proof, replayKeyVersion uint32) (out identitypostgres.CapabilityPlan, err error) {
	return i.prepareConsumptionProfile(ctx, binding, envelope, proof, replayKeyVersion, "")
}

// The email action is distinct from its unchanged internal signed purpose.
// Only that explicit native profile selects the bridge; existing identifier
// and privacy callers keep their exact operation verification contract.
func (i *Issuer) prepareConsumptionProfile(ctx context.Context, binding identity.CommandBinding, envelope [32]byte, proof capability.Proof, replayKeyVersion uint32, profile string) (out identitypostgres.CapabilityPlan, err error) {
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out = identitypostgres.CapabilityPlan{}
			err = identity.UnavailableError{}
		}
	}()
	if err = issuerContext(ctx); err != nil {
		return out, err
	}
	purpose := capability.Purpose(binding.OperationID)
	if profile != "" {
		purpose = "identity.identifier.verify"
	}
	grant, err := i.verifyConsumptionProof(ctx, proof, purpose)
	if err != nil {
		return out, err
	}
	if grant.EnvelopeDigest() != envelope {
		return out, identity.ForbiddenError{}
	}
	if profile != "" && (grant.Payload().Resource != string(binding.RecordID) || !emailConsumptionAction(grant.Payload(), profile, binding.OperationID)) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(binding, binding.UserID, grant, replayKeyVersion)
	if err != nil {
		return identitypostgres.CapabilityPlan{}, err
	}
	if err = issuerContext(ctx); err != nil {
		return identitypostgres.CapabilityPlan{}, err
	}
	return out, nil
}

// All consumption preparations use the same non-consuming verifier and error
// boundary; a caller's deadline wins even when verification returns success.
func (i *Issuer) verifyConsumptionProof(ctx context.Context, proof capability.Proof, purpose capability.Purpose) (capability.Grant, error) {
	if err := issuerContext(ctx); err != nil {
		return capability.Grant{}, err
	}
	grant, err := i.service.Verify(ctx, proof, purpose, i.audience)
	if cause := issuerContext(ctx); cause != nil {
		return capability.Grant{}, cause
	}
	if err != nil {
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			return capability.Grant{}, identity.UnavailableError{}
		}
		return capability.Grant{}, identity.ForbiddenError{}
	}
	return grant, nil
}
