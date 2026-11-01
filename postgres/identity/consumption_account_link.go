package identitycapability

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PrepareAccountLinkConsumption reauthenticates the original opaque proof for
// one bare canonical explicit self-link command, before native counter
// enrichment. The root constructor owns the complete signed provider, target,
// actor, session, policy and mutation intent. The supplied proof must be that
// exact envelope under this issuer's configured verification policy. The
// replay-key version comes from trusted original issuance custody, not a
// request or the current issuance default. Original expiry is never extended.
//
// This bounded read-only phase does not sign, transfer, reserve or consume proof,
// establish provider/session authority, or attach newly minted issuance. The
// native AccountLinkUnitOfWork and registered Participant must still match
// durable issuance and consume atomically with the protected mutation and all
// current owner checks. OAuth state-before-exchange and post-exchange issuance
// require their separate native composition; this method supplies neither.
//
// Calls borrow shared proof custody and may overlap. PreparationTimeout and the
// earlier caller deadline bound verification. Invalid composition returns
// InvalidInput; invalid, foreign or expired proof returns Forbidden; unavailable
// verification or panic returns Unavailable. Cancellation remains classified,
// errors are redacted and every failure returns a zero plan.
func (i *Issuer) PrepareAccountLinkConsumption(ctx context.Context, command identity.Command, proof capability.Proof, replayKeyVersion uint32) (kernel.CapabilityPlan, error) {
	spec, ok := command.LinkAccount()
	if !ok || spec.Change.Mode != identity.AccountLinkExplicit || spec.Binding.ActorKind != authorization.SubjectUser || string(spec.Binding.ActorID) != string(spec.Binding.UserID) || spec.Proof.EnvelopeDigest() == ([32]byte{}) {
		return kernel.CapabilityPlan{}, invalid()
	}
	return i.prepareConsumptionProfile(ctx, spec.Binding, spec.Proof.EnvelopeDigest(), proof, replayKeyVersion, "")
}
