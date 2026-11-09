package identitycapability

import "github.com/faustbrian/go-capability/v2"

// Grants returns the original authenticated grants in immutable plan order,
// including after checkpoint or local encrypted restoration. The returned slice
// belongs to the caller; each Grant's Payload also returns defensive copies.
// Zero, failed or internally inconsistent preparation returns InvalidInput and
// no grants. Like Plan, this method requires serial use of the preparation while
// checkpoint or transfer is active; immutable completed values permit reads.
//
// Projection performs only bounded local metadata checks. It does not invoke
// signing, verification, clock, resolver or revocation collaborators, transfer
// bearer custody, consume a grant, extend expiry or establish fresh authority.
// The caller must still enforce current time, revocation and native ownership
// policy at their proper admission and protected execution phases.
func (p PreparedIssuance) Grants() ([]capability.Grant, error) {
	if p.state == nil || p.state.preparationFailed || p.state.owner == nil || len(p.state.grants) != len(p.state.plan.Grants) {
		return nil, invalid()
	}
	s := p.state
	if s.owner.ValidateCapabilityIssuance(s.binding, s.plan) != nil {
		return nil, invalid()
	}
	subject, _ := issuerPlanSubject(s.binding, s.plan)
	for n, grant := range s.grants {
		metadata, err := s.owner.grantSubjectPlan(s.binding, subject, grant, s.plan.Grants[n].ReplayKeyVersion)
		if err != nil || metadata != s.plan.Grants[n] {
			return nil, invalid()
		}
	}
	return append([]capability.Grant(nil), s.grants...), nil
}
