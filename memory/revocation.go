package memory

import (
	"context"
	"time"

	"github.com/faustbrian/go-capability"
	capabilitymemory "github.com/faustbrian/go-capability/adapters/memory"
)

// Revocations preserves the released compatibility-path type identity while
// delegating all behavior to the canonical adapter.
type Revocations struct {
	canonical *capabilitymemory.Revocations
}

// NewRevocations constructs an empty process-local revocation set.
func NewRevocations() *Revocations {
	return &Revocations{canonical: capabilitymemory.NewRevocations()}
}

// RevokeCapability revokes one capability ID within an issuer namespace.
func (store *Revocations) RevokeCapability(ctx context.Context, issuer, capabilityID string) error {
	return store.canonical.RevokeCapability(ctx, issuer, capabilityID)
}

// RevokeKey revokes every capability signed by one key ID for an issuer.
func (store *Revocations) RevokeKey(ctx context.Context, issuer, keyID string) error {
	return store.canonical.RevokeKey(ctx, issuer, keyID)
}

// RevokeSubject revokes every subject-bound capability for an issuer.
func (store *Revocations) RevokeSubject(ctx context.Context, issuer, subject string) error {
	return store.canonical.RevokeSubject(ctx, issuer, subject)
}

// RevokeResource revokes an exact issuer, tenant, and resource boundary.
func (store *Revocations) RevokeResource(ctx context.Context, issuer, tenant, resource string) error {
	return store.canonical.RevokeResource(ctx, issuer, tenant, resource)
}

// RevokeIssuedBefore revokes capabilities issued strictly before cutoff.
func (store *Revocations) RevokeIssuedBefore(ctx context.Context, issuer string, cutoff time.Time) error {
	return store.canonical.RevokeIssuedBefore(ctx, issuer, cutoff)
}

// Check reports whether any exact revocation boundary matches query.
func (store *Revocations) Check(ctx context.Context, query capability.RevocationQuery) (bool, error) {
	return store.canonical.Check(ctx, query)
}
