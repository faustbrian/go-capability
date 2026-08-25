package memory

import (
	"context"
	"sync"
	"time"

	"github.com/faustbrian/go-capability"
)

type issuerValue struct{ issuer, value string }
type resourceValue struct{ issuer, tenant, resource string }

// Revocations is a concurrency-safe process-local revocation set.
type Revocations struct {
	mu           sync.RWMutex
	capabilities map[issuerValue]struct{}
	keys         map[issuerValue]struct{}
	subjects     map[issuerValue]struct{}
	resources    map[resourceValue]struct{}
	issuedBefore map[string]time.Time
}

// NewRevocations constructs an empty process-local revocation set.
func NewRevocations() *Revocations {
	return &Revocations{
		capabilities: make(map[issuerValue]struct{}), keys: make(map[issuerValue]struct{}),
		subjects: make(map[issuerValue]struct{}), resources: make(map[resourceValue]struct{}),
		issuedBefore: make(map[string]time.Time),
	}
}

// RevokeCapability revokes one capability ID within an issuer namespace.
func (store *Revocations) RevokeCapability(ctx context.Context, issuer, capabilityID string) error {
	return store.add(ctx, issuer, capabilityID, store.capabilities)
}

// RevokeKey revokes every capability signed by one key ID for an issuer.
func (store *Revocations) RevokeKey(ctx context.Context, issuer, keyID string) error {
	return store.add(ctx, issuer, keyID, store.keys)
}

// RevokeSubject revokes every subject-bound capability for an issuer.
func (store *Revocations) RevokeSubject(ctx context.Context, issuer, subject string) error {
	return store.add(ctx, issuer, subject, store.subjects)
}

// RevokeResource revokes an exact issuer, tenant, and resource boundary.
func (store *Revocations) RevokeResource(ctx context.Context, issuer, tenant, resource string) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if issuer == "" || resource == "" {
		return capability.ErrInvalidConfiguration
	}
	store.mu.Lock()
	store.resources[resourceValue{issuer: issuer, tenant: tenant, resource: resource}] = struct{}{}
	store.mu.Unlock()
	return nil
}

// RevokeIssuedBefore revokes capabilities issued strictly before cutoff. A
// later cutoff replaces an earlier one; the boundary never moves backward.
func (store *Revocations) RevokeIssuedBefore(ctx context.Context, issuer string, cutoff time.Time) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if issuer == "" || cutoff.IsZero() {
		return capability.ErrInvalidConfiguration
	}
	store.mu.Lock()
	if current := store.issuedBefore[issuer]; cutoff.After(current) {
		store.issuedBefore[issuer] = cutoff
	}
	store.mu.Unlock()
	return nil
}

// Check reports whether any exact revocation boundary matches query.
func (store *Revocations) Check(ctx context.Context, query capability.RevocationQuery) (bool, error) {
	if err := validContext(ctx); err != nil {
		return false, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if _, found := store.capabilities[issuerValue{issuer: query.Issuer, value: query.CapabilityID}]; found {
		return true, nil
	}
	if _, found := store.keys[issuerValue{issuer: query.Issuer, value: query.KeyID}]; found {
		return true, nil
	}
	if query.Subject != "" {
		if _, found := store.subjects[issuerValue{issuer: query.Issuer, value: query.Subject}]; found {
			return true, nil
		}
	}
	if _, found := store.resources[resourceValue{issuer: query.Issuer, tenant: query.Tenant, resource: query.Resource}]; found {
		return true, nil
	}
	cutoff := store.issuedBefore[query.Issuer]
	return !cutoff.IsZero() && query.IssuedAt.Before(cutoff), nil
}

func (store *Revocations) add(ctx context.Context, issuer, value string, target map[issuerValue]struct{}) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if issuer == "" || value == "" {
		return capability.ErrInvalidConfiguration
	}
	store.mu.Lock()
	target[issuerValue{issuer: issuer, value: value}] = struct{}{}
	store.mu.Unlock()
	return nil
}

func validContext(ctx context.Context) error {
	if ctx == nil {
		return capability.ErrInvalidConfiguration
	}
	return ctx.Err()
}
