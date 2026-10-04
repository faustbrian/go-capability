package capabilitymemory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/faustbrian/go-capability"
)

type issuerValue struct{ issuer, value string }
type resourceValue struct{ issuer, tenant, resource string }

// Revocations is a concurrency-safe finite process-local revocation set. Its
// five maps share one admission budget and never evict entries. Trusted
// administrative callers must handle ErrCapacity from every writer: a failed
// insertion is not a revocation. Construct it with NewRevocations or
// NewRevocationsWithLimits; its zero value is not usable.
type Revocations struct {
	mu           sync.RWMutex
	capabilities map[issuerValue]struct{}
	keys         map[issuerValue]struct{}
	subjects     map[issuerValue]struct{}
	resources    map[resourceValue]struct{}
	issuedBefore map[string]*time.Time
	budget       admission
}

// NewRevocations constructs an empty set with DefaultStoreLimits.
func NewRevocations() *Revocations {
	store, _ := NewRevocationsWithLimits(DefaultStoreLimits())
	return store
}

// NewRevocationsWithLimits copies explicit positive budgets. Invalid limits
// return ErrInvalidConfiguration. Duplicate writes and existing cutoff
// updates need no additional admission, even at capacity.
func NewRevocationsWithLimits(limits StoreLimits) (*Revocations, error) {
	if limits.MaxRecords <= 0 || limits.MaxStringBytes <= 0 {
		return nil, capability.ErrInvalidConfiguration
	}
	return &Revocations{
		capabilities: make(map[issuerValue]struct{}), keys: make(map[issuerValue]struct{}),
		subjects: make(map[issuerValue]struct{}), resources: make(map[resourceValue]struct{}),
		issuedBefore: make(map[string]*time.Time),
		budget:       admission{limits: limits},
	}, nil
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
	size, admitted := store.budget.size(issuer, tenant, resource)
	if !admitted {
		return capability.ErrCapacity
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := resourceValue{issuer: issuer, tenant: tenant, resource: resource}
	if _, exists := store.resources[key]; exists {
		return nil
	}
	if !store.budget.reserve(size) {
		return capability.ErrCapacity
	}
	store.resources[resourceValue{issuer: strings.Clone(issuer), tenant: strings.Clone(tenant), resource: strings.Clone(resource)}] = struct{}{}
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
	size, admitted := store.budget.size(issuer)
	if !admitted {
		return capability.ErrCapacity
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if current, exists := store.issuedBefore[issuer]; exists {
		// In-place updates also preserve the originally cloned map key.
		if cutoff.After(*current) {
			*current = cutoff
		}
		return nil
	}
	if !store.budget.reserve(size) {
		return capability.ErrCapacity
	}
	store.issuedBefore[strings.Clone(issuer)] = &cutoff
	return nil
}

// Check reports whether any exact revocation boundary matches query. Its
// aggregate input string length must fit MaxStringBytes before any map lookup;
// otherwise it returns false, ErrCapacity. Verify sanitizes checker failures
// as ErrRevocationUnknown and returns no grant.
func (store *Revocations) Check(ctx context.Context, query capability.RevocationQuery) (bool, error) {
	if err := validContext(ctx); err != nil {
		return false, err
	}
	if _, admitted := store.budget.size(query.Issuer, query.CapabilityID, query.KeyID, query.Subject, query.Tenant, query.Resource); !admitted {
		return false, capability.ErrCapacity
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
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
	return cutoff != nil && query.IssuedAt.Before(*cutoff), nil
}

func (store *Revocations) add(ctx context.Context, issuer, value string, target map[issuerValue]struct{}) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if issuer == "" || value == "" {
		return capability.ErrInvalidConfiguration
	}
	size, admitted := store.budget.size(issuer, value)
	if !admitted {
		return capability.ErrCapacity
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := issuerValue{issuer: issuer, value: value}
	if _, exists := target[key]; exists {
		return nil
	}
	if !store.budget.reserve(size) {
		return capability.ErrCapacity
	}
	target[issuerValue{issuer: strings.Clone(issuer), value: strings.Clone(value)}] = struct{}{}
	return nil
}

func validContext(ctx context.Context) error {
	if ctx == nil {
		return capability.ErrInvalidConfiguration
	}
	return ctx.Err()
}
