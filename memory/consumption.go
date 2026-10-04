// Package memory is the compatibility facade for the target-oriented
// process-local replay and revocation adapter.
//
// Deprecated: use github.com/faustbrian/go-capability/adapters/memory. This
// package remains supported through the documented compatibility interval.
package memory

import (
	"context"
	"time"

	"github.com/faustbrian/go-capability"
	capabilitymemory "github.com/faustbrian/go-capability/adapters/memory"
)

// Clock supplies wall time for expiry decisions.
type Clock interface {
	Now() time.Time
}

// ConsumptionStore preserves the released compatibility-path type identity
// while delegating all behavior to the canonical adapter.
type ConsumptionStore struct {
	canonical *capabilitymemory.ConsumptionStore
}

// NewConsumptionStore constructs an empty store with DefaultStoreLimits.
func NewConsumptionStore(clock Clock) (*ConsumptionStore, error) {
	return NewConsumptionStoreWithLimits(clock, DefaultStoreLimits())
}

// NewConsumptionStoreWithLimits constructs a store with explicit positive budgets.
func NewConsumptionStoreWithLimits(clock Clock, limits StoreLimits) (*ConsumptionStore, error) {
	store, err := capabilitymemory.NewConsumptionStoreWithLimits(clock, limits)
	if err != nil {
		return nil, err
	}
	return &ConsumptionStore{canonical: store}, nil
}

// Consume records a use through the canonical finite store. ErrCapacity is a
// known no-consume refusal; repeats do not charge additional admission.
func (store *ConsumptionStore) Consume(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
	return store.canonical.Consume(ctx, request)
}

// Cleanup releases removed count and string-byte admission. The trusted caller
// must choose a cutoff beyond all relevant acceptance windows to avoid resetting
// live allowance; no background cleanup runs.
func (store *ConsumptionStore) Cleanup(ctx context.Context, cutoff time.Time) (int, error) {
	return store.canonical.Cleanup(ctx, cutoff)
}
