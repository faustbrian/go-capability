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

// NewConsumptionStore constructs an empty process-local store.
func NewConsumptionStore(clock Clock) (*ConsumptionStore, error) {
	store, err := capabilitymemory.NewConsumptionStore(clock)
	if err != nil {
		return nil, err
	}
	return &ConsumptionStore{canonical: store}, nil
}

// Consume atomically records one use or returns ErrReplayExhausted without incrementing.
func (store *ConsumptionStore) Consume(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
	return store.canonical.Consume(ctx, request)
}

// Cleanup removes state expiring at or before cutoff and returns the number removed.
func (store *ConsumptionStore) Cleanup(ctx context.Context, cutoff time.Time) (int, error) {
	return store.canonical.Cleanup(ctx, cutoff)
}
