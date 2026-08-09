package capability

import (
	"context"
	"errors"
	"time"
)

// Consumption is the immutable identity and bound for one atomic use attempt.
type Consumption struct {
	CapabilityID string
	ExpiresAt    time.Time
	MaxUses      uint32
}

// ConsumptionResult is the committed use ordinal and remaining allowance.
type ConsumptionResult struct {
	Use       uint32
	Remaining uint32
	Reusable  bool
}

// ConsumptionStore atomically increments a capability only when its committed
// use count remains below MaxUses. Any non-policy error may represent an
// unknown commit outcome and callers must fail closed rather than retry blindly.
type ConsumptionStore interface {
	Consume(context.Context, Consumption) (ConsumptionResult, error)
}

// ConsumptionStoreFunc adapts a function to ConsumptionStore.
type ConsumptionStoreFunc func(context.Context, Consumption) (ConsumptionResult, error)

// Consume implements ConsumptionStore.
func (function ConsumptionStoreFunc) Consume(ctx context.Context, consumption Consumption) (ConsumptionResult, error) {
	return function(ctx, consumption)
}

// Consume atomically records one bounded use. Reusable grants do not require a store.
func (grant Grant) Consume(ctx context.Context, store ConsumptionStore) (ConsumptionResult, error) {
	if err := contextError(ctx); err != nil {
		return ConsumptionResult{}, err
	}
	if grant.payload.MaxUses == 0 {
		return ConsumptionResult{Reusable: true}, nil
	}
	if store == nil {
		return ConsumptionResult{}, ErrInvalidConfiguration
	}
	result, err := store.Consume(ctx, Consumption{
		CapabilityID: grant.payload.ID,
		ExpiresAt:    grant.payload.ExpiresAt,
		MaxUses:      grant.payload.MaxUses,
	})
	if err == nil {
		return result, nil
	}
	if errors.Is(err, ErrReplayExhausted) || errors.Is(err, ErrReplayConflict) {
		return ConsumptionResult{}, err
	}
	return ConsumptionResult{}, redact(ErrConsumptionUnknown, err)
}
