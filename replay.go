package capability

import (
	"context"
	"errors"
	"time"
)

// Consumption binds an exact authenticated issuer and capability ID to one
// immutable expiry and maximum-use bound. Issuer is required; stores must not
// merge different issuer namespaces even when their capability IDs match.
type Consumption struct {
	Issuer       string
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
// use count remains below MaxUses. ErrCapacity, like ErrReplayExhausted and
// ErrReplayConflict, asserts that no use was committed. Custom adapters are
// trusted to return those classifications only for known no-consume outcomes.
// Any non-policy error may represent an
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
// Store errors retain only replay-policy, capacity, and safe context classifications, not
// the store's diagnostic text or arbitrary causes.
func (grant Grant) Consume(ctx context.Context, store ConsumptionStore) (ConsumptionResult, error) {
	if err := contextError(ctx); err != nil {
		return ConsumptionResult{}, err
	}
	if grant.payload.Issuer == "" {
		return ConsumptionResult{}, ErrInvalidConfiguration
	}
	if grant.payload.MaxUses == 0 {
		return ConsumptionResult{Reusable: true}, nil
	}
	if store == nil {
		return ConsumptionResult{}, ErrInvalidConfiguration
	}
	result, err := store.Consume(ctx, Consumption{
		Issuer:       grant.payload.Issuer,
		CapabilityID: grant.payload.ID,
		ExpiresAt:    grant.payload.ExpiresAt,
		MaxUses:      grant.payload.MaxUses,
	})
	if err == nil {
		return result, nil
	}
	var policies []error
	for _, policy := range []error{ErrReplayExhausted, ErrReplayConflict, ErrCapacity} {
		if errors.Is(err, policy) {
			policies = append(policies, policy)
		}
	}
	if len(policies) == 1 {
		return ConsumptionResult{}, redact(policies[0], err)
	}
	if len(policies) > 1 {
		return ConsumptionResult{}, redact(errors.Join(policies...), err)
	}
	return ConsumptionResult{}, redact(ErrConsumptionUnknown, err)
}
