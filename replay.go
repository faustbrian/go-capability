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
	// Issuer is required authenticated namespace; never merge equal IDs across issuers.
	Issuer string
	// CapabilityID is required exact signed identity, not an application transaction ID.
	CapabilityID string
	// ExpiresAt is signed expiry bound; each store applies its own clock and supported
	// precision.
	ExpiresAt time.Time
	// MaxUses must be positive for direct store calls and remains immutable for live
	// identity.
	MaxUses uint32
}

// ConsumptionResult is the committed use ordinal and remaining allowance.
type ConsumptionResult struct {
	// Use is the one-based committed ordinal for bounded uses; zero for reusable grants.
	Use uint32
	// Remaining is the allowance after this committed use, not a reservation for future
	// operations.
	Remaining uint32
	// Reusable is true only for the core unbounded-use shortcut; Use/Remaining are then
	// zero.
	Reusable bool
}

// ConsumptionStore atomically increments a capability only when its committed
// use count remains below MaxUses. ErrCapacity, like ErrReplayExhausted and
// ErrReplayConflict, asserts that no use was committed. Custom adapters are
// trusted to return those classifications only for known no-consume outcomes.
// Any non-policy error may represent an
// unknown commit outcome and callers must fail closed rather than retry blindly.
type ConsumptionStore interface {
	// Consume atomically compares exact issuer/ID, live expiry/max and count before
	// increment. Honor ctx; document server clock/precision, retention and unknown
	// commit windows.
	Consume(context.Context, Consumption) (ConsumptionResult, error)
}

// ConsumptionStoreFunc adapts a function to ConsumptionStore.
type ConsumptionStoreFunc func(context.Context, Consumption) (ConsumptionResult, error)

// Consume implements ConsumptionStore.
func (function ConsumptionStoreFunc) Consume(ctx context.Context, consumption Consumption) (ConsumptionResult, error) {
	return function(ctx, consumption)
}

// Consume forwards authenticated issuer/ID/expiry/max for one atomic bounded
// use; reusable grants need no store. Non-nil ctx and verified grant are
// required. It performs no Authorize, clock or revocation recheck, and trusts
// successful custom results. Store errors retain only no-consume
// policy/capacity/context categories or ErrConsumptionUnknown, not arbitrary
// graphs/text. Callbacks/typed nil remain trusted; business effects are not
// coupled (DEC-008).
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
	switch len(policies) {
	case 0:
		return ConsumptionResult{}, redact(ErrConsumptionUnknown, err)
	case 1:
		return ConsumptionResult{}, redact(policies[0], err)
	default:
		return ConsumptionResult{}, redact(errors.Join(policies...), err)
	}
}
