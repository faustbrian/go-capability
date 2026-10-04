// Package capabilitymemory provides process-local replay and revocation
// adapters. State is not shared across processes and therefore cannot provide
// cluster-wide one-time or instant revocation semantics.
package capabilitymemory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/faustbrian/go-capability"
)

// Clock supplies wall time for expiry decisions.
type Clock interface {
	Now() time.Time
}

type consumptionRecord struct {
	uses      uint32
	maxUses   uint32
	expiresAt time.Time
}

type consumptionIdentity struct{ issuer, capabilityID string }

// ConsumptionStore owns finite process-local atomic replay state. Construct it
// with NewConsumptionStore or NewConsumptionStoreWithLimits; its zero value is
// not usable. Records are never evicted to make room for another identity.
type ConsumptionStore struct {
	mu      sync.Mutex
	clock   Clock
	records map[consumptionIdentity]*consumptionRecord
	budget  admission
}

// NewConsumptionStore constructs an empty store with DefaultStoreLimits.
func NewConsumptionStore(clock Clock) (*ConsumptionStore, error) {
	return NewConsumptionStoreWithLimits(clock, DefaultStoreLimits())
}

// NewConsumptionStoreWithLimits copies explicit positive budgets. Invalid
// limits or a nil clock return ErrInvalidConfiguration. Clock remains trusted
// caller-owned code and must be safe for concurrent use.
func NewConsumptionStoreWithLimits(clock Clock, limits StoreLimits) (*ConsumptionStore, error) {
	if clock == nil || limits.MaxRecords <= 0 || limits.MaxStringBytes <= 0 {
		return nil, capability.ErrInvalidConfiguration
	}
	return &ConsumptionStore{clock: clock, records: make(map[consumptionIdentity]*consumptionRecord), budget: admission{limits: limits}}, nil
}

// Consume atomically records one use. ErrCapacity refuses an oversized identity
// or new record before consumption without eviction or allowance reset.
// Repeats use no additional admission; live conflicting bounds return
// ErrReplayConflict and exhausted records return ErrReplayExhausted.
func (store *ConsumptionStore) Consume(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
	if ctx == nil {
		return capability.ConsumptionResult{}, capability.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return capability.ConsumptionResult{}, err
	}
	now := store.clock.Now()
	if request.Issuer == "" || request.CapabilityID == "" || request.MaxUses == 0 || !request.ExpiresAt.After(now) {
		return capability.ConsumptionResult{}, capability.ErrInvalidConfiguration
	}
	size, admitted := store.budget.size(request.Issuer, request.CapabilityID)
	if !admitted {
		return capability.ConsumptionResult{}, capability.ErrCapacity
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return capability.ConsumptionResult{}, err
	}
	identity := consumptionIdentity{issuer: request.Issuer, capabilityID: request.CapabilityID}
	record, exists := store.records[identity]
	if exists && !record.expiresAt.After(now) {
		delete(store.records, identity)
		store.budget.release(size)
		exists = false
	}
	if exists && (record.maxUses != request.MaxUses || !record.expiresAt.Equal(request.ExpiresAt)) {
		return capability.ConsumptionResult{}, capability.ErrReplayConflict
	}
	if !exists {
		if !store.budget.reserve(size) {
			return capability.ConsumptionResult{}, capability.ErrCapacity
		}
		identity = consumptionIdentity{issuer: strings.Clone(request.Issuer), capabilityID: strings.Clone(request.CapabilityID)}
		record = &consumptionRecord{maxUses: request.MaxUses, expiresAt: request.ExpiresAt}
		// Update the record through its pointer thereafter: reassigning an equal
		// map key could replace the owned strings with caller-backed strings.
		store.records[identity] = record
	}
	if record.uses >= record.maxUses {
		return capability.ConsumptionResult{}, capability.ErrReplayExhausted
	}
	record.uses++
	return capability.ConsumptionResult{Use: record.uses, Remaining: record.maxUses - record.uses}, nil
}

// Cleanup removes state expiring at or before cutoff and releases its admission.
// The trusted caller must choose a cutoff beyond all relevant acceptance windows;
// removing live state can reset its allowance. No background cleanup runs.
func (store *ConsumptionStore) Cleanup(ctx context.Context, cutoff time.Time) (int, error) {
	if ctx == nil || cutoff.IsZero() {
		return 0, capability.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	removed := 0
	for capabilityID, record := range store.records {
		if !record.expiresAt.After(cutoff) {
			delete(store.records, capabilityID)
			store.budget.release(len(capabilityID.issuer) + len(capabilityID.capabilityID))
			removed++
		}
	}
	return removed, nil
}
