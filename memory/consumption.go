// Package memory provides process-local replay and revocation adapters. State
// is not shared across processes and therefore cannot provide cluster-wide
// one-time or instant revocation semantics.
package memory

import (
	"context"
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

// ConsumptionStore owns process-local atomic replay state.
type ConsumptionStore struct {
	mu      sync.Mutex
	clock   Clock
	records map[string]consumptionRecord
}

// NewConsumptionStore constructs an empty process-local store.
func NewConsumptionStore(clock Clock) (*ConsumptionStore, error) {
	if clock == nil {
		return nil, capability.ErrInvalidConfiguration
	}
	return &ConsumptionStore{clock: clock, records: make(map[string]consumptionRecord)}, nil
}

// Consume atomically records one use or returns ErrReplayExhausted without incrementing.
func (store *ConsumptionStore) Consume(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
	if ctx == nil {
		return capability.ConsumptionResult{}, capability.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return capability.ConsumptionResult{}, err
	}
	now := store.clock.Now()
	if request.CapabilityID == "" || request.MaxUses == 0 || !request.ExpiresAt.After(now) {
		return capability.ConsumptionResult{}, capability.ErrInvalidConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[request.CapabilityID]
	if exists && !record.expiresAt.After(now) {
		delete(store.records, request.CapabilityID)
		exists = false
	}
	if exists && (record.maxUses != request.MaxUses || !record.expiresAt.Equal(request.ExpiresAt)) {
		return capability.ConsumptionResult{}, capability.ErrReplayConflict
	}
	if !exists {
		record = consumptionRecord{maxUses: request.MaxUses, expiresAt: request.ExpiresAt}
	}
	if record.uses >= record.maxUses {
		return capability.ConsumptionResult{}, capability.ErrReplayExhausted
	}
	record.uses++
	store.records[request.CapabilityID] = record
	return capability.ConsumptionResult{Use: record.uses, Remaining: record.maxUses - record.uses}, nil
}

// Cleanup removes state expiring at or before cutoff and returns the number removed.
func (store *ConsumptionStore) Cleanup(ctx context.Context, cutoff time.Time) (int, error) {
	if ctx == nil || cutoff.IsZero() {
		return 0, capability.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	removed := 0
	for capabilityID, record := range store.records {
		if !record.expiresAt.After(cutoff) {
			delete(store.records, capabilityID)
			removed++
		}
	}
	return removed, nil
}
