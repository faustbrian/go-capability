package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/golib/pkg/capability"
	"github.com/faustbrian/golib/pkg/capability/memory"
)

func TestConsumptionStoreValidationCleanupAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if _, err := memory.NewConsumptionStore(nil); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewConsumptionStore(nil) error = %v", err)
	}
	clock := &clock{now: now}
	store, _ := memory.NewConsumptionStore(clock)
	valid := capability.Consumption{CapabilityID: "cap", MaxUses: 2, ExpiresAt: now.Add(time.Minute)}
	for name, test := range map[string]struct {
		ctx     context.Context
		request capability.Consumption
		want    error
	}{
		"nil context": {request: valid, want: capability.ErrInvalidConfiguration},
		"empty ID":    {ctx: context.Background(), request: capability.Consumption{MaxUses: 1, ExpiresAt: valid.ExpiresAt}, want: capability.ErrInvalidConfiguration},
		"zero uses":   {ctx: context.Background(), request: capability.Consumption{CapabilityID: "cap", ExpiresAt: valid.ExpiresAt}, want: capability.ErrInvalidConfiguration},
		"expired":     {ctx: context.Background(), request: capability.Consumption{CapabilityID: "cap", MaxUses: 1, ExpiresAt: now}, want: capability.ErrInvalidConfiguration},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Consume(test.ctx, test.request); !errors.Is(err, test.want) {
				t.Fatalf("Consume() error = %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Consume(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("Consume(canceled) error = %v", err)
	}
	first, err := store.Consume(context.Background(), valid)
	if err != nil || first.Use != 1 || first.Remaining != 1 {
		t.Fatalf("Consume() = %#v, %v", first, err)
	}
	conflict := valid
	conflict.MaxUses = 3
	if _, err := store.Consume(context.Background(), conflict); !errors.Is(err, capability.ErrReplayConflict) {
		t.Fatalf("Consume(conflict) error = %v", err)
	}
	second, err := store.Consume(context.Background(), valid)
	if err != nil || second.Use != 2 || second.Remaining != 0 {
		t.Fatalf("Consume(second) = %#v, %v", second, err)
	}
	if _, err := store.Consume(context.Background(), valid); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatalf("Consume(exhausted) error = %v", err)
	}
	clock.now = now.Add(2 * time.Minute)
	valid.ExpiresAt = clock.now.Add(time.Minute)
	result, err := store.Consume(context.Background(), valid)
	if err != nil || result.Use != 1 {
		t.Fatalf("Consume(after expiry) = %#v, %v", result, err)
	}
	var nilContext context.Context
	if _, err := store.Cleanup(nilContext, clock.now); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Cleanup(nil) error = %v", err)
	}
	if _, err := store.Cleanup(context.Background(), time.Time{}); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Cleanup(zero) error = %v", err)
	}
	if _, err := store.Cleanup(ctx, clock.now); !errors.Is(err, context.Canceled) {
		t.Fatalf("Cleanup(canceled) error = %v", err)
	}
	removed, err := store.Cleanup(context.Background(), clock.now.Add(time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("Cleanup() = %d, %v", removed, err)
	}
	removed, err = store.Cleanup(context.Background(), clock.now.Add(time.Hour))
	if err != nil || removed != 0 {
		t.Fatalf("second Cleanup() = %d, %v", removed, err)
	}
}

func TestRevocationsValidateAndKeepMonotonicCutoff(t *testing.T) {
	store := memory.NewRevocations()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.RevokeCapability(ctx, "issuer", "cap"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RevokeCapability(canceled) error = %v", err)
	}
	var nilContext context.Context
	if err := store.RevokeKey(nilContext, "issuer", "key"); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("RevokeKey(nil) error = %v", err)
	}
	if err := store.RevokeSubject(context.Background(), "", "subject"); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("RevokeSubject(empty issuer) error = %v", err)
	}
	if err := store.RevokeResource(context.Background(), "", "tenant", "resource"); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("RevokeResource(empty issuer) error = %v", err)
	}
	if err := store.RevokeResource(ctx, "issuer", "tenant", "resource"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RevokeResource(canceled) error = %v", err)
	}
	if err := store.RevokeIssuedBefore(context.Background(), "issuer", time.Time{}); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("RevokeIssuedBefore(zero) error = %v", err)
	}
	if _, err := store.Check(ctx, capability.RevocationQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check(canceled) error = %v", err)
	}
	if err := store.RevokeIssuedBefore(ctx, "issuer", laterTime()); !errors.Is(err, context.Canceled) {
		t.Fatalf("RevokeIssuedBefore(canceled) error = %v", err)
	}
	if err := store.RevokeCapability(context.Background(), "issuer", ""); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("RevokeCapability(empty ID) error = %v", err)
	}

	if err := store.RevokeCapability(context.Background(), "issuer", "cap"); err != nil {
		t.Fatalf("RevokeCapability() error = %v", err)
	}
	if err := store.RevokeKey(context.Background(), "issuer", "key"); err != nil {
		t.Fatalf("RevokeKey() error = %v", err)
	}
	if err := store.RevokeSubject(context.Background(), "issuer", "subject"); err != nil {
		t.Fatalf("RevokeSubject() error = %v", err)
	}
	if err := store.RevokeResource(context.Background(), "issuer", "tenant", "resource"); err != nil {
		t.Fatalf("RevokeResource() error = %v", err)
	}
	for name, query := range map[string]capability.RevocationQuery{
		"capability": {Issuer: "issuer", CapabilityID: "cap", IssuedAt: laterTime()},
		"key":        {Issuer: "issuer", KeyID: "key", IssuedAt: laterTime()},
		"subject":    {Issuer: "issuer", Subject: "subject", IssuedAt: laterTime()},
		"resource":   {Issuer: "issuer", Tenant: "tenant", Resource: "resource", IssuedAt: laterTime()},
	} {
		t.Run("revoked "+name, func(t *testing.T) {
			revoked, err := store.Check(context.Background(), query)
			if err != nil || !revoked {
				t.Fatalf("Check() = %t, %v", revoked, err)
			}
		})
	}

	later := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if err := store.RevokeIssuedBefore(context.Background(), "issuer", later); err != nil {
		t.Fatalf("RevokeIssuedBefore() error = %v", err)
	}
	if err := store.RevokeIssuedBefore(context.Background(), "issuer", later.Add(-time.Hour)); err != nil {
		t.Fatalf("RevokeIssuedBefore(earlier) error = %v", err)
	}
	for name, query := range map[string]capability.RevocationQuery{
		"at cutoff":    {Issuer: "issuer", IssuedAt: later},
		"other issuer": {Issuer: "other", IssuedAt: later.Add(-time.Hour)},
		"bearer":       {Issuer: "issuer", Subject: "", IssuedAt: later.Add(time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			revoked, err := store.Check(context.Background(), query)
			if err != nil || revoked {
				t.Fatalf("Check() = %t, %v", revoked, err)
			}
		})
	}
}

func laterTime() time.Time {
	return time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
}

type clock struct{ now time.Time }

func (clock *clock) Now() time.Time { return clock.now }
