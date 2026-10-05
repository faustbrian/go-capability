package capabilitymemory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

type refusalClock struct{ now time.Time }

func (clock refusalClock) Now() time.Time { return clock.now }

// MEMORY-OVERSIZE: rejected identities neither retain state nor spend admission.
func TestOversizedMemoryIdentitiesPreserveAdmission(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	limits := StoreLimits{MaxRecords: 1, MaxStringBytes: 4}
	store, err := NewConsumptionStoreWithLimits(refusalClock{now}, limits)
	if err != nil {
		t.Fatal(err)
	}
	request := capability.Consumption{Issuer: "aa", CapabilityID: "bb", MaxUses: 2, ExpiresAt: now.Add(time.Hour)}
	oversized := request
	oversized.Issuer = "aaa"
	result, err := store.Consume(context.Background(), oversized)
	if !errors.Is(err, capability.ErrCapacity) || result != (capability.ConsumptionResult{}) {
		t.Fatalf("oversized Consume = %#v, %v", result, err)
	}
	for use := uint32(1); use <= 2; use++ {
		result, err = store.Consume(context.Background(), request)
		if err != nil || result.Use != use || result.Remaining != 2-use {
			t.Fatalf("exact Consume = %#v, %v", result, err)
		}
	}
	for _, cutoff := range []bool{false, true} {
		revocations, err := NewRevocationsWithLimits(limits)
		if err != nil {
			t.Fatal(err)
		}
		if cutoff {
			err = revocations.RevokeIssuedBefore(context.Background(), "aaaaa", now)
		} else {
			err = revocations.RevokeCapability(context.Background(), "aaa", "bb")
		}
		if !errors.Is(err, capability.ErrCapacity) {
			t.Fatalf("oversized revocation = %v", err)
		}
		query := capability.RevocationQuery{Issuer: "aa", CapabilityID: "bb"}
		if cutoff {
			err = revocations.RevokeIssuedBefore(context.Background(), "aaaa", now)
			query = capability.RevocationQuery{Issuer: "aaaa", IssuedAt: now.Add(-time.Second)}
		} else {
			err = revocations.RevokeCapability(context.Background(), "aa", "bb")
		}
		if err != nil {
			t.Fatal("oversized refusal spent admission")
		}
		revoked, err := revocations.Check(context.Background(), query)
		if err != nil || !revoked {
			t.Fatal("exact-limit revocation was not retained")
		}
	}
}

// entryContext reports a completed initial Err observation. The parent holds
// the store lock until cancellation, so the operation cannot pass the second
// check before cancellation. Err always comes from a real cancelable context.
type entryContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *entryContext) Err() error {
	err := ctx.Context.Err()
	ctx.once.Do(func() { close(ctx.entered) })
	return err
}

func canceledAfterEntry(t *testing.T, lock sync.Locker, operation func(context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	observed := &entryContext{Context: ctx, entered: make(chan struct{})}
	lock.Lock()
	result := make(chan error, 1)
	go func() { result <- operation(observed) }()
	select {
	case <-observed.entered:
		cancel()
	case <-ctx.Done():
		lock.Unlock()
		<-result
		t.Fatal("operation did not reach its initial context check")
	}
	lock.Unlock()
	// Joining before inspecting results prevents fixtures from outliving the test.
	return <-result
}

// MEMORY-LATE-CANCEL: cancellation between admission and lock acquisition must
// refuse without spending replay allowance or deleting retained records.
func TestConsumptionLateCancellationPreservesState(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store, err := NewConsumptionStore(refusalClock{now})
	if err != nil {
		t.Fatal(err)
	}
	request := capability.Consumption{Issuer: "ordinary-issuer", CapabilityID: "ordinary-capability", MaxUses: 3, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.Consume(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var result capability.ConsumptionResult
	err = canceledAfterEntry(t, &store.mu, func(ctx context.Context) error {
		var err error
		result, err = store.Consume(ctx, request)
		return err
	})
	if !errors.Is(err, context.Canceled) || result != (capability.ConsumptionResult{}) {
		t.Fatalf("late canceled Consume = %#v, %v", result, err)
	}
	result, err = store.Consume(context.Background(), request)
	if err != nil || result.Use != 2 || result.Remaining != 1 {
		t.Fatal("canceled use changed retained allowance")
	}
	var removed int
	err = canceledAfterEntry(t, &store.mu, func(ctx context.Context) error {
		var err error
		removed, err = store.Cleanup(ctx, request.ExpiresAt)
		return err
	})
	if !errors.Is(err, context.Canceled) || removed != 0 {
		t.Fatalf("late canceled Cleanup = %d, %v", removed, err)
	}
	result, err = store.Consume(context.Background(), request)
	if err != nil || result.Use != 3 || result.Remaining != 0 {
		t.Fatal("canceled cleanup reset retained allowance")
	}
}

func TestRevocationLateCancellationPreservesState(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	for _, boundary := range []string{"capability", "resource", "cutoff", "check"} {
		t.Run(boundary, func(t *testing.T) {
			store := NewRevocations()
			query := capability.RevocationQuery{Issuer: "ordinary-issuer", CapabilityID: "ordinary-capability", Resource: "ordinary-resource", IssuedAt: now}
			operation := func(ctx context.Context) error { return store.RevokeCapability(ctx, query.Issuer, query.CapabilityID) }
			var observed bool
			switch boundary {
			case "resource":
				operation = func(ctx context.Context) error { return store.RevokeResource(ctx, query.Issuer, "", query.Resource) }
			case "cutoff":
				if err := store.RevokeIssuedBefore(context.Background(), query.Issuer, now.Add(-time.Minute)); err != nil {
					t.Fatal(err)
				}
				operation = func(ctx context.Context) error {
					return store.RevokeIssuedBefore(ctx, query.Issuer, now.Add(time.Minute))
				}
			case "check":
				if err := store.RevokeCapability(context.Background(), query.Issuer, query.CapabilityID); err != nil {
					t.Fatal(err)
				}
				operation = func(ctx context.Context) error {
					var err error
					observed, err = store.Check(ctx, query)
					return err
				}
			}
			err := canceledAfterEntry(t, &store.mu, operation)
			if !errors.Is(err, context.Canceled) || observed {
				t.Fatalf("late canceled operation = %t, %v", observed, err)
			}
			revoked, err := store.Check(context.Background(), query)
			if err != nil || revoked != (boundary == "check") {
				t.Fatal("canceled operation changed revocation or cutoff state")
			}
			if boundary != "check" {
				if err := operation(context.Background()); err != nil {
					t.Fatal(err)
				}
				revoked, err = store.Check(context.Background(), query)
				if err != nil || !revoked {
					t.Fatal("fresh operation did not retain revocation")
				}
			}
		})
	}
}
