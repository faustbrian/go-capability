package capability_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/golib/pkg/capability"
	capmemory "github.com/faustbrian/golib/pkg/capability/memory"
)

func TestMemoryConsumptionIsAtomicAtTheUseLimit(t *testing.T) {
	clock := fixedClock{now: testNow}
	store, err := capmemory.NewConsumptionStore(clock)
	if err != nil {
		t.Fatalf("NewConsumptionStore() error = %v", err)
	}
	grant := verifiedGrantWithMaxUses(t, 1)
	const contenders = 32
	var consumed atomic.Int64
	var exhausted atomic.Int64
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			result, consumeErr := grant.Consume(context.Background(), store)
			switch {
			case consumeErr == nil:
				if result.Use != 1 || result.Remaining != 0 {
					t.Errorf("Consume() result = %#v", result)
				}
				consumed.Add(1)
			case errors.Is(consumeErr, capability.ErrReplayExhausted):
				exhausted.Add(1)
			default:
				t.Errorf("Consume() error = %v", consumeErr)
			}
		}()
	}
	wait.Wait()
	if consumed.Load() != 1 || exhausted.Load() != contenders-1 {
		t.Fatalf("consumed = %d, exhausted = %d", consumed.Load(), exhausted.Load())
	}
}

func TestConsumptionSupportsBoundedAndReusableCapabilities(t *testing.T) {
	store, _ := capmemory.NewConsumptionStore(fixedClock{now: testNow})
	grant := verifiedGrantWithMaxUses(t, 2)
	first, err := grant.Consume(context.Background(), store)
	if err != nil || first.Use != 1 || first.Remaining != 1 {
		t.Fatalf("first Consume() = %#v, %v", first, err)
	}
	second, err := grant.Consume(context.Background(), store)
	if err != nil || second.Use != 2 || second.Remaining != 0 {
		t.Fatalf("second Consume() = %#v, %v", second, err)
	}
	if _, err := grant.Consume(context.Background(), store); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatalf("third Consume() error = %v", err)
	}

	reusable := verifiedGrantWithMaxUses(t, 0)
	result, err := reusable.Consume(context.Background(), nil)
	if err != nil || !result.Reusable {
		t.Fatalf("reusable Consume() = %#v, %v", result, err)
	}
}

func TestConsumptionStoreRejectsConflictingIdentityAndExpiresState(t *testing.T) {
	clock := &mutableClock{now: testNow}
	store, _ := capmemory.NewConsumptionStore(clock)
	request := capability.Consumption{CapabilityID: "cap-42", MaxUses: 2, ExpiresAt: testNow.Add(time.Minute)}
	if _, err := store.Consume(context.Background(), request); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	conflict := request
	conflict.MaxUses = 3
	if _, err := store.Consume(context.Background(), conflict); !errors.Is(err, capability.ErrReplayConflict) {
		t.Fatalf("Consume(conflict) error = %v", err)
	}
	clock.now = testNow.Add(2 * time.Minute)
	replacement := request
	replacement.ExpiresAt = clock.now.Add(time.Minute)
	result, err := store.Consume(context.Background(), replacement)
	if err != nil || result.Use != 1 {
		t.Fatalf("Consume(after expiry) = %#v, %v", result, err)
	}
	removed, err := store.Cleanup(context.Background(), clock.now.Add(time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("Cleanup() = %d, %v", removed, err)
	}
}

func TestUnknownConsumptionOutcomeFailsClosed(t *testing.T) {
	grant := verifiedGrantWithMaxUses(t, 1)
	storageErr := errors.New("connection lost after write")
	store := capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
		return capability.ConsumptionResult{}, storageErr
	})
	if _, err := grant.Consume(context.Background(), store); !errors.Is(err, capability.ErrConsumptionUnknown) || errors.Is(err, storageErr) {
		t.Fatalf("Consume() error = %v", err)
	}
}

func TestTerminalConsumptionErrorsRemainDistinctFromUnknownOutcomes(t *testing.T) {
	grant := verifiedGrantWithMaxUses(t, 1)
	for _, terminal := range []error{capability.ErrReplayExhausted, capability.ErrReplayConflict} {
		store := capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
			return capability.ConsumptionResult{}, terminal
		})
		if _, err := grant.Consume(context.Background(), store); err != terminal {
			t.Fatalf("Consume() error = %v, want %v", err, terminal)
		}
	}
}

func verifiedGrantWithMaxUses(t *testing.T, maxUses uint32) capability.Grant {
	t.Helper()
	payload := validPayload()
	payload.MaxUses = maxUses
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("replay-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	grant, err := capability.Verify(context.Background(), token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	}), capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return grant
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type mutableClock struct{ now time.Time }

func (clock *mutableClock) Now() time.Time { return clock.now }
