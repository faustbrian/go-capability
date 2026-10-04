package capability_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	capmemory "github.com/faustbrian/go-capability/v2/adapters/memory"
	//lint:ignore SA1019 The supported facade must preserve finite admission semantics.
	legacy "github.com/faustbrian/go-capability/v2/memory" //nolint:staticcheck // Intentional supported-facade coverage.
)

type capacityReplay interface {
	capability.ConsumptionStore
	Cleanup(context.Context, time.Time) (int, error)
}

type capacityRevocations interface {
	capability.RevocationChecker
	RevokeCapability(context.Context, string, string) error
	RevokeKey(context.Context, string, string) error
	RevokeSubject(context.Context, string, string) error
	RevokeResource(context.Context, string, string, string) error
	RevokeIssuedBefore(context.Context, string, time.Time) error
}

var capacityReplayFactories = map[string]func(capmemory.StoreLimits) (capacityReplay, error){
	"canonical": func(l capmemory.StoreLimits) (capacityReplay, error) {
		return capmemory.NewConsumptionStoreWithLimits(replayIdentityClock{}, l)
	},
	"facade": func(l capmemory.StoreLimits) (capacityReplay, error) {
		return legacy.NewConsumptionStoreWithLimits(replayIdentityClock{}, l)
	},
}
var capacityRevocationFactories = map[string]func(capmemory.StoreLimits) (capacityRevocations, error){
	"canonical": func(l capmemory.StoreLimits) (capacityRevocations, error) {
		return capmemory.NewRevocationsWithLimits(l)
	},
	"facade": func(l capmemory.StoreLimits) (capacityRevocations, error) { return legacy.NewRevocationsWithLimits(l) },
}

func TestMemoryReplayFiniteAdmissionAndAccounting(t *testing.T) {
	ctx := context.Background()
	for name, makeStore := range capacityReplayFactories {
		t.Run(name, func(t *testing.T) {
			for _, limits := range []capmemory.StoreLimits{{MaxRecords: 1, MaxStringBytes: 20}, {MaxRecords: 3, MaxStringBytes: 2}} {
				store, err := makeStore(limits)
				if err != nil {
					t.Fatal(err)
				}
				request := capability.Consumption{Issuer: "i", CapabilityID: "a", MaxUses: 3, ExpiresAt: replayIdentityClock{}.Now().Add(time.Minute)}
				if result, err := store.Consume(ctx, request); err != nil || result.Use != 1 {
					t.Fatal("first use not admitted")
				}
				other := request
				other.CapabilityID = "b"
				if result, err := store.Consume(ctx, other); result != (capability.ConsumptionResult{}) || !errors.Is(err, capability.ErrCapacity) {
					t.Error("new identity exceeded count or string budget")
				}
				conflict := request
				conflict.MaxUses++
				if _, err := store.Consume(ctx, conflict); !errors.Is(err, capability.ErrReplayConflict) {
					t.Error("conflict changed at capacity")
				}
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				if _, err := store.Consume(canceled, request); !errors.Is(err, context.Canceled) {
					t.Error("cancellation changed")
				}
				if result, err := store.Consume(ctx, request); err != nil || result.Use != 2 || result.Remaining != 1 {
					t.Error("refusal or cancellation changed existing accounting")
				}
				if removed, err := store.Cleanup(ctx, request.ExpiresAt.Add(-time.Second)); err != nil || removed != 0 {
					t.Error("cleanup removed live state")
				}
				if _, err := store.Consume(ctx, other); !errors.Is(err, capability.ErrCapacity) {
					t.Error("live cleanup released admission")
				}
				if removed, err := store.Cleanup(ctx, request.ExpiresAt); err != nil || removed != 1 {
					t.Error("cleanup did not release exact record")
				}
				if result, err := store.Consume(ctx, other); err != nil || result.Use != 1 {
					t.Error("cleanup did not release exact byte budget")
				}
			}
		})
	}
}

func TestMemoryRevocationsAggregateAdmissionAndMonotonicUpdates(t *testing.T) {
	ctx := context.Background()
	now := replayIdentityClock{}.Now()
	for name, makeStore := range capacityRevocationFactories {
		t.Run(name, func(t *testing.T) {
			for _, limits := range []capmemory.StoreLimits{{MaxRecords: 5, MaxStringBytes: 100}, {MaxRecords: 20, MaxStringBytes: 10}} {
				store, err := makeStore(limits)
				if err != nil {
					t.Fatal(err)
				}
				writers := []func() error{
					func() error { return store.RevokeCapability(ctx, "i", "a") },
					func() error { return store.RevokeKey(ctx, "i", "k") },
					func() error { return store.RevokeSubject(ctx, "i", "s") },
					func() error { return store.RevokeResource(ctx, "i", "t", "r") },
					func() error { return store.RevokeIssuedBefore(ctx, "i", now) },
				}
				for _, write := range writers {
					if err := write(); err != nil {
						t.Fatal("ordinary boundary not admitted", err)
					}
				}
				for _, write := range writers {
					if err := write(); err != nil {
						t.Error("duplicate charged capacity")
					}
				}
				if err := store.RevokeIssuedBefore(ctx, "i", now.Add(time.Second)); err != nil {
					t.Error("later cutoff charged capacity")
				}
				if err := store.RevokeIssuedBefore(ctx, "i", now.Add(-time.Second)); err != nil {
					t.Error("earlier cutoff charged capacity")
				}
				refusals := []func() error{
					func() error { return store.RevokeCapability(ctx, "i", "b") },
					func() error { return store.RevokeKey(ctx, "i", "l") },
					func() error { return store.RevokeSubject(ctx, "i", "u") },
					func() error { return store.RevokeResource(ctx, "i", "t", "q") },
					func() error { return store.RevokeIssuedBefore(ctx, "j", now) },
				}
				for _, write := range refusals {
					if !errors.Is(write(), capability.ErrCapacity) {
						t.Error("five maps did not share aggregate allowance")
					}
				}
				for _, query := range []capability.RevocationQuery{{Issuer: "i", CapabilityID: "a"}, {Issuer: "i", KeyID: "k"}, {Issuer: "i", Subject: "s"}, {Issuer: "i", Tenant: "t", Resource: "r"}, {Issuer: "i", IssuedAt: now}} {
					if revoked, err := store.Check(ctx, query); err != nil || !revoked {
						t.Error("admitted revocation lost or cutoff retreated")
					}
				}
				if revoked, err := store.Check(ctx, capability.RevocationQuery{Issuer: "j", CapabilityID: "b", IssuedAt: now}); err != nil || revoked {
					t.Error("failed insertion mutated unrelated authority")
				}
			}
		})
	}
}

func TestMemoryStringAdmissionAndInvalidLimits(t *testing.T) {
	ctx := context.Background()
	for name, makeStore := range capacityRevocationFactories {
		t.Run(name, func(t *testing.T) {
			store, err := makeStore(capmemory.StoreLimits{MaxRecords: 3, MaxStringBytes: 2})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.RevokeCapability(ctx, "i", "a"); err != nil {
				t.Fatal(err)
			}
			if err := store.RevokeIssuedBefore(ctx, "j", replayIdentityClock{}.Now()); !errors.Is(err, capability.ErrCapacity) {
				t.Error("string bytes not shared across maps")
			}
			if _, err := store.Check(ctx, capability.RevocationQuery{Issuer: "i", CapabilityID: "ab"}); !errors.Is(err, capability.ErrCapacity) {
				t.Error("query hashing admission unbounded")
			}
			if err := store.RevokeResource(ctx, "i", "t", "r"); !errors.Is(err, capability.ErrCapacity) {
				t.Error("write hashing admission unbounded")
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if err := store.RevokeKey(canceled, "i", "k"); !errors.Is(err, context.Canceled) {
				t.Error("revocation cancellation changed")
			}
			if _, err := store.Check(canceled, capability.RevocationQuery{Issuer: "i"}); !errors.Is(err, context.Canceled) {
				t.Error("query cancellation changed")
			}
		})
		for _, limits := range []capmemory.StoreLimits{{MaxRecords: 0, MaxStringBytes: 1}, {MaxRecords: 1, MaxStringBytes: 0}, {MaxRecords: -1, MaxStringBytes: 1}} {
			if _, err := makeStore(limits); !errors.Is(err, capability.ErrInvalidConfiguration) {
				t.Error("invalid revocation limits accepted")
			}
		}
	}
	for _, makeStore := range capacityReplayFactories {
		for _, limits := range []capmemory.StoreLimits{{MaxRecords: 0, MaxStringBytes: 1}, {MaxRecords: 1, MaxStringBytes: 0}, {MaxRecords: 1, MaxStringBytes: -1}} {
			if _, err := makeStore(limits); !errors.Is(err, capability.ErrInvalidConfiguration) {
				t.Error("invalid replay limits accepted")
			}
		}
	}
}

func TestGrantConsumptionPreservesSafeCapacityClassification(t *testing.T) {
	ctx := context.Background()
	grant := ordinaryReplayGrant(t, "issuer-one", 2)
	for name, makeStore := range capacityReplayFactories {
		t.Run(name, func(t *testing.T) {
			store, err := makeStore(capmemory.StoreLimits{MaxRecords: 1, MaxStringBytes: 100})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ordinaryReplayGrant(t, "issuer-two", 1).Consume(ctx, store); err != nil {
				t.Fatal(err)
			}
			if result, err := grant.Consume(ctx, store); result != (capability.ConsumptionResult{}) || !errors.Is(err, capability.ErrCapacity) || errors.Is(err, capability.ErrConsumptionUnknown) {
				t.Error("real Grant lost known no-consume capacity classification")
			}
		})
	}
	diagnostic := errors.New("ordinary collaborator diagnostic")
	for _, cause := range []error{capability.ErrCapacity, fmt.Errorf("ordinary context: %w", capability.ErrCapacity), errors.Join(capability.ErrCapacity, diagnostic, context.Canceled), errors.Join(capability.ErrCapacity, diagnostic, context.DeadlineExceeded), errors.Join(capability.ErrCapacity, capability.ErrReplayConflict, capability.ErrReplayExhausted, diagnostic)} {
		result, err := grant.Consume(ctx, capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
			return capability.ConsumptionResult{Use: 1}, cause
		}))
		if result != (capability.ConsumptionResult{}) || !errors.Is(err, capability.ErrCapacity) || errors.Is(err, capability.ErrConsumptionUnknown) || errors.Is(err, diagnostic) || (cause != capability.ErrCapacity && errors.Is(err, cause)) {
			t.Error("capacity normalization retained diagnostics or lost classification")
		}
		if strings.Contains(err.Error(), diagnostic.Error()) || (cause == capability.ErrCapacity && err != capability.ErrCapacity) {
			t.Error("capacity error exposed diagnostics or lost bare sentinel identity")
		}
		for _, classification := range []error{context.Canceled, context.DeadlineExceeded, capability.ErrReplayConflict, capability.ErrReplayExhausted} {
			if errors.Is(err, classification) != errors.Is(cause, classification) {
				t.Error("safe joined classification changed")
			}
		}
	}
}

func TestBothMemoryRevocationPathsFailClosedDuringRealVerification(t *testing.T) {
	ctx := context.Background()
	grant := ordinaryReplayGrant(t, "issuer-one", 1)
	key := make([]byte, 32)
	signer, _ := capability.NewHMACSHA256Signer("ordinary-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(ctx, grant.Payload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal("ordinary issuance failed")
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: "issuer-one", Verifier: verifier}, nil
	})
	for name, makeStore := range capacityRevocationFactories {
		t.Run(name, func(t *testing.T) {
			store, err := makeStore(capmemory.StoreLimits{MaxRecords: 1, MaxStringBytes: 100})
			if err != nil {
				t.Fatal(err)
			}
			options := capability.VerifyOptions{Issuer: "issuer-one", Now: replayIdentityClock{}.Now(), Limits: capability.DefaultLimits(), Revocations: store}
			if _, err := capability.Verify(ctx, token, resolver, options); err != nil {
				t.Fatal("ordinary unrevoked grant rejected")
			}
			if err := store.RevokeCapability(ctx, "issuer-one", "ordinary-capability"); err != nil {
				t.Fatal(err)
			}
			if err := store.RevokeKey(ctx, "issuer-one", "ordinary-key"); !errors.Is(err, capability.ErrCapacity) {
				t.Error("administrative capacity error missing")
			}
			if _, err := capability.Verify(ctx, token, resolver, options); !errors.Is(err, capability.ErrRevoked) {
				t.Error("capacity refusal erased admitted revocation")
			}
			limited, err := makeStore(capmemory.StoreLimits{MaxRecords: 1, MaxStringBytes: 2})
			if err != nil {
				t.Fatal(err)
			}
			options.Revocations = limited
			if _, err := capability.Verify(ctx, token, resolver, options); !errors.Is(err, capability.ErrRevocationUnknown) || errors.Is(err, capability.ErrCapacity) {
				t.Error("oversized ordinary query did not fail closed through Verify redaction")
			}
		})
	}
}

type capacityClock struct{ now time.Time }

func (clock *capacityClock) Now() time.Time { return clock.now }

func TestBothMemoryReplayPathsReleaseOnlyRemovedBytesAndRenewExpiredIdentity(t *testing.T) {
	ctx := context.Background()
	for _, makeStore := range []func(*capacityClock, capmemory.StoreLimits) (capacityReplay, error){
		func(clock *capacityClock, l capmemory.StoreLimits) (capacityReplay, error) {
			return capmemory.NewConsumptionStoreWithLimits(clock, l)
		},
		func(clock *capacityClock, l capmemory.StoreLimits) (capacityReplay, error) {
			return legacy.NewConsumptionStoreWithLimits(clock, l)
		},
	} {
		clock := &capacityClock{now: replayIdentityClock{}.Now()}
		store, err := makeStore(clock, capmemory.StoreLimits{MaxRecords: 2, MaxStringBytes: 5})
		if err != nil {
			t.Fatal(err)
		}
		first := capability.Consumption{Issuer: "i", CapabilityID: "a", MaxUses: 1, ExpiresAt: clock.now.Add(time.Minute)}
		second := first
		second.CapabilityID = "bb"
		second.ExpiresAt = clock.now.Add(2 * time.Minute)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := store.Consume(canceled, first); !errors.Is(err, context.Canceled) {
			t.Error("new canceled request not rejected")
		}
		for _, request := range []capability.Consumption{first, second} {
			if result, err := store.Consume(ctx, request); err != nil || result.Use != 1 {
				t.Fatal("ordinary records not admitted")
			}
		}
		clock.now = first.ExpiresAt
		if removed, err := store.Cleanup(canceled, first.ExpiresAt); !errors.Is(err, context.Canceled) || removed != 0 {
			t.Error("canceled cleanup changed state")
		}
		if removed, err := store.Cleanup(ctx, first.ExpiresAt); err != nil || removed != 1 {
			t.Error("partial cleanup changed retained count")
		}
		third := first
		third.Issuer = "j"
		third.ExpiresAt = second.ExpiresAt
		if result, err := store.Consume(ctx, third); err != nil || result.Use != 1 {
			t.Error("partial cleanup did not release two bytes")
		}
		if _, err := store.Consume(ctx, second); !errors.Is(err, capability.ErrReplayExhausted) {
			t.Error("partial cleanup reset retained quota")
		}
		clock.now = second.ExpiresAt
		second.ExpiresAt = clock.now.Add(time.Minute)
		second.MaxUses = 2
		if result, err := store.Consume(ctx, second); err != nil || result.Use != 1 || result.Remaining != 1 {
			t.Error("expired identity replacement charged twice or lost renewal semantics")
		}
		if result, err := store.Consume(ctx, second); err != nil || result.Use != 2 {
			t.Error("renewed tuple accounting changed")
		}
	}
}
