package capability_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	capmemory "github.com/faustbrian/go-capability/v2/adapters/memory"
	//lint:ignore SA1019 The supported facade must preserve issuer-scoped consumption.
	legacy "github.com/faustbrian/go-capability/v2/memory" //nolint:staticcheck // Intentional supported-facade behavior coverage.
)

func TestGrantConsumptionCarriesAuthenticatedIssuer(t *testing.T) {
	grant := ordinaryReplayGrant(t, "issuer-one", 1)
	result, err := grant.Consume(context.Background(), capability.ConsumptionStoreFunc(func(_ context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
		if request.Issuer != "issuer-one" || request.CapabilityID != "ordinary-capability" || request.MaxUses != 1 || !request.ExpiresAt.Equal(grant.Payload().ExpiresAt) {
			t.Error("consumption dropped authenticated identity or bounds")
		}
		return capability.ConsumptionResult{Use: 1}, nil
	}))
	if err != nil || result.Use != 1 {
		t.Fatal("ordinary consumption failed")
	}
	if _, err := (capability.Grant{}).Consume(context.Background(), nil); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatal("missing issuer granted reusable authority")
	}
}

func TestBothMemoryPathsIsolateIssuerReplayIdentity(t *testing.T) {
	for _, makeStore := range []func() capability.ConsumptionStore{
		func() capability.ConsumptionStore {
			s, _ := capmemory.NewConsumptionStore(replayIdentityClock{})
			return s
		},
		func() capability.ConsumptionStore {
			s, _ := legacy.NewConsumptionStore(replayIdentityClock{})
			return s
		},
	} {
		store := makeStore()
		for _, issuer := range []string{"issuer-one", "issuer-two"} {
			grant := ordinaryReplayGrant(t, issuer, 1)
			result, err := grant.Consume(context.Background(), store)
			if err != nil || result.Use != 1 || result.Remaining != 0 {
				t.Error("different issuer shared a quota")
			}
			if _, err := grant.Consume(context.Background(), store); !errors.Is(err, capability.ErrReplayExhausted) {
				t.Error("same issuer regained a quota")
			}
			if _, err := ordinaryReplayGrant(t, issuer, 2).Consume(context.Background(), store); !errors.Is(err, capability.ErrReplayConflict) {
				t.Error("same tuple changed its bound")
			}
			if _, err := store.Consume(context.Background(), capability.Consumption{Issuer: issuer, CapabilityID: "ordinary-capability", MaxUses: 1, ExpiresAt: grant.Payload().ExpiresAt.Add(time.Minute)}); !errors.Is(err, capability.ErrReplayConflict) {
				t.Error("same tuple changed live expiry")
			}
		}
		if _, err := store.Consume(context.Background(), capability.Consumption{CapabilityID: "ordinary-capability", MaxUses: 1, ExpiresAt: replayIdentityClock{}.Now().Add(time.Minute)}); !errors.Is(err, capability.ErrInvalidConfiguration) {
			t.Error("memory accepted missing issuer")
		}
	}
}

type replayIdentityClock struct{}

func (replayIdentityClock) Now() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }

func ordinaryReplayGrant(t *testing.T, issuer string, maximum uint32) capability.Grant {
	t.Helper()
	now := replayIdentityClock{}.Now()
	key := make([]byte, 32)
	signer, _ := capability.NewHMACSHA256Signer("ordinary-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	payload := capability.Payload{Version: 1, Issuer: issuer, Audiences: []string{"ordinary-audience"}, Bearer: true, Resource: "ordinary-resource", Operation: "read", ID: "ordinary-capability", MaxUses: maximum, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal("ordinary issuance failed")
	}
	grant, err := capability.Verify(context.Background(), token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: issuer, Verifier: verifier}, nil
	}), capability.VerifyOptions{Issuer: issuer, Now: now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal("ordinary verification failed")
	}
	return grant
}
