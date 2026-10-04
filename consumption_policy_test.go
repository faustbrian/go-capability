package capability_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	capmemory "github.com/faustbrian/go-capability/adapters/memory"
	compatmemory "github.com/faustbrian/go-capability/memory"
)

func TestGrantConsumptionSanitizesPolicyErrors(t *testing.T) {
	grant := ordinaryConsumptionGrant(t, 1)
	diagnostic := errors.New("ordinary storage diagnostic")
	for _, policy := range []error{capability.ErrReplayExhausted, capability.ErrReplayConflict} {
		t.Run(policy.Error(), func(t *testing.T) {
			for _, variant := range []struct {
				name           string
				cause          error
				classification error
			}{
				{name: "bare", cause: policy},
				{name: "wrapped", cause: fmt.Errorf("ordinary storage diagnostic: %w", policy)},
				{name: "nested", cause: fmt.Errorf("ordinary outer diagnostic: %w", fmt.Errorf("ordinary inner diagnostic: %w", policy))},
				{name: "joined", cause: errors.Join(policy, diagnostic)},
				{name: "canceled", cause: fmt.Errorf("ordinary storage diagnostic: %w", errors.Join(policy, diagnostic, context.Canceled)), classification: context.Canceled},
				{name: "deadline", cause: fmt.Errorf("ordinary storage diagnostic: %w", errors.Join(policy, diagnostic, context.DeadlineExceeded)), classification: context.DeadlineExceeded},
				{name: "context precedence", cause: errors.Join(policy, diagnostic, context.Canceled, context.DeadlineExceeded), classification: context.Canceled},
			} {
				t.Run(variant.name, func(t *testing.T) {
					store := capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
						return capability.ConsumptionResult{}, variant.cause
					})
					result, err := grant.Consume(context.Background(), store)
					if result != (capability.ConsumptionResult{}) {
						t.Fatalf("policy failure returned a successful consumption result")
					}
					if !errors.Is(err, policy) || errors.Is(err, capability.ErrConsumptionUnknown) {
						t.Fatalf("policy classification changed")
					}
					if err.Error() != policy.Error() || errors.Is(err, diagnostic) ||
						(variant.cause != policy && errors.Is(err, variant.cause)) {
						t.Errorf("policy failure retained collaborator diagnostics or error graph")
					}
					for _, classification := range []error{context.Canceled, context.DeadlineExceeded} {
						if errors.Is(err, classification) != (classification == variant.classification) {
							t.Errorf("safe context classification changed")
						}
					}
				})
			}
		})
	}
}

func TestGrantConsumptionPreservesJoinedPolicyClassifications(t *testing.T) {
	grant := ordinaryConsumptionGrant(t, 1)
	diagnostic := errors.New("ordinary storage diagnostic")
	cause := errors.Join(capability.ErrReplayExhausted, capability.ErrReplayConflict, diagnostic)
	result, err := grant.Consume(context.Background(), capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
		return capability.ConsumptionResult{}, cause
	}))
	if result != (capability.ConsumptionResult{}) ||
		!errors.Is(err, capability.ErrReplayExhausted) || !errors.Is(err, capability.ErrReplayConflict) ||
		errors.Is(err, capability.ErrConsumptionUnknown) {
		t.Fatal("joined policy classifications changed")
	}
	if errors.Is(err, cause) || errors.Is(err, diagnostic) ||
		err.Error() != errors.Join(capability.ErrReplayExhausted, capability.ErrReplayConflict).Error() {
		t.Fatal("joined policy error retained collaborator diagnostics or error graph")
	}
}

func TestGrantConsumptionPreservesUnknownOutcomes(t *testing.T) {
	grant := ordinaryConsumptionGrant(t, 1)
	diagnostic := errors.New("ordinary storage diagnostic")
	for _, classification := range []error{nil, context.Canceled, context.DeadlineExceeded} {
		cause := diagnostic
		if classification != nil {
			cause = errors.Join(diagnostic, classification)
		}
		result, err := grant.Consume(context.Background(), capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
			return capability.ConsumptionResult{}, cause
		}))
		if result != (capability.ConsumptionResult{}) || !errors.Is(err, capability.ErrConsumptionUnknown) ||
			errors.Is(err, capability.ErrReplayExhausted) || errors.Is(err, capability.ErrReplayConflict) {
			t.Fatal("unknown outcome classification changed")
		}
		if errors.Is(err, diagnostic) || errors.Is(err, cause) || err.Error() != capability.ErrConsumptionUnknown.Error() {
			t.Fatal("unknown outcome retained collaborator diagnostics or error graph")
		}
		for _, candidate := range []error{context.Canceled, context.DeadlineExceeded} {
			if errors.Is(err, candidate) != (candidate == classification) {
				t.Fatal("unknown outcome lost safe context classification")
			}
		}
	}
}

func TestGrantConsumptionPreservesMemoryAccountingAndReusableGrants(t *testing.T) {
	canonical, err := capmemory.NewConsumptionStore(ordinaryConsumptionClock{})
	if err != nil {
		t.Fatal("construct canonical memory store")
	}
	compatibility, err := compatmemory.NewConsumptionStore(ordinaryConsumptionClock{})
	if err != nil {
		t.Fatal("construct compatibility memory store")
	}
	for name, store := range map[string]capability.ConsumptionStore{"canonical": canonical, "compatibility": compatibility} {
		t.Run(name, func(t *testing.T) {
			grant := ordinaryConsumptionGrant(t, 2)
			for use := uint32(1); use <= 2; use++ {
				result, consumeErr := grant.Consume(context.Background(), store)
				if consumeErr != nil || result != (capability.ConsumptionResult{Use: use, Remaining: 2 - use}) {
					t.Fatal("successful use accounting changed")
				}
			}
			if result, consumeErr := grant.Consume(context.Background(), store); result != (capability.ConsumptionResult{}) || consumeErr != capability.ErrReplayExhausted {
				t.Fatal("exhausted bare policy identity changed")
			}
			conflict := ordinaryConsumptionGrant(t, 3)
			if result, consumeErr := conflict.Consume(context.Background(), store); result != (capability.ConsumptionResult{}) || consumeErr != capability.ErrReplayConflict {
				t.Fatal("conflicting bare policy identity changed")
			}
		})
	}
	if result, err := ordinaryConsumptionGrant(t, 0).Consume(context.Background(), nil); err != nil || result != (capability.ConsumptionResult{Reusable: true}) {
		t.Fatal("reusable grant behavior changed")
	}
}

type ordinaryConsumptionClock struct{}

func (ordinaryConsumptionClock) Now() time.Time {
	return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
}

func ordinaryConsumptionGrant(t *testing.T, maxUses uint32) capability.Grant {
	t.Helper()
	now := (ordinaryConsumptionClock{}).Now()
	payload := capability.Payload{
		Version: 1, Issuer: "ordinary-issuer", Audiences: []string{"ordinary-audience"},
		Bearer: true, Resource: "ordinary-resource", Operation: "read",
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "ordinary-capability",
		MaxUses: maxUses,
	}
	// This generated, fixed-size test value is not an operational signing key.
	key := make([]byte, 32)
	signer, err := capability.NewHMACSHA256Signer("ordinary-key", key)
	if err != nil {
		t.Fatal("construct test signer")
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal("construct test verifier")
	}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal("issue ordinary grant")
	}
	grant, err := capability.Verify(context.Background(), token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	}), capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal("verify ordinary grant")
	}
	return grant
}
