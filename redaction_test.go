package capability_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

func TestOperationalErrorsPreserveClassificationWithoutExposingDiagnostics(t *testing.T) {
	diagnostic := errors.New("private key bytes and remote endpoint details")
	_, err := capability.Issue(context.Background(), validPayload(), failingSigner{err: diagnostic}, capability.DefaultLimits())
	assertRedactedError(t, err, capability.ErrSigningFailed, diagnostic)
	for name, classification := range map[string]error{
		"canceled": context.Canceled, "deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			privateCause := fmt.Errorf("private signing diagnostic: %w", classification)
			_, classifiedErr := capability.Issue(
				context.Background(), validPayload(), failingSigner{err: privateCause}, capability.DefaultLimits(),
			)
			assertRedactedError(t, classifiedErr, capability.ErrSigningFailed, privateCause)
			if !errors.Is(classifiedErr, classification) {
				t.Fatalf("error omitted safe classification: %v", classifiedErr)
			}
		})
	}

	token, verifier := hmacFixture(t)
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{}, diagnostic
	})
	_, err = capability.Verify(context.Background(), token, resolver, options)
	assertRedactedError(t, err, capability.ErrKeyResolution, diagnostic)

	options.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
		return false, diagnostic
	})
	resolver = capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	_, err = capability.Verify(context.Background(), token, resolver, options)
	assertRedactedError(t, err, capability.ErrRevocationUnknown, diagnostic)

	grant := verifiedGrantWithMaxUses(t, 1)
	_, err = grant.Consume(context.Background(), capability.ConsumptionStoreFunc(func(context.Context, capability.Consumption) (capability.ConsumptionResult, error) {
		return capability.ConsumptionResult{}, diagnostic
	}))
	assertRedactedError(t, err, capability.ErrConsumptionUnknown, diagnostic)
}

type failingSigner struct{ err error }

func (failingSigner) Algorithm() capability.Algorithm { return capability.HMACSHA256 }
func (failingSigner) KeyID() string                   { return "failing-key" }
func (signer failingSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, signer.err
}

func assertRedactedError(t *testing.T, err, kind, cause error) {
	t.Helper()
	if !errors.Is(err, kind) {
		t.Fatalf("error classification = %v", err)
	}
	if errors.Is(err, cause) {
		t.Fatalf("error retained private cause")
	}
	if strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("error exposed diagnostic: %q", err)
	}
}
