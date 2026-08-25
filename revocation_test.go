package capability_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	capmemory "github.com/faustbrian/go-capability/memory"
)

func TestVerificationChecksEveryRevocationBoundary(t *testing.T) {
	payload := validPayload()
	payload.Bearer = false
	payload.Subject = "user-7"
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	boundaries := []func(*capmemory.Revocations) error{
		func(store *capmemory.Revocations) error {
			return store.RevokeCapability(context.Background(), "https://issuer.example", "cap-42")
		},
		func(store *capmemory.Revocations) error {
			return store.RevokeKey(context.Background(), "https://issuer.example", "key")
		},
		func(store *capmemory.Revocations) error {
			return store.RevokeSubject(context.Background(), "https://issuer.example", "user-7")
		},
		func(store *capmemory.Revocations) error {
			return store.RevokeResource(context.Background(), "https://issuer.example", "tenant-7", "documents/report-42")
		},
		func(store *capmemory.Revocations) error {
			return store.RevokeIssuedBefore(context.Background(), "https://issuer.example", testNow.Add(time.Second))
		},
	}
	for index, revoke := range boundaries {
		store := capmemory.NewRevocations()
		if err := revoke(store); err != nil {
			t.Fatalf("boundary %d revoke error = %v", index, err)
		}
		options.Revocations = store
		if _, err := capability.Verify(context.Background(), token, resolver, options); !errors.Is(err, capability.ErrRevoked) {
			t.Fatalf("boundary %d Verify() error = %v", index, err)
		}
	}
}

func TestRevocationOutageAndCancellationFailClosed(t *testing.T) {
	token, verifier := hmacFixture(t)
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	storeErr := errors.New("revocation store offline")
	checker := capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
		return false, storeErr
	})
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits(), Revocations: checker}
	if _, err := capability.Verify(context.Background(), token, resolver, options); !errors.Is(err, capability.ErrRevocationUnknown) || errors.Is(err, storeErr) {
		t.Fatalf("Verify() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := capability.Verify(ctx, token, resolver, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify(canceled) error = %v", err)
	}
}
