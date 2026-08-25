package capability_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

func TestKeySetBindsKeyIDsToOneAlgorithmAndLifecycle(t *testing.T) {
	hmacVerifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	set, err := capability.NewKeySet([]capability.Key{
		{ID: "current", Verifier: hmacVerifier},
		{ID: "previous", Verifier: hmacVerifier, Disabled: true, NotAfter: testNow.Add(time.Hour)},
	})
	if err != nil {
		t.Fatalf("NewKeySet() error = %v", err)
	}
	resolved, err := set.Resolve(context.Background(), "previous", capability.HMACSHA256)
	if err != nil || !resolved.Disabled || !resolved.NotAfter.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
	if _, err := set.Resolve(context.Background(), "missing", capability.HMACSHA256); !errors.Is(err, capability.ErrUnknownKey) {
		t.Fatalf("Resolve(missing) error = %v", err)
	}
	if _, err := set.Resolve(context.Background(), "current", capability.Ed25519); !errors.Is(err, capability.ErrAlgorithmMismatch) {
		t.Fatalf("Resolve(wrong algorithm) error = %v", err)
	}
	if _, err := capability.NewKeySet([]capability.Key{{ID: "same", Verifier: hmacVerifier}, {ID: "same", Verifier: hmacVerifier}}); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewKeySet(duplicate ID) error = %v", err)
	}
}

func TestKeySetAcceptsAnOpenEndedNotBeforeBoundary(t *testing.T) {
	hmacVerifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	set, err := capability.NewKeySet([]capability.Key{{
		ID: "future", Verifier: hmacVerifier, NotBefore: testNow,
	}})
	if err != nil {
		t.Fatalf("NewKeySet() error = %v", err)
	}
	resolved, err := set.Resolve(context.Background(), "future", capability.HMACSHA256)
	if err != nil || !resolved.NotBefore.Equal(testNow) || !resolved.NotAfter.IsZero() {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
}

func TestBoundedResolverRestrictsAlgorithmsKeyIDsAndDuration(t *testing.T) {
	hmacVerifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	source := capability.ResolverFunc(func(ctx context.Context, _ string, _ capability.Algorithm) (capability.ResolvedKey, error) {
		select {
		case <-ctx.Done():
			return capability.ResolvedKey{}, ctx.Err()
		case <-time.After(time.Second):
			return capability.ResolvedKey{Verifier: hmacVerifier}, nil
		}
	})
	resolver, err := capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: source, Timeout: 10 * time.Millisecond,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}, MaxKeyIDBytes: 16,
	})
	if err != nil {
		t.Fatalf("NewBoundedResolver() error = %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), "key", capability.HMACSHA256); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Resolve(timeout) error = %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), "key", capability.Ed25519); !errors.Is(err, capability.ErrAlgorithmMismatch) {
		t.Fatalf("Resolve(algorithm) error = %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), "key-id-is-too-long", capability.HMACSHA256); !errors.Is(err, capability.ErrUnknownKey) {
		t.Fatalf("Resolve(long key ID) error = %v", err)
	}
}

func TestResolverConfigurationAndSuccessfulRemoteBinding(t *testing.T) {
	hmacVerifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	invalidKeys := [][]capability.Key{
		nil,
		{{ID: "", Verifier: hmacVerifier}},
		{{ID: "key"}},
		{{ID: "key", Verifier: algorithmVerifier{algorithm: "unknown"}}},
		{{ID: "key", Verifier: hmacVerifier, NotBefore: testNow, NotAfter: testNow}},
	}
	for index, keys := range invalidKeys {
		if _, err := capability.NewKeySet(keys); !errors.Is(err, capability.ErrInvalidConfiguration) {
			t.Fatalf("NewKeySet(%d) error = %v", index, err)
		}
	}
	set, _ := capability.NewKeySet([]capability.Key{{ID: "key", Verifier: hmacVerifier}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := set.Resolve(ctx, "key", capability.HMACSHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve(canceled) error = %v", err)
	}

	invalidOptions := []capability.BoundedResolverOptions{
		{},
		{Source: set, Timeout: time.Second, MaxKeyIDBytes: 16},
		{Source: set, Timeout: 0, MaxKeyIDBytes: 16, AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}},
		{Source: set, Timeout: time.Second, MaxKeyIDBytes: 0, AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}},
		{Source: set, Timeout: time.Second, MaxKeyIDBytes: 257, AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}},
		{Source: set, Timeout: time.Second, MaxKeyIDBytes: 16, AllowedAlgorithms: []capability.Algorithm{"unknown"}},
		{Source: set, Timeout: time.Second, MaxKeyIDBytes: 16, AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256, capability.HMACSHA256}},
	}
	for index, options := range invalidOptions {
		if _, err := capability.NewBoundedResolver(options); !errors.Is(err, capability.ErrInvalidConfiguration) {
			t.Fatalf("NewBoundedResolver(%d) error = %v", index, err)
		}
	}
	resolver, _ := capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: set, Timeout: time.Second, MaxKeyIDBytes: 16,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256},
	})
	resolved, err := resolver.Resolve(context.Background(), "key", capability.HMACSHA256)
	if err != nil || resolved.Verifier != hmacVerifier {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
	if _, err := resolver.Resolve(ctx, "key", capability.HMACSHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve(canceled) error = %v", err)
	}

	nilSource := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{}, nil
	})
	resolver, _ = capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: nilSource, Timeout: time.Second, MaxKeyIDBytes: 16,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256},
	})
	if _, err := resolver.Resolve(context.Background(), "key", capability.HMACSHA256); !errors.Is(err, capability.ErrUnknownKey) {
		t.Fatalf("Resolve(nil verifier) error = %v", err)
	}
	wrongSource := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: algorithmVerifier{algorithm: capability.Ed25519}}, nil
	})
	resolver, _ = capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: wrongSource, Timeout: time.Second, MaxKeyIDBytes: 16,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256},
	})
	if _, err := resolver.Resolve(context.Background(), "key", capability.HMACSHA256); !errors.Is(err, capability.ErrAlgorithmMismatch) {
		t.Fatalf("Resolve(wrong verifier) error = %v", err)
	}
}

func TestBoundedResolverAcceptsExactMaximumKeyIDPolicy(t *testing.T) {
	hmacVerifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	set, _ := capability.NewKeySet([]capability.Key{{ID: "key", Verifier: hmacVerifier}})
	resolver, err := capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: set, Timeout: time.Nanosecond, MaxKeyIDBytes: capability.DefaultLimits().MaxFieldBytes,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256},
	})
	if err != nil || resolver == nil {
		t.Fatalf("NewBoundedResolver(exact maximum) = %#v, %v", resolver, err)
	}
}

func TestBoundedResolverObservesRotationRemovalWithoutCaching(t *testing.T) {
	hmacVerifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	var mu sync.RWMutex
	current := capability.ResolvedKey{Verifier: hmacVerifier}
	source := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		mu.RLock()
		defer mu.RUnlock()
		if current.Verifier == nil {
			return capability.ResolvedKey{}, capability.ErrUnknownKey
		}
		return current, nil
	})
	resolver, err := capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: source, Timeout: time.Second, MaxKeyIDBytes: 16,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256},
	})
	if err != nil {
		t.Fatalf("NewBoundedResolver() error = %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), "old-key", capability.HMACSHA256); err != nil {
		t.Fatalf("Resolve(overlap) error = %v", err)
	}
	mu.Lock()
	current = capability.ResolvedKey{}
	mu.Unlock()
	if _, err := resolver.Resolve(context.Background(), "old-key", capability.HMACSHA256); !errors.Is(err, capability.ErrUnknownKey) {
		t.Fatalf("Resolve(after removal) error = %v", err)
	}
}

type algorithmVerifier struct{ algorithm capability.Algorithm }

func (verifier algorithmVerifier) Algorithm() capability.Algorithm     { return verifier.algorithm }
func (algorithmVerifier) Verify(context.Context, []byte, []byte) error { return nil }
