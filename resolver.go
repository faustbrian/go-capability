package capability

import (
	"context"
	"time"
)

// Key is immutable verifier policy for one globally unique key ID.
type Key struct {
	ID        string
	Verifier  Verifier
	Disabled  bool
	Revoked   bool
	NotBefore time.Time
	NotAfter  time.Time
}

// KeySet is an immutable in-process resolver suitable for explicit rotation overlap.
type KeySet struct{ keys map[string]ResolvedKey }

// NewKeySet validates and copies key lifecycle policy. A key ID binds exactly
// one algorithm, so duplicate IDs are rejected even when key types differ.
func NewKeySet(keys []Key) (*KeySet, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidConfiguration
	}
	resolved := make(map[string]ResolvedKey, len(keys))
	for _, key := range keys {
		if !validText(key.ID, DefaultLimits().MaxFieldBytes, true) || key.Verifier == nil ||
			!validAlgorithm(key.Verifier.Algorithm()) ||
			(!key.NotBefore.IsZero() && !key.NotAfter.IsZero() && !key.NotBefore.Before(key.NotAfter)) {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := resolved[key.ID]; exists {
			return nil, ErrInvalidConfiguration
		}
		resolved[key.ID] = ResolvedKey{
			Verifier: key.Verifier, Disabled: key.Disabled, Revoked: key.Revoked,
			NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		}
	}
	return &KeySet{keys: resolved}, nil
}

// Resolve returns immutable local key policy.
func (set *KeySet) Resolve(ctx context.Context, keyID string, algorithm Algorithm) (ResolvedKey, error) {
	if err := contextError(ctx); err != nil {
		return ResolvedKey{}, err
	}
	resolved, exists := set.keys[keyID]
	if !exists {
		return ResolvedKey{}, ErrUnknownKey
	}
	if resolved.Verifier.Algorithm() != algorithm {
		return ResolvedKey{}, ErrAlgorithmMismatch
	}
	return resolved, nil
}

// BoundedResolverOptions limits a caller-provided remote key source. Source
// must honor context cancellation; this adapter creates no hidden goroutines.
type BoundedResolverOptions struct {
	Source            Resolver
	Timeout           time.Duration
	AllowedAlgorithms []Algorithm
	MaxKeyIDBytes     int
}

// BoundedResolver constrains remote key lookups by algorithm, identifier size, and deadline.
type BoundedResolver struct {
	source        Resolver
	timeout       time.Duration
	algorithms    map[Algorithm]struct{}
	maxKeyIDBytes int
}

// NewBoundedResolver validates remote resolution policy.
func NewBoundedResolver(options BoundedResolverOptions) (*BoundedResolver, error) {
	if options.Source == nil || options.Timeout <= 0 || options.MaxKeyIDBytes <= 0 ||
		options.MaxKeyIDBytes > DefaultLimits().MaxFieldBytes || len(options.AllowedAlgorithms) == 0 {
		return nil, ErrInvalidConfiguration
	}
	algorithms := make(map[Algorithm]struct{}, len(options.AllowedAlgorithms))
	for _, algorithm := range options.AllowedAlgorithms {
		if !validAlgorithm(algorithm) {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := algorithms[algorithm]; exists {
			return nil, ErrInvalidConfiguration
		}
		algorithms[algorithm] = struct{}{}
	}
	return &BoundedResolver{
		source: options.Source, timeout: options.Timeout,
		algorithms: algorithms, maxKeyIDBytes: options.MaxKeyIDBytes,
	}, nil
}

// Resolve calls the remote source under the configured deadline and rechecks algorithm binding.
func (resolver *BoundedResolver) Resolve(ctx context.Context, keyID string, algorithm Algorithm) (ResolvedKey, error) {
	if err := contextError(ctx); err != nil {
		return ResolvedKey{}, err
	}
	if !validText(keyID, resolver.maxKeyIDBytes, true) {
		return ResolvedKey{}, ErrUnknownKey
	}
	if _, allowed := resolver.algorithms[algorithm]; !allowed {
		return ResolvedKey{}, ErrAlgorithmMismatch
	}
	lookupContext, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	resolved, err := resolver.source.Resolve(lookupContext, keyID, algorithm)
	if err != nil {
		return ResolvedKey{}, redact(ErrKeyResolution, err)
	}
	if resolved.Verifier == nil {
		return ResolvedKey{}, ErrUnknownKey
	}
	if resolved.Verifier.Algorithm() != algorithm {
		return ResolvedKey{}, ErrAlgorithmMismatch
	}
	return resolved, nil
}
