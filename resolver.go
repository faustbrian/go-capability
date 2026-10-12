package capability

import (
	"context"
	"time"
)

// Key is immutable verifier policy for one globally unique key ID owned by
// exactly one explicit issuer namespace.
type Key struct {
	// Issuer is required independently established key ownership, never inferred from a
	// token.
	Issuer string
	// ID is required globally unique exact key identity with a 256-byte ceiling.
	ID string
	// Verifier is mandatory borrowed trusted code; concurrent resolution/use requires it to
	// be safe.
	Verifier Verifier
	// Disabled refuses verified use without marking compromise.
	Disabled bool
	// Revoked refuses verified use regardless of Disabled.
	Revoked bool
	// NotBefore is inclusive unskewed activation; zero is open.
	NotBefore time.Time
	// NotAfter is exclusive unskewed expiry; zero is open, otherwise must follow nonzero
	// NotBefore.
	NotAfter time.Time
}

// KeySet is an immutable in-process resolver suitable for explicit rotation overlap.
// Construct with NewKeySet; zero Resolve returns ErrUnknownKey. Policy values
// are copied, Verifiers remain borrowed and must support concurrent use. Publish
// a new set for rotation; no refresh, worker or close lifecycle is owned.
type KeySet struct{ keys map[string]ResolvedKey }

// NewKeySet copies nonempty key policy into a snapshot but borrows Verifier
// objects. Duplicate globally unique IDs are rejected even across algorithms. No
// key-count cap or typed-nil detection is added; invalid identity/lifecycle
// returns nil and ErrInvalidConfiguration.
func NewKeySet(keys []Key) (*KeySet, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidConfiguration
	}
	resolved := make(map[string]ResolvedKey, len(keys))
	for _, key := range keys {
		if !validText(key.ID, DefaultLimits().MaxFieldBytes, true) ||
			!validText(key.Issuer, DefaultLimits().MaxFieldBytes, true) || key.Verifier == nil ||
			!validAlgorithm(key.Verifier.Algorithm()) ||
			(!key.NotBefore.IsZero() && !key.NotAfter.IsZero() && !key.NotBefore.Before(key.NotAfter)) {
			return nil, ErrInvalidConfiguration
		}
		if _, exists := resolved[key.ID]; exists {
			return nil, ErrInvalidConfiguration
		}
		resolved[key.ID] = ResolvedKey{
			Issuer:   key.Issuer,
			Verifier: key.Verifier, Disabled: key.Disabled, Revoked: key.Revoked,
			NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		}
	}
	return &KeySet{keys: resolved}, nil
}

// Resolve returns copied local policy plus its borrowed Verifier. Non-nil ctx is
// required; missing keys return ErrUnknownKey and algorithm mismatch returns
// ErrAlgorithmMismatch. It does not enforce key activation/revocation or
// selected issuer equality; Verify owns those checks.
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
	// Source is mandatory borrowed policy; it must honor context and return promptly.
	Source Resolver
	// Timeout must be positive and bounds a cooperative source, not arbitrary callback
	// execution.
	Timeout time.Duration
	// AllowedAlgorithms must be nonempty/unique built-in constructions and is copied into
	// an allowlist.
	AllowedAlgorithms []Algorithm
	// MaxKeyIDBytes must be positive and at most 256, checked before a source call.
	MaxKeyIDBytes int
}

// BoundedResolver constrains remote key lookups by algorithm, identifier size, and deadline.
// Construct with NewBoundedResolver; zero is unusable. It owns no cache or
// goroutine and cannot forcibly stop a source ignoring context. Shared use
// requires safe borrowed source/verifier methods.
type BoundedResolver struct {
	source        Resolver
	timeout       time.Duration
	algorithms    map[Algorithm]struct{}
	maxKeyIDBytes int
}

// NewBoundedResolver copies a nonempty unique algorithm allowlist while
// borrowing Source. Invalid bounds return nil and ErrInvalidConfiguration. It
// does not call the source, start workers or create a timer until Resolve.
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

// Resolve admits key/algorithm before one timed source call and rechecks issuer
// text plus verifier binding. Verify still owns lifecycle and selected-issuer
// equality. Source errors retain safe key/algorithm/context categories, not
// diagnostics. It does not forcibly interrupt or independently reject a source
// returning successfully after its deadline.
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
		return ResolvedKey{}, redactResolver(err)
	}
	if resolved.Verifier == nil {
		return ResolvedKey{}, ErrUnknownKey
	}
	if resolved.Verifier.Algorithm() != algorithm {
		return ResolvedKey{}, ErrAlgorithmMismatch
	}
	if !validText(resolved.Issuer, DefaultLimits().MaxFieldBytes, true) {
		return ResolvedKey{}, ErrInvalidConfiguration
	}
	return resolved, nil
}
