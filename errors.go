package capability

import (
	"context"
	"errors"
)

var (
	// ErrInvalidConfiguration reports an unsafe or incomplete caller policy.
	ErrInvalidConfiguration = errors.New("capability: invalid configuration")
	// ErrInvalidPayload reports a malformed or semantically invalid payload.
	ErrInvalidPayload = errors.New("capability: invalid payload")
	// ErrNonCanonical reports a valid representation that is not the unique v1 encoding.
	ErrNonCanonical = errors.New("capability: non-canonical encoding")
	// ErrInvalidToken reports malformed token framing or protected metadata.
	ErrInvalidToken = errors.New("capability: invalid token")
	// ErrInvalidSignature reports that the protected token did not authenticate.
	ErrInvalidSignature = errors.New("capability: invalid signature")
	// ErrSigningFailed reports a signer failure without exposing its diagnostic.
	ErrSigningFailed = errors.New("capability: signing failed")
	// ErrKeyResolution reports a resolver failure without exposing its diagnostic.
	ErrKeyResolution = errors.New("capability: key resolution failed")
	// ErrAlgorithmMismatch reports an algorithm and key-type mismatch.
	ErrAlgorithmMismatch = errors.New("capability: algorithm mismatch")
	// ErrUnknownKey reports an unresolved key identifier.
	ErrUnknownKey = errors.New("capability: unknown key")
	// ErrKeyDisabled reports a key that policy has disabled without revoking it.
	ErrKeyDisabled = errors.New("capability: key disabled")
	// ErrKeyRevoked reports a key that policy has revoked.
	ErrKeyRevoked = errors.New("capability: key revoked")
	// ErrKeyNotActive reports a key outside its configured activation interval.
	ErrKeyNotActive = errors.New("capability: key not active")
	// ErrNotYetValid reports a capability used before its validity interval.
	ErrNotYetValid = errors.New("capability: not yet valid")
	// ErrExpired reports a capability used after its validity interval.
	ErrExpired = errors.New("capability: expired")
	// ErrUnauthorized reports that a verified grant does not cover a requested use.
	ErrUnauthorized = errors.New("capability: unauthorized use")
	// ErrInvalidURL reports a URL or profile with ambiguous or unsafe semantics.
	ErrInvalidURL = errors.New("capability: invalid URL")
	// ErrURLBinding reports a valid capability presented for a different URL use.
	ErrURLBinding = errors.New("capability: URL binding mismatch")
	// ErrReplayExhausted reports a capability whose bounded uses were consumed.
	ErrReplayExhausted = errors.New("capability: use limit exhausted")
	// ErrReplayConflict reports inconsistent state for one capability identity.
	ErrReplayConflict = errors.New("capability: replay state conflict")
	// ErrConsumptionUnknown reports a store failure whose commit outcome is unknown.
	ErrConsumptionUnknown = errors.New("capability: consumption outcome unknown")
	// ErrRevoked reports authority matched by a configured revocation boundary.
	ErrRevoked = errors.New("capability: revoked")
	// ErrRevocationUnknown reports a revocation check that could not complete.
	ErrRevocationUnknown = errors.New("capability: revocation status unknown")
	// ErrAdapterProtocol reports a malformed durable-adapter response.
	ErrAdapterProtocol = errors.New("capability: adapter protocol violation")
)

type safeError struct {
	kind           error
	classification error
}

func (failure *safeError) Error() string { return failure.kind.Error() }

func (failure *safeError) Unwrap() []error {
	return []error{failure.kind, failure.classification}
}

func redact(kind, cause error) error {
	switch {
	case errors.Is(cause, context.Canceled):
		return &safeError{kind: kind, classification: context.Canceled}
	case errors.Is(cause, context.DeadlineExceeded):
		return &safeError{kind: kind, classification: context.DeadlineExceeded}
	default:
		return kind
	}
}
