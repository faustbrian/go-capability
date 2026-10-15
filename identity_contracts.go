package capability

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Purpose names one literal operation. Dots are punctuation, not hierarchy;
// no wildcard, prefix, case folding or cross-purpose matching is supported.
// Its zero value is invalid.
type Purpose string

// NewPurpose accepts 1..128 ASCII bytes matching
// [A-Za-z0-9][A-Za-z0-9._-]*. It never normalizes caller input.
func NewPurpose(value string) (Purpose, error) {
	if len(value) == 0 || len(value) > 128 {
		return "", ErrInvalidPayload
	}
	for index := range len(value) {
		c := value[index]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if index != 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}
		return "", ErrInvalidPayload
	}
	return Purpose(value), nil
}

// Reference is non-secret lookup metadata, never authority. It is a mutable
// value: applications must validate reconstructed values before storage/use.
type Reference struct {
	CapabilityID string
	Purpose      Purpose
	Digest       [32]byte
	ExpiresAt    time.Time
}

// NewReference validates a bounded ID, literal purpose, nonzero caller-supplied
// digest and positive UTC-second expiry. It cannot authenticate the digest's
// preimage or prove that a capability exists. Service.Issue derives its digest
// from the documented domain-separated canonical token framing.
func NewReference(id string, purpose Purpose, digest [32]byte, expiry time.Time) (Reference, error) {
	if !validText(id, 256, true) {
		return Reference{}, ErrInvalidPayload
	}
	if _, err := NewPurpose(string(purpose)); err != nil {
		return Reference{}, err
	}
	if digest == ([32]byte{}) || expiry.IsZero() || expiry.Unix() <= 0 || expiry.Nanosecond() != 0 || expiry.Location() != time.UTC {
		return Reference{}, ErrInvalidPayload
	}
	return Reference{CapabilityID: id, Purpose: purpose, Digest: digest, ExpiresAt: expiry}, nil
}

// Proof owns canonical token bytes through shared private lifetime state.
// Copies alias that state; zero and transferred values are invalid. Transfer
// clears owned/borrowed allocation capacity, not malicious caller copies or
// arbitrary runtime memory. Concurrent Transfer/Verify is safe.
type Proof struct{ state *proofState }

// proofState.mu is the sole synchronization owner of token custody. No caller
// callbacks, resolver operations or clock reads execute under it.
type proofState struct {
	mu    sync.Mutex
	token []byte
}

// Format redacts every fmt verb, including pointer and container formatting.
func (Proof) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED capability.Proof]")
}

// LogValue prevents structured log reflection from exposing private storage.
func (Proof) LogValue() slog.Value { return slog.StringValue("[REDACTED capability.Proof]") }

// ParseProof bounds ingress through Parse before copying canonical token bytes.
// Parsing establishes structure only, not signature, current validity or use
// authority. Failure returns a zero proof. Limits must be explicitly valid.
func ParseProof(token string, limits Limits) (Proof, error) {
	if _, err := Parse(token, limits); err != nil {
		return Proof{}, err
	}
	return Proof{state: &proofState{token: []byte(token)}}, nil
}

// ValidateBounds checks inclusive canonical token byte bounds without copying,
// exposing, transferring or consuming the proof. Both bounds must be positive
// and minimum must not exceed maximum; invalid bounds return
// ErrInvalidConfiguration. Zero, transferred or out-of-range proofs return
// ErrInvalidToken. Consumer bounds do not change ParseProof's configured limits.
// This is a synchronized custody observation, not authentication or authority:
// concurrent Transfer may invalidate the proof immediately after success.
func (proof Proof) ValidateBounds(minimum, maximum int) error {
	if minimum <= 0 || maximum < minimum {
		return ErrInvalidConfiguration
	}
	if proof.state == nil {
		return ErrInvalidToken
	}
	proof.state.mu.Lock()
	defer proof.state.mu.Unlock()
	if len(proof.state.token) < minimum || len(proof.state.token) > maximum {
		return ErrInvalidToken
	}
	return nil
}

// Transfer invalidates every alias before invoking one synchronous callback
// outside locks. The callback borrows bytes only until it returns; all exposed
// capacity is cleared on success, error or panic. Failures never retry, consume
// authority or imply transport success. Pre-cancellation preserves custody.
// Explicit transport copies remain the caller's secret-custody responsibility.
func (proof Proof) Transfer(ctx context.Context, callback func(context.Context, []byte) error) (err error) {
	if ctx == nil || callback == nil {
		return ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if proof.state == nil {
		return ErrInvalidToken
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	proof.state.mu.Lock()
	if len(proof.state.token) == 0 {
		proof.state.mu.Unlock()
		return ErrInvalidToken
	}
	borrowed := proof.state.token
	proof.state.token = nil
	proof.state.mu.Unlock()
	callbackReturned := false
	defer func() {
		clear(borrowed[:cap(borrowed)])
		if cause := recover(); cause != nil || !callbackReturned {
			err = transferPanic(cause)
		}
	}()
	callbackErr := callback(ctx, borrowed)
	callbackReturned = true
	if callbackErr != nil {
		return redact(ErrProofTransferFailed, callbackErr)
	}
	return nil
}

func transferPanic(cause any) (err error) {
	err = ErrProofTransferFailed
	// Error classification may itself call user-defined Is/Unwrap methods.
	// A second panic must not escape the redacted callback boundary.
	defer func() {
		if recover() != nil {
			err = ErrProofTransferFailed
		}
	}()
	if failure, ok := cause.(error); ok {
		return redact(ErrProofTransferFailed, failure)
	}
	return err
}

func (proof Proof) snapshot() ([]byte, error) {
	if proof.state == nil {
		return nil, ErrInvalidToken
	}
	proof.state.mu.Lock()
	defer proof.state.mu.Unlock()
	if len(proof.state.token) == 0 {
		return nil, ErrInvalidToken
	}
	return append([]byte(nil), proof.state.token...), nil
}

// Service is the canonical issuing and purpose/audience verification boundary.
// Verification never consumes a grant or commits a protected operation.
type Service interface {
	Issue(context.Context, Payload) (Proof, Reference, error)
	Verify(context.Context, Proof, Purpose, string) (Grant, error)
}

// ServiceConfig pins explicit policy. Clock must be a fast local trusted clock;
// all collaborators must support concurrent calls if the service is shared.
// Limits has no implicit defaults: use DefaultLimits explicitly. Revocations
// may be nil only when the application's policy permits no revocation source.
type ServiceConfig struct {
	// Issuer is independently selected trusted deployment policy, not a token
	// claim. It fixes both issuance and verification to this exact key owner.
	Issuer      string
	Signer      Signer
	Resolver    Resolver
	Clock       func() time.Time
	Limits      Limits
	Skew        time.Duration
	Revocations RevocationChecker
}

type service struct{ config ServiceConfig }

// NewService constructs an immutable policy holder. A nil signer, resolver or
// clock, invalid limits or negative skew fails with ErrInvalidConfiguration.
// Collaborator panics are not recovered; only Transfer callback panics are.
func NewService(config ServiceConfig) (Service, error) {
	if config.Signer == nil || config.Resolver == nil || config.Clock == nil || config.Skew < 0 || !validText(config.Issuer, config.Limits.MaxFieldBytes, true) {
		return nil, ErrInvalidConfiguration
	}
	if err := validateLimits(config.Limits); err != nil {
		return nil, err
	}
	if !validAlgorithm(config.Signer.Algorithm()) || !validText(config.Signer.KeyID(), config.Limits.MaxFieldBytes, true) {
		return nil, ErrInvalidConfiguration
	}
	return &service{config: config}, nil
}

// Issue preserves nonzero caller timestamps and fills only zero IssuedAt and
// NotBefore from the pinned clock (UTC seconds). Expiry is always explicit;
// existing Issue validation and timestamp-skew semantics remain unchanged.
func (s *service) Issue(ctx context.Context, payload Payload) (Proof, Reference, error) {
	if err := contextError(ctx); err != nil {
		return Proof{}, Reference{}, err
	}
	if payload.Issuer != s.config.Issuer {
		return Proof{}, Reference{}, ErrUnauthorized
	}
	purpose, err := NewPurpose(payload.Operation)
	if err != nil {
		return Proof{}, Reference{}, err
	}
	now := s.config.Clock()
	if now.IsZero() {
		return Proof{}, Reference{}, ErrInvalidConfiguration
	}
	now = now.UTC().Truncate(time.Second)
	if payload.IssuedAt.IsZero() {
		payload.IssuedAt = now
	}
	if payload.NotBefore.IsZero() {
		payload.NotBefore = now
	}
	token, err := Issue(ctx, payload, s.config.Signer, s.config.Limits)
	if err != nil {
		return Proof{}, Reference{}, err
	}
	framing := make([]byte, len("golib/capability/reference/v1\x00")+8+len(token))
	copy(framing, "golib/capability/reference/v1\x00")
	binary.BigEndian.PutUint64(framing[len("golib/capability/reference/v1\x00"):], uint64(len(token)))
	copy(framing[len("golib/capability/reference/v1\x00")+8:], token)
	digest := sha256.Sum256(framing)
	clear(framing[:cap(framing)])
	reference, err := NewReference(payload.ID, purpose, digest, time.Unix(payload.ExpiresAt.Unix(), 0).UTC())
	if err != nil {
		return Proof{}, Reference{}, err
	}
	proof, err := ParseProof(token, s.config.Limits)
	if err != nil {
		return Proof{}, Reference{}, err
	}
	return proof, reference, nil
}

// Verify authenticates a private snapshot. A snapshot acquired before Transfer
// may finish; snapshots after transfer fail. Existing signature, key/time and
// revocation checks precede exact purpose/audience matching. Returned grants
// still require explicit authorization and transactional one-time consumption.
func (s *service) Verify(ctx context.Context, proof Proof, purpose Purpose, audience string) (Grant, error) {
	if err := contextError(ctx); err != nil {
		return Grant{}, err
	}
	if _, err := NewPurpose(string(purpose)); err != nil {
		return Grant{}, err
	}
	if !validText(audience, s.config.Limits.MaxFieldBytes, true) {
		return Grant{}, ErrInvalidPayload
	}
	bytes, err := proof.snapshot()
	if err != nil {
		return Grant{}, err
	}
	defer clear(bytes[:cap(bytes)])
	grant, err := Verify(ctx, string(bytes), s.config.Resolver, VerifyOptions{Issuer: s.config.Issuer, Now: s.config.Clock(), Skew: s.config.Skew, Limits: s.config.Limits, Revocations: s.config.Revocations})
	if err != nil {
		return Grant{}, err
	}
	if grant.payload.Operation != string(purpose) || !contains(grant.payload.Audiences, audience) {
		return Grant{}, ErrUnauthorized
	}
	return grant, nil
}
