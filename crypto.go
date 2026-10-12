package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Algorithm identifies a reviewed signature construction and its required key type.
type Algorithm string

const (
	// HMACSHA256 is HMAC with SHA-256 and keys of at least 256 bits.
	HMACSHA256 Algorithm = "hmac-sha256"
	// Ed25519 is the standard-library Ed25519 signature scheme.
	Ed25519 Algorithm = "ed25519"
)

// Signer signs canonical protected bytes with an explicitly bound algorithm and key ID.
// Shared implementations must be concurrency-safe, bounded and context-aware.
// No core worker, timeout, cache or panic boundary owns collaborator execution.
type Signer interface {
	// Algorithm returns the stable trusted construction, never untrusted caller
	// selection.
	Algorithm() Algorithm
	// KeyID returns stable public identity as valid nonempty text <=256 bytes.
	KeyID() string
	// Sign authenticates exact borrowed bytes, honoring context and returning owned
	// signature storage.
	Sign(context.Context, []byte) ([]byte, error)
}

// Verifier authenticates canonical protected bytes with one bound algorithm.
type Verifier interface {
	// Algorithm returns the stable trusted construction, never untrusted caller
	// selection.
	Algorithm() Algorithm
	// Verify returns nil only for authentic exact borrowed bytes; honor ctx, retain
	// no inputs and return ErrInvalidSignature on refusal.
	Verify(context.Context, []byte, []byte) error
}

type hmacSigner struct {
	keyID string
	key   []byte
}

type hmacVerifier struct{ key []byte }

type ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

type ed25519Verifier struct{ key ed25519.PublicKey }

// NewHMACSHA256Signer copies >=32 secret bytes and valid nonempty <=256-byte key
// ID into a concurrent signer. Entropy is caller-owned; copies are not erased.
// Failure returns nil/ErrInvalidConfiguration. Sign checks context before
// synchronous work (RFC 2104/4231, local DEC-002).
func NewHMACSHA256Signer(keyID string, key []byte) (Signer, error) {
	if !validText(keyID, DefaultLimits().MaxFieldBytes, true) || len(key) < sha256.Size {
		return nil, ErrInvalidConfiguration
	}
	return &hmacSigner{keyID: keyID, key: append([]byte(nil), key...)}, nil
}

// NewHMACSHA256Verifier copies >=32 secret bytes, returning
// nil/ErrInvalidConfiguration for a short key. It is concurrently usable, checks
// ctx before work and compares MACs with hmac.Equal, not constant total latency.
// Keys are not erased.
func NewHMACSHA256Verifier(key []byte) (Verifier, error) {
	if len(key) < sha256.Size {
		return nil, ErrInvalidConfiguration
	}
	return &hmacVerifier{key: append([]byte(nil), key...)}, nil
}

// NewEd25519Signer copies a standard-library sized private key and valid
// nonempty <=256-byte ID, returning nil/ErrInvalidConfiguration on refusal. It
// validates size, not key consistency/entropy. Concurrent Sign checks context
// before synchronous RFC 8032 work; copies are not erased.
func NewEd25519Signer(keyID string, key ed25519.PrivateKey) (Signer, error) {
	if !validText(keyID, DefaultLimits().MaxFieldBytes, true) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidConfiguration
	}
	return &ed25519Signer{keyID: keyID, key: append(ed25519.PrivateKey(nil), key...)}, nil
}

// NewEd25519Verifier copies a standard-library sized public key, returning
// nil/ErrInvalidConfiguration on wrong length. Concurrent Verify checks context
// before synchronous work; issuer/key lifecycle remains resolver-owned.
func NewEd25519Verifier(key ed25519.PublicKey) (Verifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalidConfiguration
	}
	return &ed25519Verifier{key: append(ed25519.PublicKey(nil), key...)}, nil
}

func (signer *hmacSigner) Algorithm() Algorithm { return HMACSHA256 }
func (signer *hmacSigner) KeyID() string        { return signer.keyID }
func (signer *hmacSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

func (verifier *hmacVerifier) Algorithm() Algorithm { return HMACSHA256 }
func (verifier *hmacVerifier) Verify(ctx context.Context, message, signature []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, verifier.key)
	_, _ = mac.Write(message)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (signer *ed25519Signer) Algorithm() Algorithm { return Ed25519 }
func (signer *ed25519Signer) KeyID() string        { return signer.keyID }
func (signer *ed25519Signer) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return ed25519.Sign(signer.key, message), nil
}

func (verifier *ed25519Verifier) Algorithm() Algorithm { return Ed25519 }
func (verifier *ed25519Verifier) Verify(ctx context.Context, message, signature []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !ed25519.Verify(verifier.key, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func validAlgorithm(algorithm Algorithm) bool {
	return algorithm == HMACSHA256 || algorithm == Ed25519
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidConfiguration)
	}
	return ctx.Err()
}
