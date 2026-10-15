package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const tokenPrefix = "cap1"

// Header is protected token metadata. Algorithm is authenticated but is also
// checked against the trusted verifier returned by Resolver.
type Header struct {
	// Version must be 1 for local cap1 framing.
	Version int `json:"v"`
	// Type must be capability, not a JWT/JWS media type.
	Type string `json:"typ"`
	// Algorithm is protected but cannot select a different trusted verifier construction.
	Algorithm Algorithm `json:"alg"`
	// KeyID is protected public key identity with a fixed 256-byte canonical-header
	// ceiling.
	KeyID string `json:"kid"`
}

// Parsed is a structurally valid canonical token. It is not authenticated and
// grants no authority until passed to Verify.
// Exported decoded fields remain untrusted and mutable; returned collections
// belong to the caller. Verify reparses token text rather than trusting this
// value.
type Parsed struct {
	// Header is decoded untrusted metadata, not trusted resolver policy.
	Header Header
	// Payload is decoded untrusted authority with caller-owned slices/maps; changing it
	// does not verify anything.
	Payload Payload

	signingInput []byte
	signature    []byte
}

// ResolvedKey is trusted key-policy state returned by a Resolver.
type ResolvedKey struct {
	// Issuer is the trusted namespace owning this key, not a token-derived claim.
	Issuer string
	// Verifier is mandatory borrowed trusted cryptographic code; typed nil is not detected.
	Verifier Verifier
	// Disabled refuses use without declaring the key revoked.
	Disabled bool
	// Revoked refuses all use and takes precedence over Disabled.
	Revoked bool
	// NotBefore is inclusive key activation at unskewed verification time; zero is open.
	NotBefore time.Time
	// NotAfter is exclusive key expiry at unskewed verification time; zero is open.
	NotAfter time.Time
}

// Resolver finds a trusted verifier and its current lifecycle policy.
// Shared implementations must be concurrency-safe, bounded and context-aware.
// No core worker, timeout, cache or panic boundary owns collaborator execution.
type Resolver interface {
	// Resolve supplies independently trusted issuer/key policy for exact global
	// ID/algorithm; honor ctx and return safe ErrUnknownKey/ErrAlgorithmMismatch
	// categories.
	Resolve(context.Context, string, Algorithm) (ResolvedKey, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(context.Context, string, Algorithm) (ResolvedKey, error)

// Resolve implements Resolver.
func (function ResolverFunc) Resolve(ctx context.Context, keyID string, algorithm Algorithm) (ResolvedKey, error) {
	return function(ctx, keyID, algorithm)
}

// VerifyOptions defines trusted issuer selection, time, skew, and parser limits.
type VerifyOptions struct {
	// Issuer is selected by trusted application configuration. It is required
	// and must match both the signed claim and the resolved key's owner.
	Issuer string
	// Now is required trusted processing time; no clock is implicitly sampled.
	Now time.Time
	// Skew is nonnegative tolerance on payload validity, not key activation or store
	// expiry.
	Skew time.Duration
	// Limits is explicit finite parser policy; zero is invalid.
	Limits Limits
	// Revocations is optional borrowed policy invoked after signature/time validation; nil
	// disables that check.
	Revocations RevocationChecker
}

// Issue validates/signs local cap1/v1 under DEC-001–003 with non-nil ctx/signer.
// Payload collections are copied, but signer methods remain trusted synchronous
// code with stable key IDs no longer than 256 bytes. It generates no ID or
// randomness. Signatures must be 1–512 bytes; output length is checked after
// encoding. Signer errors retain only ErrSigningFailed and safe context
// categories; panics/typed nil are not contained.
func Issue(ctx context.Context, payload Payload, signer Signer, limits Limits) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if signer == nil || !validAlgorithm(signer.Algorithm()) ||
		!validText(signer.KeyID(), limits.MaxFieldBytes, true) {
		return "", ErrInvalidConfiguration
	}
	canonicalPayload, err := CanonicalPayload(payload, limits)
	if err != nil {
		return "", err
	}
	header := Header{Version: 1, Type: "capability", Algorithm: signer.Algorithm(), KeyID: signer.KeyID()}
	canonicalHeader, _ := canonicalHeader(header)
	encode := base64.RawURLEncoding.EncodeToString
	signingInput := tokenPrefix + "." + encode(canonicalHeader) + "." + encode(canonicalPayload)
	signature, err := signer.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", redact(ErrSigningFailed, err)
	}
	if len(signature) == 0 || len(signature) > 512 {
		return "", ErrInvalidConfiguration
	}
	token := signingInput + "." + encode(signature)
	if len(token) > limits.MaxTokenBytes {
		return "", fmt.Errorf("%w: token exceeds limit", ErrInvalidToken)
	}
	return token, nil
}

// Parse bounds complete input before splitting/decoding and requires canonical
// decoded header/payload JSON, without authenticating authority. Refusal returns
// zero Parsed. Go Strict RawURLEncoding rejects padding/nonzero trailing bits
// but permits CR/LF during decoding; this is not a separate unique-token-text
// re-encoding check.
func Parse(token string, limits Limits) (Parsed, error) {
	if err := validateLimits(limits); err != nil {
		return Parsed{}, err
	}
	if len(token) == 0 {
		return Parsed{}, ErrInvalidToken
	}
	if len(token) > limits.MaxTokenBytes {
		return Parsed{}, ErrInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return Parsed{}, ErrInvalidToken
	}
	if parts[0] != tokenPrefix {
		return Parsed{}, ErrInvalidToken
	}
	decode := base64.RawURLEncoding.Strict().DecodeString
	headerBytes, err := decode(parts[1])
	if err != nil {
		return Parsed{}, ErrInvalidToken
	}
	payloadBytes, err := decode(parts[2])
	if err != nil {
		return Parsed{}, ErrInvalidToken
	}
	signature, err := decode(parts[3])
	if err != nil {
		return Parsed{}, ErrInvalidToken
	}
	if len(signature) == 0 {
		return Parsed{}, ErrInvalidToken
	}
	if len(signature) > 512 {
		return Parsed{}, ErrInvalidToken
	}
	header, err := parseHeader(headerBytes, limits)
	if err != nil {
		return Parsed{}, err
	}
	payload, err := ParsePayload(payloadBytes, limits)
	if err != nil {
		return Parsed{}, err
	}
	return Parsed{
		Header: header, Payload: payload,
		signingInput: []byte(strings.Join(parts[:3], ".")),
		signature:    append([]byte(nil), signature...),
	}, nil
}

// Verify reparses/authenticates the token, returning zero Grant on failure.
// Trusted selected issuer must match claim and key owner before cryptography.
// Key activation is inclusive/exclusive at unskewed Now; payload expiry is
// exclusive with Skew. Revocation runs after crypto/time success. Errors strip
// collaborator diagnostics; callbacks remain borrowed/cooperative. Authorize and
// Consume remain explicit; no cache/worker is added (DEC-004/005/009/010).
func Verify(ctx context.Context, token string, resolver Resolver, options VerifyOptions) (Grant, error) {
	if err := contextError(ctx); err != nil {
		return Grant{}, err
	}
	if resolver == nil || options.Now.IsZero() || options.Skew < 0 ||
		!validText(options.Issuer, options.Limits.MaxFieldBytes, true) {
		return Grant{}, ErrInvalidConfiguration
	}
	parsed, err := Parse(token, options.Limits)
	if err != nil {
		return Grant{}, err
	}
	if parsed.Payload.Issuer != options.Issuer {
		return Grant{}, ErrUnauthorized
	}
	resolved, err := resolver.Resolve(ctx, parsed.Header.KeyID, parsed.Header.Algorithm)
	if err != nil {
		return Grant{}, redactResolver(err)
	}
	if resolved.Verifier == nil {
		return Grant{}, ErrUnknownKey
	}
	if !validText(resolved.Issuer, options.Limits.MaxFieldBytes, true) {
		return Grant{}, ErrInvalidConfiguration
	}
	if resolved.Issuer != options.Issuer {
		return Grant{}, ErrUnauthorized
	}
	if resolved.Verifier.Algorithm() != parsed.Header.Algorithm {
		return Grant{}, ErrAlgorithmMismatch
	}
	if resolved.Revoked {
		return Grant{}, ErrKeyRevoked
	}
	if resolved.Disabled {
		return Grant{}, ErrKeyDisabled
	}
	now := options.Now.UTC()
	if (!resolved.NotBefore.IsZero() && now.Before(resolved.NotBefore)) ||
		(!resolved.NotAfter.IsZero() && !now.Before(resolved.NotAfter)) {
		return Grant{}, ErrKeyNotActive
	}
	if err := resolved.Verifier.Verify(ctx, parsed.signingInput, parsed.signature); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return Grant{}, ErrInvalidSignature
		}
		return Grant{}, redact(ErrInvalidSignature, err)
	}
	if now.Add(options.Skew).Before(parsed.Payload.IssuedAt) ||
		now.Add(options.Skew).Before(parsed.Payload.NotBefore) {
		return Grant{}, ErrNotYetValid
	}
	if !now.Add(-options.Skew).Before(parsed.Payload.ExpiresAt) {
		return Grant{}, ErrExpired
	}
	if options.Revocations != nil {
		revoked, checkErr := options.Revocations.Check(ctx, RevocationQuery{
			Issuer: parsed.Payload.Issuer, Tenant: parsed.Payload.Tenant,
			CapabilityID: parsed.Payload.ID, KeyID: parsed.Header.KeyID,
			Subject: parsed.Payload.Subject, Resource: parsed.Payload.Resource,
			IssuedAt: parsed.Payload.IssuedAt,
		})
		if checkErr != nil {
			return Grant{}, redact(ErrRevocationUnknown, checkErr)
		}
		if revoked {
			return Grant{}, ErrRevoked
		}
	}
	grant := newGrant(parsed.Payload, parsed.Header)
	grant.envelopeDigest = sha256.Sum256([]byte(token))
	return grant, nil
}

func canonicalHeader(header Header) ([]byte, error) {
	if header.Version != 1 || header.Type != "capability" ||
		!validAlgorithm(header.Algorithm) || !validText(header.KeyID, DefaultLimits().MaxFieldBytes, true) {
		return nil, ErrInvalidToken
	}
	return json.Marshal(header)
}

func parseHeader(encoded []byte, limits Limits) (Header, error) {
	var header Header
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		return Header{}, ErrInvalidToken
	}
	if err := requireEOF(decoder); err != nil {
		return Header{}, ErrInvalidToken
	}
	canonical, err := canonicalHeader(header)
	if err != nil {
		return Header{}, err
	}
	if len(header.KeyID) > limits.MaxFieldBytes || !bytes.Equal(encoded, canonical) {
		return Header{}, ErrNonCanonical
	}
	return header, nil
}
