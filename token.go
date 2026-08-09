package capability

import (
	"bytes"
	"context"
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
	Version   int       `json:"v"`
	Type      string    `json:"typ"`
	Algorithm Algorithm `json:"alg"`
	KeyID     string    `json:"kid"`
}

// Parsed is a structurally valid canonical token. It is not authenticated and
// grants no authority until passed to Verify.
type Parsed struct {
	Header  Header
	Payload Payload

	signingInput []byte
	signature    []byte
}

// ResolvedKey is trusted key-policy state returned by a Resolver.
type ResolvedKey struct {
	Verifier  Verifier
	Disabled  bool
	Revoked   bool
	NotBefore time.Time
	NotAfter  time.Time
}

// Resolver finds a trusted verifier and its current lifecycle policy.
type Resolver interface {
	Resolve(context.Context, string, Algorithm) (ResolvedKey, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(context.Context, string, Algorithm) (ResolvedKey, error)

// Resolve implements Resolver.
func (function ResolverFunc) Resolve(ctx context.Context, keyID string, algorithm Algorithm) (ResolvedKey, error) {
	return function(ctx, keyID, algorithm)
}

// VerifyOptions defines the current time, accepted clock skew, and parser limits.
type VerifyOptions struct {
	Now         time.Time
	Skew        time.Duration
	Limits      Limits
	Revocations RevocationChecker
}

// Issue validates and signs one canonical v1 payload.
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

// Parse validates token framing and canonical protected fields without
// authenticating them or authorizing resource use.
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

// Verify authenticates and validates a token. It does not authorize an
// attempted resource operation; use Grant.Authorize for that separate step.
func Verify(ctx context.Context, token string, resolver Resolver, options VerifyOptions) (Grant, error) {
	if err := contextError(ctx); err != nil {
		return Grant{}, err
	}
	if resolver == nil || options.Now.IsZero() || options.Skew < 0 {
		return Grant{}, ErrInvalidConfiguration
	}
	parsed, err := Parse(token, options.Limits)
	if err != nil {
		return Grant{}, err
	}
	resolved, err := resolver.Resolve(ctx, parsed.Header.KeyID, parsed.Header.Algorithm)
	if err != nil {
		return Grant{}, redactResolver(err)
	}
	if resolved.Verifier == nil {
		return Grant{}, ErrUnknownKey
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
	return newGrant(parsed.Payload, parsed.Header), nil
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
