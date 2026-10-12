// Package capability issues and verifies local cap1/v1 grants. Start with
// DefaultLimits, an explicit signer and issuer-owned NewKeySet. Parsing, Verify,
// Grant.Authorize and Grant.Consume are separate trust boundaries: verification
// alone does not authorize business effects or consume a use.
//
// Core code owns no network, database, worker or clock lifecycle and adds no cgo.
// Optional HTTP/memory/PostgreSQL/Valkey packages compose caller-owned resources.
// Tokens encode visible bearer authority, not encryption, JWT/JWS or RFC 9421.
// Local policies and pinned standards are in docs/specification-decisions.md.
//
// Constructors copy secrets without secure erasure. Maps/slices and callbacks
// stay borrowed during calls: use safe immutable collaborators and bounded
// context-aware I/O. Cancellation cannot forcibly preempt synchronous callbacks.
package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"
)

const payloadVersion = 1

// Limits defines explicit payload/token admission. Zero is invalid; start with
// DefaultLimits. CanonicalPayload copies collections before validation, and URL
// profile counts remain caller-owned. Finite defaults are not an exact heap
// quota; very large custom limits require allocation/arithmetic review.
type Limits struct {
	// MaxTokenBytes caps encoded payload input/output and complete token bytes; positive,
	// not an exact heap quota.
	MaxTokenBytes int
	// MaxFieldBytes caps bounded text fields; positive. Protected key IDs retain a separate
	// 256-byte ceiling.
	MaxFieldBytes int
	// MaxAudiences is the positive maximum audience count.
	MaxAudiences int
	// MaxCaveats is the maximum caveat count; zero permits none, negative is invalid.
	MaxCaveats int
	// MaxCaveatBytes is the positive byte limit for each caveat value.
	MaxCaveatBytes int
	// MaxLifetime is positive; expiry minus the earlier issued/not-before second must fit
	// its whole seconds.
	MaxLifetime time.Duration
	// MaxUses is the positive ceiling on signed bounded use counts; payload zero still
	// means reusable.
	MaxUses uint32
}

// DefaultLimits returns the reviewed v1 resource limits.
func DefaultLimits() Limits {
	return Limits{
		MaxTokenBytes: 16 << 10, MaxFieldBytes: 256, MaxAudiences: 16,
		MaxCaveats: 16, MaxCaveatBytes: 512, MaxLifetime: 24 * time.Hour,
		MaxUses: 1_000_000,
	}
}

// Payload is the authority encoded by a v1 capability. Subject and Bearer are
// mutually exclusive. MaxUses zero means reusable; a positive value is an
// upper bound enforced by a replay store, not by signature verification alone.
// Zero is invalid. Collections are borrowed during calls and must not be
// concurrently mutated; times encode UTC Unix seconds, discarding fractions.
type Payload struct {
	// Version must be local wire version 1, independent of the Go module major.
	Version int
	// Issuer is required exact issuer text; verification separately binds trusted key
	// ownership.
	Issuer string
	// Audiences is required borrowed text; canonicalization copies/sorts it and rejects
	// duplicate values.
	Audiences []string
	// Subject is the exact independently authenticated subject; it is mutually exclusive
	// with Bearer.
	Subject string
	// Bearer permits use without subject matching and requires an empty Subject; tokens
	// remain transferable.
	Bearer bool
	// Resource is required exact application authority; SignURL owns it instead.
	Resource string
	// Operation is required exact application operation; SignURL substitutes its HTTP
	// method.
	Operation string
	// IssuedAt encodes nonnegative Unix seconds; subsecond precision is discarded.
	IssuedAt time.Time
	// NotBefore encodes nonnegative Unix seconds; it may precede IssuedAt, but expiry must
	// follow both.
	NotBefore time.Time
	// ExpiresAt is exclusive signed Unix-second expiry; Verify applies caller skew
	// separately.
	ExpiresAt time.Time
	// ID is required public capability identity; callers generate collision-resistant
	// values per issuer.
	ID string
	// Tenant is exact optional authority; empty is an explicit empty boundary.
	Tenant string
	// CorrelationID is optional diagnostic attribution, never authorization.
	CorrelationID string
	// MaxUses zero is reusable; positive requires explicit atomic consumption, not just
	// verification.
	MaxUses uint32
	// Caveats is an optional borrowed map of exact required pairs; Use may supply extras.
	Caveats map[string]string
}

type payloadWire struct {
	Version       int               `json:"v"`
	Issuer        string            `json:"iss"`
	Audiences     []string          `json:"aud"`
	Subject       string            `json:"sub,omitempty"`
	Bearer        bool              `json:"bearer,omitempty"`
	Resource      string            `json:"resource"`
	Operation     string            `json:"operation"`
	IssuedAt      int64             `json:"iat"`
	NotBefore     int64             `json:"nbf"`
	ExpiresAt     int64             `json:"exp"`
	ID            string            `json:"id"`
	Tenant        string            `json:"tenant,omitempty"`
	CorrelationID string            `json:"correlation,omitempty"`
	MaxUses       uint32            `json:"max_uses,omitempty"`
	Caveats       map[string]string `json:"caveats,omitempty"`
}

// CanonicalPayload returns owned local fixed-order JSON under DEC-003. It
// copies/sorts audiences and maps before admission, rejecting duplicate
// audiences and invalid text/time/bounds. Unicode bytes are not normalized;
// equivalent Unicode spellings remain different authority. This is not RFC 8785
// canonicalization or authentication.
func CanonicalPayload(payload Payload, limits Limits) ([]byte, error) {
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	wire := wireFromPayload(payload)
	sort.Strings(wire.Audiences)
	if len(wire.Caveats) == 0 {
		wire.Caveats = nil
	}
	if err := validateWire(wire, limits); err != nil {
		return nil, err
	}
	encoded := marshalWire(wire)
	if len(encoded) > limits.MaxTokenBytes {
		return nil, fmt.Errorf("%w: encoded payload exceeds limit", ErrInvalidPayload)
	}
	return encoded, nil
}

// ParsePayload bounds input before decoding and accepts only exact local
// canonical JSON. Re-encoding rejects alternate order, duplicates, whitespace
// and trailing data. Returned slices/maps are owned; refusal returns zero
// Payload. It authenticates nothing (DEC-003).
func ParsePayload(encoded []byte, limits Limits) (Payload, error) {
	if err := validateLimits(limits); err != nil {
		return Payload{}, err
	}
	if len(encoded) == 0 || len(encoded) > limits.MaxTokenBytes || !utf8.Valid(encoded) {
		return Payload{}, fmt.Errorf("%w: encoded payload", ErrInvalidPayload)
	}
	var wire payloadWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Payload{}, fmt.Errorf("%w: decode", ErrInvalidPayload)
	}
	if err := requireEOF(decoder); err != nil {
		return Payload{}, fmt.Errorf("%w: trailing data", ErrInvalidPayload)
	}
	reencoded := marshalWire(wire)
	if !bytes.Equal(encoded, reencoded) {
		return Payload{}, ErrNonCanonical
	}
	if err := validateWire(wire, limits); err != nil {
		return Payload{}, err
	}
	return payloadFromWire(wire), nil
}

func wireFromPayload(payload Payload) payloadWire {
	audiences := append([]string(nil), payload.Audiences...)
	caveats := cloneMap(payload.Caveats)
	return payloadWire{
		Version: payload.Version, Issuer: payload.Issuer, Audiences: audiences,
		Subject: payload.Subject, Bearer: payload.Bearer, Resource: payload.Resource,
		Operation: payload.Operation, IssuedAt: payload.IssuedAt.Unix(),
		NotBefore: payload.NotBefore.Unix(), ExpiresAt: payload.ExpiresAt.Unix(),
		ID: payload.ID, Tenant: payload.Tenant, CorrelationID: payload.CorrelationID,
		MaxUses: payload.MaxUses, Caveats: caveats,
	}
}

func payloadFromWire(wire payloadWire) Payload {
	return Payload{
		Version: wire.Version, Issuer: wire.Issuer,
		Audiences: append([]string(nil), wire.Audiences...), Subject: wire.Subject,
		Bearer: wire.Bearer, Resource: wire.Resource, Operation: wire.Operation,
		IssuedAt:  time.Unix(wire.IssuedAt, 0).UTC(),
		NotBefore: time.Unix(wire.NotBefore, 0).UTC(),
		ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC(), ID: wire.ID,
		Tenant: wire.Tenant, CorrelationID: wire.CorrelationID,
		MaxUses: wire.MaxUses, Caveats: cloneMap(wire.Caveats),
	}
}

func validateLimits(limits Limits) error {
	if limits.MaxTokenBytes <= 0 || limits.MaxFieldBytes <= 0 ||
		limits.MaxAudiences <= 0 || limits.MaxCaveats < 0 ||
		limits.MaxCaveatBytes <= 0 || limits.MaxLifetime <= 0 || limits.MaxUses == 0 {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateWire(wire payloadWire, limits Limits) error {
	if wire.Version != payloadVersion {
		return invalidField("version")
	}
	for name, value := range map[string]string{
		"issuer": wire.Issuer, "resource": wire.Resource,
		"operation": wire.Operation, "id": wire.ID,
	} {
		if !validText(value, limits.MaxFieldBytes, true) {
			return invalidField(name)
		}
	}
	for name, value := range map[string]string{
		"subject": wire.Subject, "tenant": wire.Tenant,
		"correlation": wire.CorrelationID,
	} {
		if !validText(value, limits.MaxFieldBytes, false) {
			return invalidField(name)
		}
	}
	if (wire.Subject == "") == !wire.Bearer {
		return invalidField("subject")
	}
	if len(wire.Audiences) == 0 || len(wire.Audiences) > limits.MaxAudiences {
		return invalidField("audience")
	}
	for index, audience := range wire.Audiences {
		if !validText(audience, limits.MaxFieldBytes, true) ||
			(index > 0 && wire.Audiences[index-1] >= audience) {
			return invalidField("audience")
		}
	}
	validityStart := min(wire.IssuedAt, wire.NotBefore)
	if wire.IssuedAt < 0 || wire.NotBefore < 0 ||
		wire.ExpiresAt <= wire.IssuedAt || wire.ExpiresAt <= wire.NotBefore {
		return invalidField("time")
	}
	if wire.ExpiresAt-validityStart > int64(limits.MaxLifetime/time.Second) {
		return invalidField("time")
	}
	if wire.MaxUses > limits.MaxUses {
		return invalidField("max_uses")
	}
	if len(wire.Caveats) > limits.MaxCaveats {
		return invalidField("caveats")
	}
	for key, value := range wire.Caveats {
		if !validText(key, limits.MaxFieldBytes, true) ||
			!validText(value, limits.MaxCaveatBytes, true) {
			return invalidField("caveats")
		}
	}
	return nil
}

func validText(value string, maximum int, required bool) bool {
	if (required && value == "") || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func invalidField(name string) error {
	return fmt.Errorf("%w: %s", ErrInvalidPayload, name)
}

func marshalWire(wire payloadWire) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(wire)
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("additional JSON value")
	}
	return err
}

func cloneMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
