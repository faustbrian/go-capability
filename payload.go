// Package capability issues and verifies narrowly scoped, tamper-evident grants.
// Verification authenticates encoded authority; applications must separately
// authorize each attempted use against the returned Grant.
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

// Limits bounds every attacker-controlled token and payload collection.
type Limits struct {
	MaxTokenBytes  int
	MaxFieldBytes  int
	MaxAudiences   int
	MaxCaveats     int
	MaxCaveatBytes int
	MaxLifetime    time.Duration
	MaxUses        uint32
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
type Payload struct {
	Version       int
	Issuer        string
	Audiences     []string
	Subject       string
	Bearer        bool
	Resource      string
	Operation     string
	IssuedAt      time.Time
	NotBefore     time.Time
	ExpiresAt     time.Time
	ID            string
	Tenant        string
	CorrelationID string
	MaxUses       uint32
	Caveats       map[string]string
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

// CanonicalPayload validates payload and returns its unique UTF-8 JSON encoding.
// Strings are preserved byte-for-byte: canonically equivalent Unicode forms
// remain distinct authority strings and are never normalized implicitly.
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

// ParsePayload accepts only the exact canonical v1 byte representation.
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
