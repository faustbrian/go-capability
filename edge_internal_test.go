package capability

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestIssueAndParseRejectEveryFramingBoundary(t *testing.T) {
	payload := internalPayload()
	limits := DefaultLimits()
	canonical, err := CanonicalPayload(payload, limits)
	if err != nil {
		t.Fatalf("CanonicalPayload() error = %v", err)
	}
	for name, signer := range map[string]Signer{
		"algorithm": stubSigner{algorithm: "unknown", keyID: "key", signature: []byte("signature")},
		"key ID":    stubSigner{algorithm: HMACSHA256, signature: []byte("signature")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Issue(context.Background(), payload, signer, limits); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Issue() error = %v", err)
			}
		})
	}
	for name, signature := range map[string][]byte{"empty": nil, "oversized": make([]byte, 513)} {
		t.Run(name, func(t *testing.T) {
			_, err := Issue(context.Background(), payload, stubSigner{algorithm: HMACSHA256, keyID: "key", signature: signature}, limits)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Issue() error = %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Issue(ctx, payload, stubSigner{algorithm: HMACSHA256, keyID: "key", signature: []byte("signature")}, limits); !errors.Is(err, context.Canceled) {
		t.Fatalf("Issue(canceled) error = %v", err)
	}
	small := limits
	small.MaxTokenBytes = len(canonical) + 32
	if _, err := Issue(context.Background(), payload, stubSigner{algorithm: HMACSHA256, keyID: "key", signature: make([]byte, 32)}, small); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Issue(token limit) error = %v", err)
	}

	header, _ := canonicalHeader(Header{Version: 1, Type: "capability", Algorithm: HMACSHA256, KeyID: "key"})
	encode := base64.RawURLEncoding.EncodeToString
	validToken := "cap1." + encode(header) + "." + encode(canonical) + "." + encode([]byte("signature"))
	invalidLimits := limits
	invalidLimits.MaxTokenBytes = 0
	if _, err := Parse(validToken, invalidLimits); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Parse(invalid limits) error = %v", err)
	}
	tokens := map[string]string{
		"large header":         "cap1." + encode(make([]byte, 1025)) + "." + encode(canonical) + ".c2ln",
		"bad payload base64":   "cap1." + encode(header) + ".*.c2ln",
		"bad signature base64": "cap1." + encode(header) + "." + encode(canonical) + ".*",
		"large signature":      "cap1." + encode(header) + "." + encode(canonical) + "." + encode(make([]byte, 513)),
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(token, limits); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestProtectedHeaderRejectsUnknownTrailingAndNonCanonicalForms(t *testing.T) {
	limits := DefaultLimits()
	for name, header := range map[string]Header{
		"version":   {Type: "capability", Algorithm: HMACSHA256, KeyID: "key"},
		"type":      {Version: 1, Type: "other", Algorithm: HMACSHA256, KeyID: "key"},
		"algorithm": {Version: 1, Type: "capability", Algorithm: "other", KeyID: "key"},
		"key ID":    {Version: 1, Type: "capability", Algorithm: HMACSHA256},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalHeader(header); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("canonicalHeader() error = %v", err)
			}
		})
	}
	inputs := map[string][]byte{
		"decode":        []byte(`{`),
		"unknown":       []byte(`{"v":1,"typ":"capability","alg":"hmac-sha256","kid":"key","extra":true}`),
		"trailing":      []byte(`{"v":1,"typ":"capability","alg":"hmac-sha256","kid":"key"}{}`),
		"non canonical": []byte(`{ "v":1,"typ":"capability","alg":"hmac-sha256","kid":"key"}`),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeader(input, limits); err == nil {
				t.Fatal("parseHeader() error = nil")
			}
		})
	}
	header, _ := canonicalHeader(Header{Version: 1, Type: "capability", Algorithm: HMACSHA256, KeyID: "long-key"})
	limits.MaxFieldBytes = 3
	if _, err := parseHeader(header, limits); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("parseHeader(key limit) error = %v", err)
	}
}

func TestVerificationRejectsParserAndVerifierOperationalFailures(t *testing.T) {
	options := VerifyOptions{Now: internalPayload().IssuedAt, Limits: DefaultLimits()}
	resolver := ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		return ResolvedKey{Verifier: failingVerifier{err: errors.New("verifier unavailable")}}, nil
	})
	if _, err := Verify(context.Background(), "invalid", resolver, options); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(invalid token) error = %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := NewHMACSHA256Signer("key", key)
	token, _ := Issue(context.Background(), internalPayload(), signer, DefaultLimits())
	if _, err := Verify(context.Background(), token, resolver, options); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(verifier failure) error = %v", err)
	}

	header, _ := canonicalHeader(Header{Version: 1, Type: "capability", Algorithm: HMACSHA256, KeyID: "key"})
	encode := base64.RawURLEncoding.EncodeToString
	malformedPayload := "cap1." + encode(header) + "." + encode(marshalWire(payloadWire{})) + "." + encode([]byte("signature"))
	if _, err := Parse(malformedPayload, DefaultLimits()); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Parse(invalid payload) error = %v", err)
	}
}

func TestCanonicalPayloadParserRejectsCanonicalButInvalidAuthority(t *testing.T) {
	wire := wireFromPayload(internalPayload())
	wire.Issuer = ""
	if _, err := ParsePayload(marshalWire(wire), DefaultLimits()); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("ParsePayload(invalid authority) error = %v", err)
	}
}

func TestGrantConsumptionValidation(t *testing.T) {
	grant := newGrant(internalPayload(), Header{})
	grant.payload.MaxUses = 1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := grant.Consume(ctx, ConsumptionStoreFunc(func(context.Context, Consumption) (ConsumptionResult, error) {
		return ConsumptionResult{}, nil
	})); !errors.Is(err, context.Canceled) {
		t.Fatalf("Consume(canceled) error = %v", err)
	}
	if _, err := grant.Consume(context.Background(), nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Consume(nil store) error = %v", err)
	}
}

func TestURLCanonicalizerRejectsInvalidProfilesAuthoritiesPathsAndQueries(t *testing.T) {
	valid := URLProfile{
		Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"https"},
		AllowedAuthorities: []string{"example.com"}, QueryParameters: []string{"a"},
	}
	badLimits := DefaultLimits()
	badLimits.MaxTokenBytes = 0
	if err := valid.Validate(badLimits); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Validate(invalid limits) error = %v", err)
	}
	profiles := []URLProfile{
		{},
		{SignatureParameter: "cap", AllowRelative: true},
		{Name: "profile", AllowRelative: true},
		{Name: "profile", SignatureParameter: "cap"},
		{Name: "profile", SignatureParameter: "cap", AllowRelative: true, AllowedAuthorities: []string{"example.com"}},
		{Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"ftp"}, AllowedAuthorities: []string{"example.com"}},
		{Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"https", "http"}, AllowedAuthorities: []string{"example.com"}},
		{Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"Example.com"}},
		{Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"é.example"}},
		{Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"example.com"}, QueryParameters: []string{"cap"}},
	}
	for index, profile := range profiles {
		if err := profile.Validate(DefaultLimits()); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("Validate(%d) error = %v", index, err)
		}
	}
	for _, raw := range []string{
		"https://example.com:0/path", "https://example.com:65536/path",
		"https://example.com./path", "https://é.example/path",
	} {
		u, _ := url.Parse(raw)
		if _, err := canonicalAuthority(u); !errors.Is(err, ErrInvalidURL) {
			t.Fatalf("canonicalAuthority(%q) error = %v", raw, err)
		}
	}
	for _, raw := range []string{"https://[::1]/", "https://[::1]:8443/", "https://example.com:8443/"} {
		u, _ := url.Parse(raw)
		if authority, err := canonicalAuthority(u); err != nil || authority == "" {
			t.Fatalf("canonicalAuthority(%q) = %q, %v", raw, authority, err)
		}
	}
	for _, raw := range []string{"relative", "/a\\b", "/a//b", "/a/../b"} {
		u, _ := url.Parse(raw)
		if _, err := canonicalPath(u); !errors.Is(err, ErrInvalidURL) {
			t.Fatalf("canonicalPath(%q) error = %v", raw, err)
		}
	}
	if path, err := canonicalPath(&url.URL{}); err != nil || path != "/" {
		t.Fatalf("canonicalPath(empty) = %q, %v", path, err)
	}
	if values, err := parseUniqueQuery(""); err != nil || len(values) != 0 {
		t.Fatalf("parseUniqueQuery(empty) = %#v, %v", values, err)
	}
	for _, raw := range []string{"&", "=value", "%zz=value", "a=%zz", "a=1&a=2"} {
		if _, err := parseUniqueQuery(raw); !errors.Is(err, ErrInvalidURL) {
			t.Fatalf("parseUniqueQuery(%q) error = %v", raw, err)
		}
	}
	for _, method := range []string{"", "get", "GE T", "GÉT", "GET?"} {
		if validMethod(method) {
			t.Fatalf("validMethod(%q) = true", method)
		}
	}
}

func TestSignedURLInternalCaveatsAndCanonicalTransportFailures(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := NewHMACSHA256Signer("key", key)
	verifier, _ := NewHMACSHA256Verifier(key)
	profile := URLProfile{
		Name: "profile", SignatureParameter: "cap", AllowedSchemes: []string{"https"},
		AllowedAuthorities: []string{"example.com"}, QueryParameters: []string{"a"},
	}
	payload := internalPayload()
	payload.Resource = ""
	payload.Operation = ""
	payload.Caveats = map[string]string{urlProfileCaveat: "collision"}
	request := URLRequest{Method: "GET", RawURL: "https://example.com/path?a=1"}
	if _, err := SignURL(context.Background(), payload, request, profile, signer, DefaultLimits()); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("SignURL(reserved caveat) error = %v", err)
	}
	payload.Caveats = nil
	payload.Issuer = ""
	if _, err := SignURL(context.Background(), payload, request, profile, signer, DefaultLimits()); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("SignURL(invalid payload) error = %v", err)
	}
	payload = internalPayload()
	payload.Resource = ""
	payload.Operation = ""
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: request.RawURL, BodyDigest: make([]byte, 32)}, profile, DefaultLimits(), false); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("canonicalURL(uncovered digest) error = %v", err)
	}
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: "https://example.com/path?a=1"}, profile, Limits{}, false); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("canonicalURL(invalid limits) error = %v", err)
	}
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: "https://example.com/path?a=1"}, profile, DefaultLimits(), true); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("canonicalURL(missing token) error = %v", err)
	}
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: "https://example.com/path?cap=x&a=1"}, profile, DefaultLimits(), false); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("canonicalURL(preexisting signature) error = %v", err)
	}
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: "/path"}, profile, DefaultLimits(), false); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("canonicalURL(relative forbidden) error = %v", err)
	}
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: "https://example.com/path?cap=x&a=1"}, profile, DefaultLimits(), true); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("canonicalURL(non-canonical query) error = %v", err)
	}
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: "https://EXAMPLE.com/path?a=1&cap=x"}, profile, DefaultLimits(), true); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("canonicalURL(non-canonical authority) error = %v", err)
	}

	payload = internalPayload()
	payload.Resource = "https://example.com/path?a=1"
	payload.Operation = "GET"
	payload.Caveats = map[string]string{urlProfileCaveat: profile.Name, urlDigestCaveat: "unexpected"}
	token, _ := Issue(context.Background(), payload, signer, DefaultLimits())
	rawURL := "https://example.com/path?a=1&cap=" + url.QueryEscape(token)
	resolver := ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		return ResolvedKey{Verifier: verifier}, nil
	})
	if _, err := VerifyURL(context.Background(), URLRequest{Method: "GET", RawURL: rawURL}, profile, resolver, VerifyOptions{Now: payload.IssuedAt, Limits: DefaultLimits()}); !errors.Is(err, ErrURLBinding) {
		t.Fatalf("VerifyURL(unexpected digest) error = %v", err)
	}
}

func internalPayload() Payload {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	return Payload{
		Version: 1, Issuer: "issuer", Audiences: []string{"audience"}, Bearer: true,
		Resource: "resource", Operation: "operation", IssuedAt: now,
		NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "capability",
	}
}

type stubSigner struct {
	algorithm Algorithm
	keyID     string
	signature []byte
}

func (signer stubSigner) Algorithm() Algorithm { return signer.algorithm }
func (signer stubSigner) KeyID() string        { return signer.keyID }
func (signer stubSigner) Sign(context.Context, []byte) ([]byte, error) {
	return signer.signature, nil
}

type failingVerifier struct{ err error }

func (failingVerifier) Algorithm() Algorithm { return HMACSHA256 }
func (verifier failingVerifier) Verify(context.Context, []byte, []byte) error {
	return verifier.err
}
