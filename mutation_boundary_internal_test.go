package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPayloadExactAcceptedBoundaries(t *testing.T) {
	limits := DefaultLimits()
	payload := internalPayload()
	payload.Resource = strings.Repeat("r", limits.MaxFieldBytes)
	payload.Audiences = make([]string, limits.MaxAudiences)
	for index := range payload.Audiences {
		payload.Audiences[index] = fmt.Sprintf("audience-%02d", index)
	}
	payload.Caveats = make(map[string]string, limits.MaxCaveats)
	for index := range limits.MaxCaveats {
		payload.Caveats[fmt.Sprintf("caveat-%02d", index)] = strings.Repeat("v", limits.MaxCaveatBytes)
	}
	payload.IssuedAt = time.Unix(0, 0).UTC()
	payload.NotBefore = payload.IssuedAt
	payload.ExpiresAt = payload.IssuedAt.Add(limits.MaxLifetime)
	payload.MaxUses = limits.MaxUses
	encoded, err := CanonicalPayload(payload, limits)
	if err != nil {
		t.Fatalf("CanonicalPayload(exact boundaries) error = %v", err)
	}
	exact := limits
	exact.MaxTokenBytes = len(encoded)
	if _, err := CanonicalPayload(payload, exact); err != nil {
		t.Fatalf("CanonicalPayload(exact byte limit) error = %v", err)
	}
	if _, err := ParsePayload(encoded, exact); err != nil {
		t.Fatalf("ParsePayload(exact byte limit) error = %v", err)
	}

	zeroCaveats := limits
	zeroCaveats.MaxCaveats = 0
	payload = internalPayload()
	payload.Caveats = nil
	if _, err := CanonicalPayload(payload, zeroCaveats); err != nil {
		t.Fatalf("CanonicalPayload(zero caveat allowance) error = %v", err)
	}
	if !validText(" ", 1, true) || validText("\x1f", 1, true) {
		t.Fatal("validText() mishandled exact control boundary")
	}
}

func TestPayloadRejectsExpiryExactlyAtLaterNotBefore(t *testing.T) {
	payload := internalPayload()
	payload.NotBefore = payload.IssuedAt.Add(time.Minute)
	payload.ExpiresAt = payload.NotBefore
	if _, err := CanonicalPayload(payload, DefaultLimits()); err == nil {
		t.Fatal("CanonicalPayload(expiry at not-before) error = nil")
	}
}

func TestPayloadRejectsEitherNegativeTimeIndependently(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxLifetime = 2 * time.Second

	for name, mutate := range map[string]func(*Payload){
		"issued at":  func(payload *Payload) { payload.IssuedAt = time.Unix(-1, 0).UTC() },
		"not before": func(payload *Payload) { payload.NotBefore = time.Unix(-1, 0).UTC() },
	} {
		t.Run(name, func(t *testing.T) {
			payload := internalPayload()
			payload.IssuedAt = time.Unix(0, 0).UTC()
			payload.NotBefore = payload.IssuedAt
			payload.ExpiresAt = time.Unix(1, 0).UTC()
			mutate(&payload)
			if _, err := CanonicalPayload(payload, limits); err == nil {
				t.Fatal("CanonicalPayload() error = nil")
			}
		})
	}
}

func TestRequireEOFRejectsASecondCompleteValue(t *testing.T) {
	decoder := json.NewDecoder(bytes.NewBufferString(`{} {}`))
	var first any
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("Decode(first) error = %v", err)
	}
	if err := requireEOF(decoder); err == nil {
		t.Fatal("requireEOF(second value) error = nil")
	}
}

func TestEveryLimitsFieldOwnsItsBoundary(t *testing.T) {
	mutations := map[string]func(*Limits){
		"token":        func(limits *Limits) { limits.MaxTokenBytes = 0 },
		"field":        func(limits *Limits) { limits.MaxFieldBytes = 0 },
		"audiences":    func(limits *Limits) { limits.MaxAudiences = 0 },
		"caveats":      func(limits *Limits) { limits.MaxCaveats = -1 },
		"caveat bytes": func(limits *Limits) { limits.MaxCaveatBytes = 0 },
		"lifetime":     func(limits *Limits) { limits.MaxLifetime = 0 },
		"uses":         func(limits *Limits) { limits.MaxUses = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits()
			mutate(&limits)
			if err := validateLimits(limits); err == nil {
				t.Fatal("validateLimits() error = nil")
			}
		})
	}
}

func TestTokenExactAcceptedBoundaries(t *testing.T) {
	payload := internalPayload()
	limits := DefaultLimits()
	signer := stubSigner{algorithm: HMACSHA256, keyID: "key", signature: make([]byte, 512)}
	token, err := Issue(context.Background(), payload, signer, limits)
	if err != nil {
		t.Fatalf("Issue(512-byte signature) error = %v", err)
	}
	exact := limits
	exact.MaxTokenBytes = len(token)
	if _, err := Issue(context.Background(), payload, signer, exact); err != nil {
		t.Fatalf("Issue(exact token limit) error = %v", err)
	}
	if _, err := Parse(token, exact); err != nil {
		t.Fatalf("Parse(exact token and signature limit) error = %v", err)
	}

	header := Header{Version: 1, Type: "capability", Algorithm: HMACSHA256, KeyID: "key"}
	headerBytes, _ := canonicalHeader(header)
	payloadBytes, _ := CanonicalPayload(payload, limits)
	encode := base64.RawURLEncoding.EncodeToString
	framed := tokenPrefix + "." + encode(headerBytes) + "." + encode(payloadBytes) + "." + encode(make([]byte, 512))
	if _, err := Parse(framed, limits); err != nil {
		t.Fatalf("Parse(512-byte signature) error = %v", err)
	}

	header.KeyID = "key"
	headerBytes, _ = canonicalHeader(header)
	headerLimits := limits
	headerLimits.MaxFieldBytes = len(header.KeyID)
	if _, err := parseHeader(headerBytes, headerLimits); err != nil {
		t.Fatalf("parseHeader(exact key ID limit) error = %v", err)
	}
}

func TestParseRejectsEachTokenFramingBoundaryIndependently(t *testing.T) {
	limits := DefaultLimits()
	encode := base64.RawURLEncoding.EncodeToString
	payloadBytes, _ := CanonicalPayload(internalPayload(), limits)
	headerBytes, _ := canonicalHeader(Header{Version: 1, Type: "capability", Algorithm: HMACSHA256, KeyID: "key"})
	unsigned := tokenPrefix + "." + encode(headerBytes) + "." + encode(payloadBytes) + "."
	valid := unsigned + encode([]byte("signature"))

	tests := map[string]struct {
		token  string
		limits Limits
	}{
		"empty":            {token: "", limits: limits},
		"over token limit": {token: valid, limits: func() Limits { bounded := limits; bounded.MaxTokenBytes = len(valid) - 1; return bounded }()},
		"extra segment":    {token: valid + ".ignored", limits: limits},
		"wrong prefix":     {token: "other" + strings.TrimPrefix(valid, tokenPrefix), limits: limits},
		"partial base64":   {token: unsigned + "c2ln*", limits: limits},
		"empty signature":  {token: unsigned, limits: limits},
		"large signature":  {token: unsigned + encode(make([]byte, 513)), limits: limits},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(test.token, test.limits); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestClockSkewExtendsExclusiveExpiry(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := NewHMACSHA256Signer("key", key)
	verifier, _ := NewHMACSHA256Verifier(key)
	payload := internalPayload()
	token, _ := Issue(context.Background(), payload, signer, DefaultLimits())
	resolver := ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		return ResolvedKey{Verifier: verifier}, nil
	})
	if _, err := Verify(context.Background(), token, resolver, VerifyOptions{
		Now: payload.ExpiresAt.Add(30 * time.Second), Skew: time.Minute, Limits: DefaultLimits(),
	}); err != nil {
		t.Fatalf("Verify(within expiry skew) error = %v", err)
	}
}

func TestURLAndProfileExactAcceptedBoundaries(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTokenBytes = 256
	profile := URLProfile{
		Name: "profile", SignatureParameter: "cap",
		AllowedSchemes: []string{"http", "https"}, AllowedAuthorities: []string{"example.com"},
		QueryParameters: []string{"a"},
	}
	prefix := "https://example.com/"
	raw := prefix + strings.Repeat("a", limits.MaxTokenBytes*2-len(prefix))
	if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: raw}, profile, limits, false); err != nil {
		t.Fatalf("canonicalURL(exact byte limit) error = %v", err)
	}
	for rawURL, want := range map[string]string{
		"http://example.com:80/":     "example.com",
		"https://example.com:443/":   "example.com",
		"https://example.com:1/":     "example.com:1",
		"https://example.com:65535/": "example.com:65535",
		"http://example.com:443/":    "example.com:443",
		"https://[::1]/":             "[::1]",
		"https://[::1]:8443/":        "[::1]:8443",
	} {
		u, _ := url.Parse(rawURL)
		if got, err := canonicalAuthority(u); err != nil || got != want {
			t.Fatalf("canonicalAuthority(%q) = %q, %v; want %q", rawURL, got, err, want)
		}
	}
	for _, rawPath := range []string{"/", "/a/"} {
		u, _ := url.Parse(rawPath)
		if _, err := canonicalPath(u); err != nil {
			t.Fatalf("canonicalPath(%q) error = %v", rawPath, err)
		}
	}
	for _, method := range []string{"!", "~"} {
		if !validMethod(method) {
			t.Fatalf("validMethod(%q) = false", method)
		}
	}
	if validMethod(string(rune(0x7f))) {
		t.Fatal("validMethod(DEL) = true")
	}
	if !strictSortedUnique([]string{"a", "b"}) || strictSortedUnique([]string{"a", "a"}) {
		t.Fatal("strictSortedUnique() boundary mismatch")
	}
	if !containsString([]string{"a", "b"}, "b") || containsString([]string{"a", "b"}, "c") {
		t.Fatal("containsString() boundary mismatch")
	}
	if !ascii(string(rune(0x7f))) || ascii(string(rune(0x80))) {
		t.Fatal("ascii() boundary mismatch")
	}
}

func TestURLParserRejectsEachAmbiguousParsedComponent(t *testing.T) {
	profile := URLProfile{
		Name: "profile", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"example.com"},
	}
	for name, raw := range map[string]string{
		"parse error": "%",
		"opaque":      "https:opaque",
		"fragment":    "https://example.com/path#fragment",
		"force query": "https://example.com/path?",
		"userinfo":    "https://user@example.com/path",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := canonicalURL(URLRequest{Method: "GET", RawURL: raw}, profile, DefaultLimits(), false); !errors.Is(err, ErrInvalidURL) {
				t.Fatalf("canonicalURL() error = %v", err)
			}
		})
	}
}

func TestProfileAuthorityValidationDistinguishesEveryParseBoundary(t *testing.T) {
	for name, test := range map[string]struct {
		authority string
		scheme    string
		want      bool
	}{
		"valid":              {authority: "example.com", scheme: "https", want: true},
		"parse error":        {authority: "%", scheme: "https"},
		"userinfo":           {authority: "user@example.com", scheme: "https"},
		"host mismatch":      {authority: "example.com/path", scheme: "https"},
		"authority error":    {authority: "example.com:0", scheme: "https"},
		"canonical mismatch": {authority: "example.com:443", scheme: "https"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := profileAuthorityValidForScheme(test.authority, test.scheme); got != test.want {
				t.Fatalf("profileAuthorityValidForScheme() = %t, want %t", got, test.want)
			}
		})
	}
	if !canonicalProfileAuthority("example.com:443", []string{"https", "http"}) {
		t.Fatal("canonicalProfileAuthority() stopped before a valid later scheme")
	}
}

func TestCanonicalURLBaseDistinguishesSchemeAndAuthorityFailures(t *testing.T) {
	profile := URLProfile{
		Name: "profile", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"example.com"},
	}
	for name, u := range map[string]*url.URL{
		"uppercase scheme":     {Scheme: "HTTPS", Host: "example.com", Path: "/"},
		"disallowed scheme":    {Scheme: "http", Host: "example.com", Path: "/"},
		"invalid authority":    {Scheme: "https", Host: "example.com:0", Path: "/"},
		"disallowed authority": {Scheme: "https", Host: "other.example", Path: "/"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalURLBase(u, profile); !errors.Is(err, ErrInvalidURL) {
				t.Fatalf("canonicalURLBase() error = %v", err)
			}
		})
	}
}
