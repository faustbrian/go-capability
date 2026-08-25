package capability_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

func TestSignAndVerifyAbsoluteURLCoversEveryProfileComponent(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("url-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	payload := validPayload()
	payload.Resource = ""
	payload.Operation = ""
	payload.Caveats = map[string]string{"disposition": "attachment"}
	digest := sha256.Sum256([]byte("report body"))
	profile := capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
		QueryParameters: []string{"download", "locale"}, RequireBodyDigest: true,
	}
	request := capability.URLRequest{
		Method: "GET", RawURL: "https://FILES.example:443/reports/%E2%82%AC?locale=fi&download=1",
		BodyDigest: digest[:],
	}
	signed, err := capability.SignURL(context.Background(), payload, request, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}
	if !strings.HasPrefix(signed, "https://files.example/reports/%E2%82%AC?cap=") ||
		!strings.Contains(signed, "&download=1&locale=fi") {
		t.Fatalf("SignURL() = %s", signed)
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	request.RawURL = signed
	grant, err := capability.VerifyURL(context.Background(), request, profile, resolver, capability.VerifyOptions{
		Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("VerifyURL() error = %v", err)
	}
	if grant.Payload().Resource != "https://files.example/reports/%E2%82%AC?download=1&locale=fi" {
		t.Fatalf("verified resource = %q", grant.Payload().Resource)
	}

	tampered := request
	tampered.Method = "POST"
	if _, err := capability.VerifyURL(context.Background(), tampered, profile, resolver, capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}); !errors.Is(err, capability.ErrURLBinding) {
		t.Fatalf("VerifyURL(method tamper) error = %v", err)
	}
	tampered = request
	tampered.BodyDigest = sha256.New().Sum(nil)
	if _, err := capability.VerifyURL(context.Background(), tampered, profile, resolver, capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}); !errors.Is(err, capability.ErrURLBinding) {
		t.Fatalf("VerifyURL(body tamper) error = %v", err)
	}
}

func TestVerifyURLRejectsAmbiguitySmugglingAndDowngrade(t *testing.T) {
	signed, profile, resolver := signedURLFixture(t)
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	tests := map[string]string{
		"duplicate signature":    signed + "&cap=second",
		"duplicate query":        strings.Replace(signed, "download=1", "download=1&download=2", 1),
		"authority substitution": strings.Replace(signed, "files.example", "evil.example", 1),
		"insecure downgrade":     strings.Replace(signed, "https://", "http://", 1),
		"fragment":               signed + "#ignored",
		"path traversal":         strings.Replace(signed, "/reports/42", "/reports/%2e%2e/admin", 1),
		"encoded slash":          strings.Replace(signed, "/reports/42", "/reports%2F42", 1),
	}
	for name, rawURL := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := capability.VerifyURL(context.Background(), capability.URLRequest{Method: "GET", RawURL: rawURL}, profile, resolver, options)
			if err == nil {
				t.Fatal("VerifyURL() error = nil")
			}
		})
	}
}

func TestRelativeURLRequiresExplicitProfileAndPreservesRelativeForm(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("url-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	payload := validPayload()
	payload.Resource = ""
	payload.Operation = ""
	profile := capability.URLProfile{
		Name: "invitation-v1", SignatureParameter: "cap", AllowRelative: true,
		QueryParameters: []string{"invite"},
	}
	request := capability.URLRequest{Method: "POST", RawURL: "/accept?invite=42"}
	signed, err := capability.SignURL(context.Background(), payload, request, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}
	if !strings.HasPrefix(signed, "/accept?cap=") {
		t.Fatalf("SignURL() = %s", signed)
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	request.RawURL = signed
	if _, err := capability.VerifyURL(context.Background(), request, profile, resolver, capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}); err != nil {
		t.Fatalf("VerifyURL() error = %v", err)
	}
	profile.AllowRelative = false
	if _, err := capability.SignURL(context.Background(), payload, capability.URLRequest{Method: "POST", RawURL: "/accept?invite=42"}, profile, signer, capability.DefaultLimits()); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("SignURL(relative forbidden) error = %v", err)
	}
}

func TestURLProfileRejectsUncoveredOrMalformedComponents(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("url-key", key)
	payload := validPayload()
	payload.Resource = ""
	payload.Operation = ""
	profile := capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
		QueryParameters: []string{"download"},
	}
	tests := map[string]capability.URLRequest{
		"uncovered query":            {Method: "GET", RawURL: "https://files.example/reports/42?admin=true"},
		"duplicate query":            {Method: "GET", RawURL: "https://files.example/reports/42?download=1&download=2"},
		"leading empty path segment": {Method: "GET", RawURL: "https://files.example//admin"},
		"userinfo":                   {Method: "GET", RawURL: "https://user@files.example/reports/42"},
		"invalid method":             {Method: "get", RawURL: "https://files.example/reports/42"},
		"fragment":                   {Method: "GET", RawURL: "https://files.example/reports/42#fragment"},
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := capability.SignURL(context.Background(), payload, request, profile, signer, capability.DefaultLimits()); err == nil {
				t.Fatal("SignURL() error = nil")
			}
		})
	}
	payload.Resource = "already-set"
	if _, err := capability.SignURL(context.Background(), payload, capability.URLRequest{Method: "GET", RawURL: "https://files.example/reports/42"}, profile, signer, capability.DefaultLimits()); !errors.Is(err, capability.ErrInvalidPayload) {
		t.Fatalf("SignURL(prebound payload) error = %v", err)
	}
}

func TestURLProfileRejectsNonCanonicalAuthorities(t *testing.T) {
	for _, authority := range []string{
		"",
		"files.example:0443",
		"user@files.example",
		"files.example.",
		"files.example/path",
		"[fe80::1%25zone]",
	} {
		profile := capability.URLProfile{
			Name: "download-v1", SignatureParameter: "cap",
			AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{authority},
		}
		if err := profile.Validate(capability.DefaultLimits()); !errors.Is(err, capability.ErrInvalidConfiguration) {
			t.Fatalf("Validate(authority %q) error = %v", authority, err)
		}
	}
}

func signedURLFixture(t *testing.T) (string, capability.URLProfile, capability.Resolver) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("url-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	payload := validPayload()
	payload.Resource = ""
	payload.Operation = ""
	payload.Caveats = nil
	profile := capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
		QueryParameters: []string{"download"},
	}
	signed, err := capability.SignURL(context.Background(), payload, capability.URLRequest{
		Method: "GET", RawURL: "https://files.example/reports/42?download=1",
	}, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	return signed, profile, resolver
}

func TestSignedURLExpirationRemainsCapabilityExpiration(t *testing.T) {
	signed, profile, resolver := signedURLFixture(t)
	_, err := capability.VerifyURL(context.Background(), capability.URLRequest{Method: "GET", RawURL: signed}, profile, resolver, capability.VerifyOptions{
		Now: testNow.Add(10 * time.Minute), Skew: 0, Limits: capability.DefaultLimits(),
	})
	if !errors.Is(err, capability.ErrExpired) {
		t.Fatalf("VerifyURL() error = %v", err)
	}
}
