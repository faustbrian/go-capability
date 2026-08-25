package capability_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

var testNow = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func TestCanonicalPayloadHasOneStableRepresentation(t *testing.T) {
	payload := validPayload()
	payload.Audiences = []string{"worker", "download"}
	payload.Caveats = map[string]string{"region": "eu", "format": "pdf"}

	canonical, err := capability.CanonicalPayload(payload, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("CanonicalPayload() error = %v", err)
	}
	want := `{"v":1,"iss":"https://issuer.example","aud":["download","worker"],"bearer":true,"resource":"documents/report-42","operation":"download","iat":1786276800,"nbf":1786276740,"exp":1786277100,"id":"cap-42","tenant":"tenant-7","correlation":"trace-9","max_uses":1,"caveats":{"format":"pdf","region":"eu"}}`
	if string(canonical) != want {
		t.Fatalf("CanonicalPayload() = %s\nwant = %s", canonical, want)
	}

	parsed, err := capability.ParsePayload(canonical, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	if parsed.ID != payload.ID || parsed.Caveats["format"] != "pdf" || parsed.Audiences[0] != "download" {
		t.Fatalf("ParsePayload() = %#v", parsed)
	}

	nonCanonical := []byte(`{ "v":1,"iss":"https://issuer.example" }`)
	if _, err := capability.ParsePayload(nonCanonical, capability.DefaultLimits()); !errors.Is(err, capability.ErrNonCanonical) {
		t.Fatalf("ParsePayload(non-canonical) error = %v", err)
	}
}

func TestPayloadValidationRejectsAuthorityAmbiguityAndUnboundedInput(t *testing.T) {
	tests := map[string]func(*capability.Payload){
		"subject and bearer":         func(payload *capability.Payload) { payload.Subject = "user-1" },
		"neither subject nor bearer": func(payload *capability.Payload) { payload.Bearer = false },
		"duplicate audience":         func(payload *capability.Payload) { payload.Audiences = []string{"api", "api"} },
		"invalid time range":         func(payload *capability.Payload) { payload.ExpiresAt = payload.NotBefore },
		"control character":          func(payload *capability.Payload) { payload.Resource = "file\nadmin" },
		"oversized field":            func(payload *capability.Payload) { payload.Operation = strings.Repeat("x", 257) },
		"too many caveats": func(payload *capability.Payload) {
			payload.Caveats = map[string]string{}
			for index := range 17 {
				payload.Caveats[string(rune('a'+index))] = "value"
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload := validPayload()
			mutate(&payload)
			if _, err := capability.CanonicalPayload(payload, capability.DefaultLimits()); !errors.Is(err, capability.ErrInvalidPayload) {
				t.Fatalf("CanonicalPayload() error = %v", err)
			}
		})
	}
}

func TestIssueVerifyAndAuthorizeHMACCapability(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := capability.NewHMACSHA256Signer("key-2026-08", key)
	if err != nil {
		t.Fatalf("NewHMACSHA256Signer() error = %v", err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatalf("NewHMACSHA256Verifier() error = %v", err)
	}
	token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if strings.Contains(token, string(key)) {
		t.Fatal("Issue() exposed key material")
	}

	resolver := capability.ResolverFunc(func(_ context.Context, keyID string, algorithm capability.Algorithm) (capability.ResolvedKey, error) {
		if keyID != "key-2026-08" || algorithm != capability.HMACSHA256 {
			return capability.ResolvedKey{}, capability.ErrUnknownKey
		}
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	grant, err := capability.Verify(context.Background(), token, resolver, capability.VerifyOptions{
		Now:    testNow,
		Skew:   time.Minute,
		Limits: capability.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := grant.Authorize(capability.Use{
		Audience: "download", Resource: "documents/report-42", Operation: "download", Tenant: "tenant-7",
	}); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if err := grant.Authorize(capability.Use{
		Audience: "download", Resource: "documents/report-43", Operation: "download", Tenant: "tenant-7",
	}); !errors.Is(err, capability.ErrUnauthorized) {
		t.Fatalf("Authorize(wrong resource) error = %v", err)
	}
}

func TestVerifyRejectsTamperingDowngradeAndInactiveKeys(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("key-1", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	parts := strings.Split(token, ".")
	parts[3] = parts[3][:len(parts[3])-1] + "A"
	tampered := strings.Join(parts, ".")

	active := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	if _, err := capability.Verify(context.Background(), tampered, active, options); !errors.Is(err, capability.ErrInvalidSignature) {
		t.Fatalf("Verify(tampered) error = %v", err)
	}

	wrongAlgorithm, _ := capability.NewEd25519Verifier(make(ed25519.PublicKey, ed25519.PublicKeySize))
	downgraded := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: wrongAlgorithm}, nil
	})
	if _, err := capability.Verify(context.Background(), token, downgraded, options); !errors.Is(err, capability.ErrAlgorithmMismatch) {
		t.Fatalf("Verify(downgraded resolver) error = %v", err)
	}

	inactive := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier, Disabled: true}, nil
	})
	if _, err := capability.Verify(context.Background(), token, inactive, options); !errors.Is(err, capability.ErrKeyDisabled) {
		t.Fatalf("Verify(disabled key) error = %v", err)
	}
}

func TestVerifyKeyRotationOverlapRemovalAndCompromiseResponse(t *testing.T) {
	oldKey := []byte("0123456789abcdef0123456789abcdef")
	newKey := []byte("abcdef0123456789abcdef0123456789")
	oldSigner, _ := capability.NewHMACSHA256Signer("old", oldKey)
	newSigner, _ := capability.NewHMACSHA256Signer("new", newKey)
	oldVerifier, _ := capability.NewHMACSHA256Verifier(oldKey)
	newVerifier, _ := capability.NewHMACSHA256Verifier(newKey)
	oldToken, _ := capability.Issue(context.Background(), validPayload(), oldSigner, capability.DefaultLimits())
	newToken, _ := capability.Issue(context.Background(), validPayload(), newSigner, capability.DefaultLimits())
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}

	overlap, _ := capability.NewKeySet([]capability.Key{
		{ID: "old", Verifier: oldVerifier}, {ID: "new", Verifier: newVerifier},
	})
	for _, token := range []string{oldToken, newToken} {
		if _, err := capability.Verify(context.Background(), token, overlap, options); err != nil {
			t.Fatalf("Verify(overlap) error = %v", err)
		}
	}

	removed, _ := capability.NewKeySet([]capability.Key{{ID: "new", Verifier: newVerifier}})
	if _, err := capability.Verify(context.Background(), oldToken, removed, options); !errors.Is(err, capability.ErrUnknownKey) {
		t.Fatalf("Verify(removed old key) error = %v", err)
	}
	revoked, _ := capability.NewKeySet([]capability.Key{
		{ID: "old", Verifier: oldVerifier, Revoked: true}, {ID: "new", Verifier: newVerifier},
	})
	if _, err := capability.Verify(context.Background(), oldToken, revoked, options); !errors.Is(err, capability.ErrKeyRevoked) {
		t.Fatalf("Verify(revoked old key) error = %v", err)
	}
	if _, err := capability.Verify(context.Background(), newToken, revoked, options); err != nil {
		t.Fatalf("Verify(new key after compromise response) error = %v", err)
	}
}

func TestVerifyEd25519AndTimeBoundaries(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := capability.NewEd25519Signer("ed-key-1", privateKey)
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	verifier, err := capability.NewEd25519Verifier(publicKey)
	if err != nil {
		t.Fatalf("NewEd25519Verifier() error = %v", err)
	}
	token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{
			Verifier:  verifier,
			NotBefore: testNow.Add(-time.Hour),
			NotAfter:  testNow.Add(time.Hour),
		}, nil
	})
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	if _, err := capability.Verify(context.Background(), token, resolver, options); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	options.Now = testNow.Add(-2 * time.Minute)
	if _, err := capability.Verify(context.Background(), token, resolver, options); !errors.Is(err, capability.ErrNotYetValid) {
		t.Fatalf("Verify(before nbf) error = %v", err)
	}
	options.Now = testNow.Add(7 * time.Minute)
	if _, err := capability.Verify(context.Background(), token, resolver, options); !errors.Is(err, capability.ErrExpired) {
		t.Fatalf("Verify(after exp) error = %v", err)
	}
}

func validPayload() capability.Payload {
	return capability.Payload{
		Version:       1,
		Issuer:        "https://issuer.example",
		Audiences:     []string{"download"},
		Bearer:        true,
		Resource:      "documents/report-42",
		Operation:     "download",
		IssuedAt:      testNow,
		NotBefore:     testNow.Add(-time.Minute),
		ExpiresAt:     testNow.Add(5 * time.Minute),
		ID:            "cap-42",
		Tenant:        "tenant-7",
		CorrelationID: "trace-9",
		MaxUses:       1,
	}
}
