package capability_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/golib/pkg/capability"
)

func TestConstructorsRejectWrongKeyTypesAndCopyKeys(t *testing.T) {
	if _, err := capability.NewHMACSHA256Signer("", make([]byte, 32)); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewHMACSHA256Signer(empty ID) error = %v", err)
	}
	if _, err := capability.NewHMACSHA256Signer("key", make([]byte, 31)); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewHMACSHA256Signer(short key) error = %v", err)
	}
	if _, err := capability.NewHMACSHA256Verifier(make([]byte, 31)); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewHMACSHA256Verifier(short key) error = %v", err)
	}
	if _, err := capability.NewEd25519Signer("key", make(ed25519.PrivateKey, 63)); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewEd25519Signer(short key) error = %v", err)
	}
	if _, err := capability.NewEd25519Verifier(make(ed25519.PublicKey, 31)); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewEd25519Verifier(short key) error = %v", err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("copied", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	signature, _ := signer.Sign(context.Background(), []byte("message"))
	for index := range key {
		key[index] = 0
	}
	if err := verifier.Verify(context.Background(), []byte("message"), signature); err != nil {
		t.Fatalf("Verify() after caller key mutation error = %v", err)
	}
}

func TestCryptographicOperationsHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key := []byte("0123456789abcdef0123456789abcdef")
	hmacSigner, _ := capability.NewHMACSHA256Signer("key", key)
	hmacVerifier, _ := capability.NewHMACSHA256Verifier(key)
	if _, err := hmacSigner.Sign(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("HMAC Sign() error = %v", err)
	}
	if err := hmacVerifier.Verify(ctx, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("HMAC Verify() error = %v", err)
	}
	_, privateKey, _ := ed25519.GenerateKey(nil)
	edSigner, _ := capability.NewEd25519Signer("key", privateKey)
	edVerifier, _ := capability.NewEd25519Verifier(privateKey.Public().(ed25519.PublicKey))
	if _, err := edSigner.Sign(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ed25519 Sign() error = %v", err)
	}
	if err := edVerifier.Verify(ctx, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ed25519 Verify() error = %v", err)
	}
	var nilContext context.Context
	if _, err := hmacSigner.Sign(nilContext, nil); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Sign(nil context) error = %v", err)
	}
}

func TestParseRejectsMalformedAndAmbiguousTokens(t *testing.T) {
	limits := capability.DefaultLimits()
	for name, token := range map[string]string{
		"empty":           "",
		"wrong prefix":    "other.e30.e30.c2ln",
		"extra segment":   "cap1.e30.e30.c2ln.extra",
		"padded header":   "cap1.e30=.e30.c2ln",
		"empty signature": "cap1.e30.e30.",
		"oversized":       strings.Repeat("x", limits.MaxTokenBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := capability.Parse(token, limits); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func TestVerifyRejectsResolverAndKeyLifecycleFailures(t *testing.T) {
	token, verifier := hmacFixture(t)
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	resolverFailure := errors.New("resolver unavailable")
	cases := map[string]struct {
		key  capability.ResolvedKey
		err  error
		want error
	}{
		"resolver outage":  {err: resolverFailure, want: capability.ErrKeyResolution},
		"missing verifier": {want: capability.ErrUnknownKey},
		"revoked":          {key: capability.ResolvedKey{Verifier: verifier, Revoked: true}, want: capability.ErrKeyRevoked},
		"not active yet":   {key: capability.ResolvedKey{Verifier: verifier, NotBefore: testNow.Add(time.Second)}, want: capability.ErrKeyNotActive},
		"no longer active": {key: capability.ResolvedKey{Verifier: verifier, NotAfter: testNow}, want: capability.ErrKeyNotActive},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
				return test.key, test.err
			})
			if _, err := capability.Verify(context.Background(), token, resolver, options); !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v", err)
			} else if test.err != nil && errors.Is(err, test.err) {
				t.Fatal("Verify() retained private resolver error")
			}
		})
	}
	if _, err := capability.Verify(context.Background(), token, nil, options); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Verify(nil resolver) error = %v", err)
	}
	options.Skew = -time.Second
	if _, err := capability.Verify(context.Background(), token, capability.ResolverFunc(nil), options); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Verify(negative skew) error = %v", err)
	}
}

func TestVerifyPreservesUnknownKeyPolicyThroughResolverLayers(t *testing.T) {
	token, verifier := hmacFixture(t)
	set, err := capability.NewKeySet([]capability.Key{{ID: "different-key", Verifier: verifier}})
	if err != nil {
		t.Fatalf("NewKeySet() error = %v", err)
	}
	bounded, err := capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: set, Timeout: time.Second,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}, MaxKeyIDBytes: 32,
	})
	if err != nil {
		t.Fatalf("NewBoundedResolver() error = %v", err)
	}
	mismatchSource := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{}, capability.ErrAlgorithmMismatch
	})
	boundedMismatch, err := capability.NewBoundedResolver(capability.BoundedResolverOptions{
		Source: mismatchSource, Timeout: time.Second,
		AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}, MaxKeyIDBytes: 32,
	})
	if err != nil {
		t.Fatalf("NewBoundedResolver(mismatch) error = %v", err)
	}
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	for name, test := range map[string]struct {
		resolver capability.Resolver
		want     error
	}{
		"key set unknown":         {resolver: set, want: capability.ErrUnknownKey},
		"bounded unknown":         {resolver: bounded, want: capability.ErrUnknownKey},
		"direct mismatch":         {resolver: mismatchSource, want: capability.ErrAlgorithmMismatch},
		"bounded source mismatch": {resolver: boundedMismatch, want: capability.ErrAlgorithmMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := capability.Verify(context.Background(), token, test.resolver, options); !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestGrantIsDefensiveAndRequiresEveryAuthorityDimension(t *testing.T) {
	payload := validPayload()
	payload.Bearer = false
	payload.Subject = "user-7"
	payload.Caveats = map[string]string{"region": "eu"}
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	grant, err := capability.Verify(context.Background(), token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	}), capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	use := capability.Use{Audience: "download", Subject: "user-7", Resource: payload.Resource, Operation: payload.Operation, Tenant: payload.Tenant, Caveats: map[string]string{"region": "eu"}}
	if err := grant.Authorize(use); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	mutations := map[string]func(*capability.Use){
		"audience":  func(use *capability.Use) { use.Audience = "upload" },
		"subject":   func(use *capability.Use) { use.Subject = "user-8" },
		"operation": func(use *capability.Use) { use.Operation = "delete" },
		"tenant":    func(use *capability.Use) { use.Tenant = "tenant-8" },
		"caveat":    func(use *capability.Use) { use.Caveats["region"] = "us" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := use
			candidate.Caveats = map[string]string{"region": "eu"}
			mutate(&candidate)
			if err := grant.Authorize(candidate); !errors.Is(err, capability.ErrUnauthorized) {
				t.Fatalf("Authorize() error = %v", err)
			}
		})
	}

	copyPayload := grant.Payload()
	copyPayload.Audiences[0] = "admin"
	copyPayload.Caveats["region"] = "us"
	if err := grant.Authorize(use); err != nil {
		t.Fatalf("Authorize() after returned payload mutation error = %v", err)
	}
	if grant.Header().KeyID != "key" {
		t.Fatalf("Header() = %#v", grant.Header())
	}
}

func TestPayloadLimitsAndCanonicalParserFailures(t *testing.T) {
	invalidLimits := capability.DefaultLimits()
	invalidLimits.MaxTokenBytes = 0
	if _, err := capability.CanonicalPayload(validPayload(), invalidLimits); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("CanonicalPayload(invalid limits) error = %v", err)
	}
	if _, err := capability.ParsePayload([]byte(`{}`), invalidLimits); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("ParsePayload(invalid limits) error = %v", err)
	}
	limits := capability.DefaultLimits()
	for name, encoded := range map[string][]byte{
		"invalid UTF-8": {0xff},
		"trailing data": []byte(`{"v":1}{}`),
		"unknown field": []byte(`{"unknown":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := capability.ParsePayload(encoded, limits); err == nil {
				t.Fatal("ParsePayload() error = nil")
			}
		})
	}
	payload := validPayload()
	payload.Version = 2
	if _, err := capability.CanonicalPayload(payload, limits); !errors.Is(err, capability.ErrInvalidPayload) {
		t.Fatalf("CanonicalPayload(version) error = %v", err)
	}
	payload = validPayload()
	payload.MaxUses = limits.MaxUses + 1
	if _, err := capability.CanonicalPayload(payload, limits); !errors.Is(err, capability.ErrInvalidPayload) {
		t.Fatalf("CanonicalPayload(max uses) error = %v", err)
	}
}

func TestPayloadRejectsEveryBoundedCollectionAndTimeBoundary(t *testing.T) {
	limits := capability.DefaultLimits()
	tests := map[string]func(*capability.Payload, *capability.Limits){
		"missing issuer":    func(payload *capability.Payload, _ *capability.Limits) { payload.Issuer = "" },
		"missing resource":  func(payload *capability.Payload, _ *capability.Limits) { payload.Resource = "" },
		"missing operation": func(payload *capability.Payload, _ *capability.Limits) { payload.Operation = "" },
		"missing ID":        func(payload *capability.Payload, _ *capability.Limits) { payload.ID = "" },
		"invalid tenant":    func(payload *capability.Payload, _ *capability.Limits) { payload.Tenant = "tenant\x7f" },
		"no audiences":      func(payload *capability.Payload, _ *capability.Limits) { payload.Audiences = nil },
		"too many audiences": func(payload *capability.Payload, limits *capability.Limits) {
			payload.Audiences = make([]string, limits.MaxAudiences+1)
			for index := range payload.Audiences {
				payload.Audiences[index] = fmt.Sprintf("aud-%02d", index)
			}
		},
		"negative issued at":  func(payload *capability.Payload, _ *capability.Limits) { payload.IssuedAt = time.Unix(-1, 0) },
		"negative not before": func(payload *capability.Payload, _ *capability.Limits) { payload.NotBefore = time.Unix(-1, 0) },
		"expiry at issue":     func(payload *capability.Payload, _ *capability.Limits) { payload.ExpiresAt = payload.IssuedAt },
		"lifetime exceeded": func(payload *capability.Payload, limits *capability.Limits) {
			payload.ExpiresAt = payload.NotBefore.Add(limits.MaxLifetime + time.Second)
		},
		"invalid caveat key": func(payload *capability.Payload, _ *capability.Limits) {
			payload.Caveats = map[string]string{"": "value"}
		},
		"invalid caveat value": func(payload *capability.Payload, _ *capability.Limits) {
			payload.Caveats = map[string]string{"key": ""}
		},
		"oversized encoded payload": func(payload *capability.Payload, limits *capability.Limits) { limits.MaxTokenBytes = 8 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload := validPayload()
			bounded := limits
			mutate(&payload, &bounded)
			if _, err := capability.CanonicalPayload(payload, bounded); err == nil {
				t.Fatal("CanonicalPayload() error = nil")
			}
		})
	}
	canonical, _ := capability.CanonicalPayload(validPayload(), limits)
	if _, err := capability.ParsePayload(nil, limits); !errors.Is(err, capability.ErrInvalidPayload) {
		t.Fatalf("ParsePayload(empty) error = %v", err)
	}
	if _, err := capability.ParsePayload(append(canonical, '{'), limits); !errors.Is(err, capability.ErrInvalidPayload) {
		t.Fatalf("ParsePayload(trailing malformed) error = %v", err)
	}
	overflowLimits := limits
	overflowLimits.MaxTokenBytes = len(canonical) - 1
	if _, err := capability.ParsePayload(canonical, overflowLimits); !errors.Is(err, capability.ErrInvalidPayload) {
		t.Fatalf("ParsePayload(oversized) error = %v", err)
	}
}

func TestEd25519RejectsInvalidSignature(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	verifier, _ := capability.NewEd25519Verifier(publicKey)
	if err := verifier.Verify(context.Background(), []byte("message"), make([]byte, ed25519.SignatureSize)); !errors.Is(err, capability.ErrInvalidSignature) {
		t.Fatalf("Verify(invalid) error = %v", err)
	}
}

type testFataler interface {
	Helper()
	Fatalf(string, ...any)
}

func hmacFixture(t testFataler) (string, capability.Verifier) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	return token, verifier
}
