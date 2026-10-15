package capability_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-capability/v2/memory"
)

func TestIdentityPurposeExactBounds(t *testing.T) {
	for _, invalid := range []string{"", "*", "a.*", "a._*", "a.-/child", "download/*", "download:child", "download child", "é"} {
		if purpose, err := capability.NewPurpose(invalid); !errors.Is(err, capability.ErrInvalidPayload) || purpose != "" {
			t.Fatalf("invalid purpose accepted: %q, %v", purpose, err)
		}
	}
	purpose, err := capability.NewPurpose("download")
	if err != nil || purpose != "download" {
		t.Fatalf("purpose = %q, %v", purpose, err)
	}
}

func newIdentityReviewService(t *testing.T, now *time.Time) capability.Service {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := capability.NewHMACSHA256Signer("review-key", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: validPayload().Issuer, ID: "review-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := capability.NewService(capability.ServiceConfig{Issuer: validPayload().Issuer,
		Signer: signer, Resolver: keys, Clock: func() time.Time { return *now }, Limits: capability.DefaultLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestIdentityServicePurposeIsIndependentOfAudience(t *testing.T) {
	now := testNow
	service := newIdentityReviewService(t, &now)
	payload := validPayload()
	payload.Operation = "download.file"
	proof, _, err := service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.Verify(context.Background(), proof, "download.file", "download")
	if err != nil || grant.Payload().ID != payload.ID {
		t.Fatalf("matching signed control rejected: %v", err)
	}
	for _, value := range []string{"different", "download", "download.file.child", "Download.file"} {
		t.Run(value, func(t *testing.T) {
			purpose, err := capability.NewPurpose(value)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := service.Verify(context.Background(), proof, purpose, "download")
			if !errors.Is(err, capability.ErrUnauthorized) || !reflect.DeepEqual(grant, capability.Grant{}) {
				t.Fatalf("wrong purpose with correct audience returned authority: %v", err)
			}
		})
	}
}

func TestIdentityServiceRejectsStructurallyValidForgedSignature(t *testing.T) {
	now := testNow
	service := newIdentityReviewService(t, &now)
	payload := validPayload()
	proof, _, err := service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.Verify(context.Background(), proof, "download", "download")
	if err != nil || grant.Payload().ID != payload.ID {
		t.Fatalf("genuine signed active control rejected: %v", err)
	}
	var token string
	if err := proof.Transfer(context.Background(), func(_ context.Context, borrowed []byte) error {
		token = string(borrowed)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		t.Fatal("unexpected canonical token framing")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil {
		t.Fatal("signature decoding failed")
	}
	if len(signature) == 0 {
		t.Fatal("signature missing")
	}
	signature[0] ^= 0x80
	parts[3] = base64.RawURLEncoding.EncodeToString(signature)
	forged, err := capability.ParseProof(strings.Join(parts, "."), capability.DefaultLimits())
	if err != nil {
		t.Fatal("canonical modified signature must remain structurally parseable")
	}
	grant, err = service.Verify(context.Background(), forged, "download", "download")
	if !errors.Is(err, capability.ErrInvalidSignature) || !reflect.DeepEqual(grant, capability.Grant{}) {
		t.Fatalf("structural parsing was promoted to authority: %v", err)
	}
}

func TestIdentityServiceIssuePreservesExplicitTimestamps(t *testing.T) {
	clock := testNow.Add(10 * time.Second)
	explicitIssuedAt := testNow.Add(-20 * time.Second)
	explicitNotBefore := testNow.Add(40 * time.Second)
	for _, test := range []struct {
		name                        string
		issuedAt, notBefore         time.Time
		wantIssuedAt, wantNotBefore time.Time
	}{
		{"both-explicit", explicitIssuedAt, explicitNotBefore, explicitIssuedAt, explicitNotBefore},
		{"only-issued-at-zero", time.Time{}, explicitNotBefore, clock, explicitNotBefore},
		{"only-not-before-zero", explicitIssuedAt, time.Time{}, explicitIssuedAt, clock},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := clock
			service := newIdentityReviewService(t, &now)
			payload := validPayload()
			payload.IssuedAt, payload.NotBefore = test.issuedAt, test.notBefore
			proof, _, err := service.Issue(context.Background(), payload)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantNotBefore.After(now) {
				grant, err := service.Verify(context.Background(), proof, "download", "download")
				if !errors.Is(err, capability.ErrNotYetValid) || !reflect.DeepEqual(grant, capability.Grant{}) {
					t.Fatalf("signed future activation was overwritten: %v", err)
				}
			}
			now = test.wantNotBefore
			grant, err := service.Verify(context.Background(), proof, "download", "download")
			if err != nil {
				t.Fatal(err)
			}
			actual := grant.Payload()
			if actual.IssuedAt != test.wantIssuedAt || actual.NotBefore != test.wantNotBefore {
				t.Fatalf("signed timestamps changed: iat=%v nbf=%v", actual.IssuedAt, actual.NotBefore)
			}
		})
	}
}

type identityClock struct{ now time.Time }

func (c identityClock) Now() time.Time { return c.now }

func TestIdentityServiceNeverConsumesAndHonorsLimits(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	config := capability.ServiceConfig{Issuer: validPayload().Issuer, Signer: signer, Resolver: capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: validPayload().Issuer, Verifier: verifier}, nil
	}), Clock: func() time.Time { return testNow }, Limits: capability.DefaultLimits()}
	s, err := capability.NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	payload := validPayload()
	payload.IssuedAt = time.Time{}
	payload.NotBefore = time.Time{}
	proof, reference, err := s.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if reference.CapabilityID != payload.ID || reference.Purpose != capability.Purpose(payload.Operation) || reference.ExpiresAt != payload.ExpiresAt || reference.Digest == ([32]byte{}) {
		t.Fatal("wrong reference")
	}
	for range 3 {
		if err := proof.ValidateBounds(32, 4096); err != nil {
			t.Fatal(err)
		}
		grant, err := s.Verify(context.Background(), proof, reference.Purpose, "download")
		if err != nil || grant.Payload().IssuedAt != testNow || grant.Payload().NotBefore != testNow {
			t.Fatalf("verification %v", err)
		}
	}
	grant, err := s.Verify(context.Background(), proof, reference.Purpose, "download")
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewConsumptionStore(identityClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	result, err := grant.Consume(context.Background(), store)
	if err != nil || result.Use != 1 {
		t.Fatalf("implicit consumption changed ordinal %v", err)
	}
	if _, err := grant.Consume(context.Background(), store); err != capability.ErrReplayExhausted {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), proof, reference.Purpose, "download"); err != nil {
		t.Fatal("verification must not implicitly consult consumption")
	}
	payload = validPayload()
	payload.Caveats = map[string]string{}
	for index := range 16 {
		payload.Caveats[string(rune('a'+index))] = strings.Repeat("x", 512)
	}
	proof, _, err = s.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error {
		if len(b) <= 4096 || len(b) > config.Limits.MaxTokenBytes {
			t.Fatal("default token bounds changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityReferenceIndependentPythonGolden(t *testing.T) {
	golden, err := os.ReadFile("testdata/v1-hmac.token")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	signer, _ := capability.NewHMACSHA256Signer("interop", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	now := time.Unix(1786276800, 0).UTC()
	s, err := capability.NewService(capability.ServiceConfig{Issuer: "interop", Signer: signer, Resolver: capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: "interop", Verifier: verifier}, nil
	}), Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	payload := capability.Payload{Version: 1, Issuer: "interop", Audiences: []string{"service"}, Bearer: true, Resource: "objects/42", Operation: "read", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "interop-capability"}
	proof, reference, err := s.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	// Python hashlib and struct.pack independently derive this digest from the
	// checked-in 367-byte canonical token, not from Go's reference encoder.
	if hex.EncodeToString(reference.Digest[:]) != "24fb006ca781cebe17a9084536afcb51c829958f47d369fb5cf79fd151508a3a" {
		t.Fatal("reference domain vector mismatch")
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error {
		if string(b) != strings.TrimSpace(string(golden)) {
			t.Fatal("wire golden changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func FuzzIdentityProofIngress(f *testing.F) {
	f.Add("invalid")
	golden, err := os.ReadFile("testdata/v1-hmac.token")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(strings.TrimSpace(string(golden)))
	f.Add(strings.Repeat("x", 16<<10+1))
	f.Fuzz(func(t *testing.T, token string) {
		proof, err := capability.ParseProof(token, capability.DefaultLimits())
		if err != nil {
			return
		}
		if err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error {
			if string(b) != token {
				t.Error("ingress byte mutation")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIdentityProofTransferInvalidatesAliases(t *testing.T) {
	signer, err := capability.NewHMACSHA256Signer("key", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(token, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	alias := proof
	var borrowed []byte
	err = proof.Transfer(context.Background(), func(ctx context.Context, bytes []byte) error {
		borrowed = bytes
		if string(bytes) != token {
			t.Error("transfer changed canonical token")
		}
		if err := alias.Transfer(ctx, func(context.Context, []byte) error { t.Error("alias callback invoked"); return nil }); !errors.Is(err, capability.ErrInvalidToken) {
			t.Errorf("alias error = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if borrowed == nil {
		t.Fatal("callback borrow not observed")
	}
	for _, value := range borrowed[:cap(borrowed)] {
		if value != 0 {
			t.Fatal("borrowed secret retained")
		}
	}
	if err := alias.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); !errors.Is(err, capability.ErrInvalidToken) {
		t.Fatalf("reused proof = %v", err)
	}
}

func TestIdentityProofTransferErasesPoisonedSpareCapacity(t *testing.T) {
	golden, err := os.ReadFile("testdata/v1-hmac.token")
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			proof, err := capability.ParseProof(strings.TrimSpace(string(golden)), capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			alias := proof
			var exposed []byte
			err = proof.Transfer(context.Background(), func(_ context.Context, borrowed []byte) error {
				t.Logf("borrow len=%d cap=%d spare=%d", len(borrowed), cap(borrowed), cap(borrowed)-len(borrowed))
				exposed = borrowed[:cap(borrowed)]
				// Fresh allocation tails start zero. Poison every actually exposed
				// spare byte so length-only clearing cannot satisfy this assertion.
				for index := len(borrowed); index < len(exposed); index++ {
					exposed[index] = 0xa5
				}
				switch outcome {
				case "error":
					return errors.New("private callback diagnostic")
				case "panic":
					panic("private callback diagnostic")
				}
				return nil
			})
			if outcome == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, capability.ErrProofTransferFailed) {
				t.Fatalf("callback failure classification = %v", err)
			}
			if exposed == nil {
				t.Fatal("callback borrow not observed")
			}
			for index, value := range exposed {
				if value != 0 {
					t.Fatalf("exposed allocation byte %d retained after %s", index, outcome)
				}
			}
			if err := alias.Transfer(context.Background(), func(context.Context, []byte) error {
				t.Error("terminal alias invoked another callback")
				return nil
			}); !errors.Is(err, capability.ErrInvalidToken) {
				t.Fatalf("terminal alias = %v", err)
			}
		})
	}
}
