package capability_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func TestVerifyRequiresTrustedIssuerSelection(t *testing.T) {
	token, resolver, now := ordinaryIssuerToken(t, "ordinary-issuer", "ordinary-issuer")
	grant, err := capability.Verify(context.Background(), token, resolver, capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
	if !errors.Is(err, capability.ErrInvalidConfiguration) || grant.Payload().ID != "" {
		t.Fatal("verification inferred trusted issuer selection from the token")
	}
}

func TestVerifyBindsSelectedIssuerAndKeyOwnership(t *testing.T) {
	for _, test := range []struct {
		name, claim, owner, selected string
		want                         error
	}{
		{"match", "ordinary-issuer", "ordinary-issuer", "ordinary-issuer", nil},
		{"claim differs", "other-issuer", "ordinary-issuer", "ordinary-issuer", capability.ErrUnauthorized},
		{"owner differs", "ordinary-issuer", "other-issuer", "ordinary-issuer", capability.ErrUnauthorized},
		{"missing owner", "ordinary-issuer", "", "ordinary-issuer", capability.ErrInvalidConfiguration},
		{"selected differs", "ordinary-issuer", "ordinary-issuer", "other-issuer", capability.ErrUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, resolver, now := ordinaryIssuerToken(t, test.claim, test.owner)
			grant, err := capability.Verify(context.Background(), token, resolver, capability.VerifyOptions{Issuer: test.selected, Now: now, Limits: capability.DefaultLimits()})
			if !errors.Is(err, test.want) {
				t.Fatal("issuer policy classification differs")
			}
			if test.want != nil && grant.Payload().ID != "" {
				t.Fatal("issuer rejection returned authority")
			}
			if test.want == nil {
				for _, issuer := range []string{test.selected, "other-issuer", ""} {
					err := grant.Authorize(capability.Use{Issuer: issuer, Audience: "ordinary-audience", Resource: "ordinary-resource", Operation: "read"})
					if (err == nil) != (issuer == test.selected) {
						t.Fatal("attempted use did not require exact issuer")
					}
				}
			}
		})
	}
}

func ordinaryIssuerToken(t *testing.T, claim, owner string) (string, capability.Resolver, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	signer, _ := capability.NewHMACSHA256Signer("ordinary-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	payload := capability.Payload{
		Version: 1, Issuer: claim, Audiences: []string{"ordinary-audience"},
		Bearer: true, Resource: "ordinary-resource", Operation: "read", ID: "ordinary-capability",
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute),
	}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal("ordinary issuance failed")
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: owner, Verifier: verifier}, nil
	})
	return token, resolver, now
}

func TestIssuerKeyPolicySurvivesLocalAndBoundedResolution(t *testing.T) {
	token, source, now := ordinaryIssuerToken(t, "ordinary-issuer", "ordinary-issuer")
	key, err := source.Resolve(context.Background(), "ordinary-key", capability.HMACSHA256)
	if err != nil {
		t.Fatal("ordinary resolution failed")
	}
	set, err := capability.NewKeySet([]capability.Key{{ID: "ordinary-key", Issuer: "ordinary-issuer", Verifier: key.Verifier}})
	if err != nil {
		t.Fatal("owned key configuration failed")
	}
	bounded, err := capability.NewBoundedResolver(capability.BoundedResolverOptions{Source: set, Timeout: time.Second, AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}, MaxKeyIDBytes: 64})
	if err != nil {
		t.Fatal("bounded configuration failed")
	}
	for _, resolver := range []capability.Resolver{set, bounded} {
		resolved, err := resolver.Resolve(context.Background(), "ordinary-key", capability.HMACSHA256)
		if err != nil || resolved.Issuer != "ordinary-issuer" {
			t.Fatal("resolver dropped trusted key ownership")
		}
		if _, err := capability.Verify(context.Background(), token, resolver, capability.VerifyOptions{Issuer: "ordinary-issuer", Now: now, Limits: capability.DefaultLimits()}); err != nil {
			t.Fatal("owned ordinary token rejected")
		}
	}
	if _, err := capability.NewKeySet([]capability.Key{{ID: "ordinary-key", Verifier: key.Verifier}}); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatal("unowned key accepted")
	}
	if _, err := capability.NewKeySet([]capability.Key{{ID: "ordinary-key", Issuer: "ordinary-issuer", Verifier: key.Verifier}, {ID: "ordinary-key", Issuer: "other-issuer", Verifier: key.Verifier}}); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatal("global key identity became issuer-qualified")
	}
	_, unowned, _ := ordinaryIssuerToken(t, "ordinary-issuer", "")
	bounded, _ = capability.NewBoundedResolver(capability.BoundedResolverOptions{Source: unowned, Timeout: time.Second, AllowedAlgorithms: []capability.Algorithm{capability.HMACSHA256}, MaxKeyIDBytes: 64})
	if _, err := bounded.Resolve(context.Background(), "ordinary-key", capability.HMACSHA256); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatal("bounded resolver accepted unowned key")
	}
}
