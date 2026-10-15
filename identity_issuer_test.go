package capability

import (
	"context"
	"errors"
	"testing"
)

func TestIdentityServicePinsTrustedIssuer(t *testing.T) {
	config, token := identityFixture(t)
	proof := mustProof(t, token)
	config.Issuer = ""
	if service, err := NewService(config); !errors.Is(err, ErrInvalidConfiguration) || service != nil {
		t.Fatal("issuer-less service constructed", err)
	}
	config.Issuer = "other"
	service, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	payload := internalPayload()
	if _, _, err := service.Issue(context.Background(), payload); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("service signed another issuer", err)
	}
	if _, err := service.Verify(context.Background(), proof, Purpose(payload.Operation), payload.Audiences[0]); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("service trusted token-selected issuer", err)
	}
	config.Issuer = payload.Issuer
	config.Resolver = ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		key := configVerifier(t)
		key.Issuer = "other"
		return key, nil
	})
	service, err = NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), proof, Purpose(payload.Operation), payload.Audiences[0]); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("service accepted a differently owned key", err)
	}
	config.Resolver = ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		key := configVerifier(t)
		key.Issuer = ""
		return key, nil
	})
	service, err = NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), proof, Purpose(payload.Operation), payload.Audiences[0]); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("service accepted issuer-less key", err)
	}
}
