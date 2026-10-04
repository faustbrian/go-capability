//nolint:staticcheck // Compatibility proof intentionally imports the deprecated path.
package capabilityhttp_test

//lint:file-ignore SA1019 Compatibility proof intentionally imports the deprecated path.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-capability/v2/adapters/http"
	legacy "github.com/faustbrian/go-capability/v2/caphttp"
)

func TestBothHTTPPathsRequireAndForwardTrustedIssuer(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	signer, _ := capability.NewHMACSHA256Signer("ordinary-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	profile := capability.URLProfile{Name: "ordinary-profile", SignatureParameter: "cap", AllowRelative: true}
	payload := capability.Payload{Version: 1, Issuer: "ordinary-issuer", Audiences: []string{"ordinary-audience"}, Bearer: true, ID: "ordinary-capability", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	signed, err := capability.SignURL(context.Background(), payload, capability.URLRequest{Method: "GET", RawURL: "/ordinary-resource"}, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal("ordinary URL issuance failed")
	}
	for _, owner := range []string{"ordinary-issuer", "other-issuer"} {
		resolver, err := capability.NewKeySet([]capability.Key{{ID: "ordinary-key", Issuer: owner, Verifier: verifier}})
		if err != nil {
			t.Fatal("ordinary key configuration failed")
		}
		for _, selected := range []string{"ordinary-issuer", "other-issuer", ""} {
			options := capabilityhttp.VerifierOptions{Issuer: selected, Profile: profile, Resolver: resolver, Clock: fixedClock{now: now}, Limits: capability.DefaultLimits()}
			canonical, canonicalErr := capabilityhttp.NewVerifier(options)
			compatibility, compatibilityErr := legacy.NewVerifier(legacy.VerifierOptions{Issuer: selected, Profile: profile, Resolver: resolver, Clock: fixedClock{now: now}, Limits: capability.DefaultLimits()})
			if selected == "" {
				if !errors.Is(canonicalErr, capability.ErrInvalidConfiguration) || !errors.Is(compatibilityErr, capability.ErrInvalidConfiguration) {
					t.Fatal("HTTP path inferred issuer from request")
				}
				continue
			}
			if canonicalErr != nil || compatibilityErr != nil {
				t.Fatal("ordinary HTTP configuration rejected")
			}
			for _, path := range []interface {
				VerifyRequest(*http.Request) (capability.Grant, error)
			}{canonical, compatibility} {
				grant, err := path.VerifyRequest(httptest.NewRequest("GET", signed, nil))
				wantSuccess := selected == "ordinary-issuer" && owner == selected
				if wantSuccess {
					if err != nil || grant.Payload().Issuer != selected {
						t.Fatal("HTTP path dropped selected issuer")
					}
				} else if !errors.Is(err, capability.ErrUnauthorized) || grant.Payload().ID != "" {
					t.Fatal("HTTP path accepted different issuer authority")
				}
			}
		}
	}
}

func TestSuccessorPreservesHTTPCompatibility(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := capability.NewHMACSHA256Signer("current", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: "https://issuer.example", ID: "current", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	profile := capability.URLProfile{
		Name:               "download-v1",
		SignatureParameter: "cap",
		AllowedSchemes:     []string{"https"},
		AllowedAuthorities: []string{"files.example"},
	}
	payload := capability.Payload{
		Version: 1, Issuer: "https://issuer.example", Audiences: []string{"download-service"},
		Bearer: true, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "cap-42",
	}
	signed, err := capability.SignURL(context.Background(), payload, capability.URLRequest{
		Method: http.MethodGet, RawURL: "https://files.example/report/42",
	}, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	options := capabilityhttp.VerifierOptions{Issuer: "https://issuer.example",
		Profile: profile, Resolver: resolver, Origin: "https://files.example",
		Clock: fixedClock{now: now}, Limits: capability.DefaultLimits(),
	}
	handler, err := capabilityhttp.NewVerifier(options)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	response := httptest.NewRecorder()
	handler.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		called = true
		if _, found := capabilityhttp.GrantFromContext(request.Context()); !found {
			t.Fatal("successor did not observe its context grant")
		}
		if _, found := legacy.GrantFromContext(request.Context()); !found {
			t.Fatal("compatibility path did not observe successor context grant")
		}
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, signed, nil))
	if !called || response.Code != http.StatusOK {
		t.Fatalf("middleware called = %t, status = %d", called, response.Code)
	}

	compatibilityOptions := legacy.VerifierOptions{Issuer: "https://issuer.example",
		Profile: profile, Resolver: resolver, Origin: "https://files.example",
		Clock: fixedClock{now: now}, Limits: capability.DefaultLimits(),
	}
	compatibilityVerifier, err := legacy.NewVerifier(compatibilityOptions)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(compatibilityOptions) == reflect.TypeOf(options) {
		t.Fatal("successor and compatibility option identities are not distinct")
	}
	if got := reflect.TypeOf(options).PkgPath(); got != "github.com/faustbrian/go-capability/v2/adapters/http" {
		t.Fatalf("VerifierOptions package identity = %q", got)
	}
	if got := reflect.TypeOf(compatibilityOptions).PkgPath(); got != "github.com/faustbrian/go-capability/v2/caphttp" {
		t.Fatalf("compatibility VerifierOptions package identity = %q", got)
	}
	if reflect.TypeOf(compatibilityVerifier) == reflect.TypeOf(handler) {
		t.Fatal("successor and compatibility verifier identities are not distinct")
	}
	if got := reflect.TypeOf(handler).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/v2/adapters/http" {
		t.Fatalf("Verifier package identity = %q", got)
	}
	if got := reflect.TypeOf(compatibilityVerifier).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/v2/caphttp" {
		t.Fatalf("compatibility Verifier package identity = %q", got)
	}
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }
