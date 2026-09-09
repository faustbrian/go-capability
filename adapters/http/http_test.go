//nolint:staticcheck // Compatibility proof intentionally imports the deprecated path.
package capabilityhttp_test

//lint:file-ignore SA1019 Compatibility proof intentionally imports the deprecated path.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-capability/adapters/http"
	legacy "github.com/faustbrian/go-capability/caphttp"
)

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
	resolver, err := capability.NewKeySet([]capability.Key{{ID: "current", Verifier: verifier}})
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

	options := capabilityhttp.VerifierOptions{
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

	compatibilityOptions := legacy.VerifierOptions{
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
	if got := reflect.TypeOf(options).PkgPath(); got != "github.com/faustbrian/go-capability/adapters/http" {
		t.Fatalf("VerifierOptions package identity = %q", got)
	}
	if got := reflect.TypeOf(compatibilityOptions).PkgPath(); got != "github.com/faustbrian/go-capability/caphttp" {
		t.Fatalf("compatibility VerifierOptions package identity = %q", got)
	}
	if reflect.TypeOf(compatibilityVerifier) == reflect.TypeOf(handler) {
		t.Fatal("successor and compatibility verifier identities are not distinct")
	}
	if got := reflect.TypeOf(handler).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/adapters/http" {
		t.Fatalf("Verifier package identity = %q", got)
	}
	if got := reflect.TypeOf(compatibilityVerifier).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/caphttp" {
		t.Fatalf("compatibility Verifier package identity = %q", got)
	}
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }
