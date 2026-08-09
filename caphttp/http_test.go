package caphttp_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/golib/pkg/capability"
	"github.com/faustbrian/golib/pkg/capability/caphttp"
)

var now = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func TestMiddlewareVerifiesButLeavesAuthorizationVisible(t *testing.T) {
	profile, signer, resolver := fixture(t)
	signed := signedURL(t, profile, signer)
	verifier, err := caphttp.NewVerifier(caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example",
		Clock: fixedClock{}, Skew: time.Minute, Limits: capability.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	handler := verifier.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		grant, found := caphttp.GrantFromContext(request.Context())
		if !found {
			t.Fatal("GrantFromContext() found = false")
		}
		if err := grant.Authorize(capability.Use{
			Audience: "download", Resource: "https://files.example/report/42?download=1",
			Operation: "GET",
		}); err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, signed, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestMiddlewareComposesWithExplicitApplicationOrdering(t *testing.T) {
	profile, signer, resolver := fixture(t)
	profile.RequireBodyDigest = true
	body := []byte("body")
	digest := sha256.Sum256(body)
	payload := urlPayload()
	payload.Tenant = "tenant-a"
	payload.CorrelationID = "trace-a"
	signed, err := capability.SignURL(context.Background(), payload, capability.URLRequest{
		Method: http.MethodPost, RawURL: "https://files.example/report/42?download=1", BodyDigest: digest[:],
	}, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}

	type contextKey string
	const authenticated contextKey = "authenticated"
	var order []string
	verifier, err := caphttp.NewVerifier(caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example",
		Clock: fixedClock{}, Limits: capability.DefaultLimits(),
		BodyDigest: func(request *http.Request) ([]byte, error) {
			order = append(order, "capability")
			if request.Context().Value(authenticated) != true {
				t.Fatal("capability verification ran before authentication")
			}
			contents, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				return nil, readErr
			}
			request.Body = io.NopCloser(strings.NewReader(string(contents)))
			sum := sha256.Sum256(contents)
			return sum[:], nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	application := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		order = append(order, "authorization", "tenancy", "correlation", "audit", "application")
		grant, found := caphttp.GrantFromContext(request.Context())
		if !found {
			t.Fatal("GrantFromContext() found = false")
		}
		if err := grant.Authorize(capability.Use{
			Audience: "download", Resource: "https://files.example/report/42?download=1", Operation: http.MethodPost,
			Tenant: "tenant-a",
		}); err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		if grant.Payload().CorrelationID != "trace-a" || grant.Payload().Tenant != "tenant-a" {
			t.Fatal("application metadata changed during HTTP composition")
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	limited := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		order = append(order, "body-limit")
		request.Body = http.MaxBytesReader(writer, request.Body, int64(len(body)))
		verifier.Middleware(application).ServeHTTP(writer, request)
	})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		order = append(order, "authentication")
		limited.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), authenticated, true)))
	})

	request := httptest.NewRequest(http.MethodPost, signed, strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	want := "authentication,body-limit,capability,authorization,tenancy,correlation,audit,application"
	if got := strings.Join(order, ","); got != want {
		t.Fatalf("middleware order = %q, want %q", got, want)
	}
}

func TestMiddlewareRejectsBeforeCallingApplicationAndRedactsFailure(t *testing.T) {
	profile, _, resolver := fixture(t)
	verifier, _ := caphttp.NewVerifier(caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example",
		Clock: fixedClock{}, Limits: capability.DefaultLimits(),
	})
	called := false
	handler := verifier.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodGet, "https://files.example/report/42?cap=secret-looking-value&download=1", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if called || response.Code != http.StatusUnauthorized || response.Body.String() != "invalid capability\n" {
		t.Fatalf("called = %t, status = %d, body = %q", called, response.Code, response.Body.String())
	}
}

func TestSignRequestUsesExplicitClientMutationOnlyAfterSuccess(t *testing.T) {
	profile, signer, _ := fixture(t)
	request, _ := http.NewRequest(http.MethodGet, "https://files.example/report/42?download=1", nil)
	payload := urlPayload()
	if err := caphttp.SignRequest(context.Background(), request, payload, profile, signer, capability.DefaultLimits(), nil); err != nil {
		t.Fatalf("SignRequest() error = %v", err)
	}
	if request.URL.Query().Get("cap") == "" {
		t.Fatal("SignRequest() omitted capability")
	}
	original := request.URL.String()
	if err := caphttp.SignRequest(context.Background(), request, payload, profile, signer, capability.DefaultLimits(), nil); err == nil {
		t.Fatal("SignRequest(already signed) error = nil")
	}
	if request.URL.String() != original {
		t.Fatal("SignRequest() mutated request after failure")
	}
}

func TestVerifierConfigurationRequiresTrustedOriginAndClock(t *testing.T) {
	profile, _, resolver := fixture(t)
	for name, options := range map[string]caphttp.VerifierOptions{
		"clock":    {Profile: profile, Resolver: resolver, Origin: "https://files.example", Limits: capability.DefaultLimits()},
		"origin":   {Profile: profile, Resolver: resolver, Clock: fixedClock{}, Limits: capability.DefaultLimits()},
		"resolver": {Profile: profile, Origin: "https://files.example", Clock: fixedClock{}, Limits: capability.DefaultLimits()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := caphttp.NewVerifier(options); err == nil {
				t.Fatal("NewVerifier() error = nil")
			}
		})
	}
}

func TestVerifierBodyDigestCustomFailureAndBoundaryHelpers(t *testing.T) {
	profile, signer, resolver := fixture(t)
	profile.RequireBodyDigest = true
	digest := sha256.Sum256([]byte("body"))
	payload := urlPayload()
	signed, err := capability.SignURL(context.Background(), payload, capability.URLRequest{
		Method: http.MethodPost, RawURL: "https://files.example/report/42?download=1", BodyDigest: digest[:],
	}, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}
	verifier, err := caphttp.NewVerifier(caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example", Clock: fixedClock{},
		Limits: capability.DefaultLimits(), BodyDigest: func(*http.Request) ([]byte, error) { return digest[:], nil },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, signed, nil)
	if _, err := verifier.VerifyRequest(request); err != nil {
		t.Fatalf("VerifyRequest() error = %v", err)
	}
	bodyErr := errors.New("body unavailable")
	verifier, _ = caphttp.NewVerifier(caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example", Clock: fixedClock{},
		Limits: capability.DefaultLimits(), BodyDigest: func(*http.Request) ([]byte, error) { return nil, bodyErr },
	})
	if _, err := verifier.VerifyRequest(request); !errors.Is(err, capability.ErrURLBinding) || errors.Is(err, bodyErr) {
		t.Fatalf("VerifyRequest(body error) = %v", err)
	} else if strings.Contains(err.Error(), bodyErr.Error()) {
		t.Fatalf("VerifyRequest(body error) exposed diagnostic: %q", err)
	}
	for name, classification := range map[string]error{
		"canceled": context.Canceled, "deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			privateCause := fmt.Errorf("private body diagnostic: %w", classification)
			classified, classifiedErr := caphttp.NewVerifier(caphttp.VerifierOptions{
				Profile: profile, Resolver: resolver, Origin: "https://files.example", Clock: fixedClock{},
				Limits: capability.DefaultLimits(), BodyDigest: func(*http.Request) ([]byte, error) { return nil, privateCause },
			})
			if classifiedErr != nil {
				t.Fatalf("NewVerifier() error = %v", classifiedErr)
			}
			_, classifiedErr = classified.VerifyRequest(request)
			if !errors.Is(classifiedErr, capability.ErrURLBinding) || !errors.Is(classifiedErr, classification) ||
				errors.Is(classifiedErr, privateCause) || strings.Contains(classifiedErr.Error(), "private body") {
				t.Fatalf("VerifyRequest(classified body error) = %v", classifiedErr)
			}
		})
	}
	if _, err := verifier.VerifyRequest(nil); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("VerifyRequest(nil) error = %v", err)
	}
	var nilContext context.Context
	if grant, found := caphttp.GrantFromContext(nilContext); found {
		t.Fatalf("GrantFromContext(nil) = %#v, %t", grant, found)
	}
	if _, found := caphttp.GrantFromContext(context.Background()); found {
		t.Fatal("GrantFromContext(empty) found = true")
	}
}

func TestMiddlewareCustomErrorNilHandlerAndSigningValidation(t *testing.T) {
	profile, signer, resolver := fixture(t)
	customCalled := false
	verifier, err := caphttp.NewVerifier(caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example", Clock: fixedClock{},
		Limits: capability.DefaultLimits(), ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			customCalled = err != nil
			writer.WriteHeader(http.StatusForbidden)
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	response := httptest.NewRecorder()
	verifier.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		response, httptest.NewRequest(http.MethodGet, "https://files.example/report/42", nil),
	)
	if !customCalled || response.Code != http.StatusForbidden {
		t.Fatalf("customCalled = %t, status = %d", customCalled, response.Code)
	}
	response = httptest.NewRecorder()
	verifier.Middleware(nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://files.example/report/42", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("nil next status = %d", response.Code)
	}
	if err := caphttp.SignRequest(context.Background(), nil, urlPayload(), profile, signer, capability.DefaultLimits(), nil); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("SignRequest(nil) error = %v", err)
	}
}

func TestVerifierRejectsInvalidProfilesOriginsSkewAndDigestPairing(t *testing.T) {
	profile, _, resolver := fixture(t)
	valid := caphttp.VerifierOptions{
		Profile: profile, Resolver: resolver, Origin: "https://files.example", Clock: fixedClock{}, Limits: capability.DefaultLimits(),
	}
	tests := map[string]func(*caphttp.VerifierOptions){
		"negative skew":   func(options *caphttp.VerifierOptions) { options.Skew = -time.Second },
		"invalid profile": func(options *caphttp.VerifierOptions) { options.Profile.SignatureParameter = "" },
		"digest callback without profile": func(options *caphttp.VerifierOptions) {
			options.BodyDigest = func(*http.Request) ([]byte, error) { return nil, nil }
		},
		"missing digest callback": func(options *caphttp.VerifierOptions) { options.Profile.RequireBodyDigest = true },
		"trailing slash origin":   func(options *caphttp.VerifierOptions) { options.Origin += "/" },
		"wrong origin":            func(options *caphttp.VerifierOptions) { options.Origin = "https://other.example" },
		"uppercase origin":        func(options *caphttp.VerifierOptions) { options.Origin = "https://FILES.example" },
		"origin path":             func(options *caphttp.VerifierOptions) { options.Origin += "/proxy" },
		"malformed origin":        func(options *caphttp.VerifierOptions) { options.Origin = "%" },
		"relative origin":         func(options *caphttp.VerifierOptions) { options.Origin = "/relative" },
		"userinfo origin":         func(options *caphttp.VerifierOptions) { options.Origin = "https://user@files.example" },
		"missing host":            func(options *caphttp.VerifierOptions) { options.Origin = "https:" },
		"query origin":            func(options *caphttp.VerifierOptions) { options.Origin += "?a=1" },
		"empty query origin":      func(options *caphttp.VerifierOptions) { options.Origin += "?" },
		"fragment origin":         func(options *caphttp.VerifierOptions) { options.Origin += "#fragment" },
		"uppercase scheme":        func(options *caphttp.VerifierOptions) { options.Origin = "HTTPS://files.example" },
		"wrong scheme":            func(options *caphttp.VerifierOptions) { options.Origin = "http://files.example" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if _, err := caphttp.NewVerifier(options); err == nil {
				t.Fatal("NewVerifier() error = nil")
			}
		})
	}
	relative := valid
	relative.Profile = capability.URLProfile{Name: "relative", SignatureParameter: "cap", AllowRelative: true}
	relative.Origin = ""
	if _, err := caphttp.NewVerifier(relative); err != nil {
		t.Fatalf("NewVerifier(relative) error = %v", err)
	}
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return now }

func fixture(t *testing.T) (capability.URLProfile, capability.Signer, capability.Resolver) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("http-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	profile := capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
		QueryParameters: []string{"download"},
	}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	return profile, signer, resolver
}

func signedURL(t *testing.T, profile capability.URLProfile, signer capability.Signer) string {
	t.Helper()
	signed, err := capability.SignURL(context.Background(), urlPayload(), capability.URLRequest{
		Method: http.MethodGet, RawURL: "https://files.example/report/42?download=1",
	}, profile, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}
	return signed
}

func urlPayload() capability.Payload {
	return capability.Payload{
		Version: 1, Issuer: "https://issuer.example", Audiences: []string{"download"}, Bearer: true,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: fmt.Sprintf("http-%d", now.Unix()),
	}
}
