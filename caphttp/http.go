// Package caphttp integrates verified signed-URL grants with net/http without
// hiding application authorization or bounded-use consumption.
package caphttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/faustbrian/go-capability"
)

// Clock supplies request-time wall clock values.
type Clock interface {
	Now() time.Time
}

// BodyDigest obtains an already computed SHA-256 digest. It must not consume a
// request body unless it also restores it for the application.
type BodyDigest func(*http.Request) ([]byte, error)

// ErrorHandler writes a secret-safe verification failure response.
type ErrorHandler func(http.ResponseWriter, *http.Request, error)

// VerifierOptions configures signed-URL verification for one immutable profile.
type VerifierOptions struct {
	Profile      capability.URLProfile
	Resolver     capability.Resolver
	Origin       string
	Clock        Clock
	Skew         time.Duration
	Limits       capability.Limits
	Revocations  capability.RevocationChecker
	BodyDigest   BodyDigest
	ErrorHandler ErrorHandler
}

// Verifier verifies request URLs and attaches authenticated grants to context.
type Verifier struct {
	profile      capability.URLProfile
	resolver     capability.Resolver
	origin       string
	clock        Clock
	skew         time.Duration
	limits       capability.Limits
	revocations  capability.RevocationChecker
	bodyDigest   BodyDigest
	errorHandler ErrorHandler
}

type grantContextKey struct{}

// NewVerifier validates an HTTP integration. Origin is trusted static external
// configuration for absolute profiles; request forwarding headers are ignored.
func NewVerifier(options VerifierOptions) (*Verifier, error) {
	if options.Resolver == nil || options.Clock == nil || options.Skew < 0 {
		return nil, capability.ErrInvalidConfiguration
	}
	if err := options.Profile.Validate(options.Limits); err != nil {
		return nil, err
	}
	if options.Profile.RequireBodyDigest != (options.BodyDigest != nil) {
		return nil, capability.ErrInvalidConfiguration
	}
	origin, err := validateOrigin(options.Origin, options.Profile)
	if err != nil {
		return nil, err
	}
	errorHandler := options.ErrorHandler
	if errorHandler == nil {
		errorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(writer, "invalid capability", http.StatusUnauthorized)
		}
	}
	return &Verifier{
		profile: options.Profile, resolver: options.Resolver, origin: origin,
		clock: options.Clock, skew: options.Skew, limits: options.Limits,
		revocations: options.Revocations, bodyDigest: options.BodyDigest,
		errorHandler: errorHandler,
	}, nil
}

// VerifyRequest verifies a request but does not authorize or consume its grant.
func (verifier *Verifier) VerifyRequest(request *http.Request) (capability.Grant, error) {
	if request == nil || request.URL == nil {
		return capability.Grant{}, capability.ErrInvalidConfiguration
	}
	digest := []byte(nil)
	if verifier.bodyDigest != nil {
		var err error
		digest, err = verifier.bodyDigest(request)
		if err != nil {
			return capability.Grant{}, redact(capability.ErrURLBinding, err)
		}
	}
	rawURL := request.URL.RequestURI()
	if verifier.origin != "" {
		rawURL = verifier.origin + rawURL
	}
	return capability.VerifyURL(request.Context(), capability.URLRequest{
		Method: request.Method, RawURL: rawURL, BodyDigest: digest,
	}, verifier.profile, verifier.resolver, capability.VerifyOptions{
		Now: verifier.clock.Now(), Skew: verifier.skew, Limits: verifier.limits,
		Revocations: verifier.revocations,
	})
}

type safeError struct {
	kind           error
	classification error
}

func (failure *safeError) Error() string { return failure.kind.Error() }

func (failure *safeError) Unwrap() []error {
	return []error{failure.kind, failure.classification}
}

func redact(kind, cause error) error {
	switch {
	case errors.Is(cause, context.Canceled):
		return &safeError{kind: kind, classification: context.Canceled}
	case errors.Is(cause, context.DeadlineExceeded):
		return &safeError{kind: kind, classification: context.DeadlineExceeded}
	default:
		return kind
	}
}

// Middleware verifies and carries a Grant. The next handler remains responsible
// for Grant.Authorize, Grant.Consume, and the protected side effect ordering.
func (verifier *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if next == nil {
			http.Error(writer, "capability handler unavailable", http.StatusInternalServerError)
			return
		}
		grant, err := verifier.VerifyRequest(request)
		if err != nil {
			verifier.errorHandler(writer, request, err)
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), grantContextKey{}, grant)))
	})
}

// GrantFromContext returns the verified grant carried by Middleware.
func GrantFromContext(ctx context.Context) (capability.Grant, bool) {
	if ctx == nil {
		return capability.Grant{}, false
	}
	grant, found := ctx.Value(grantContextKey{}).(capability.Grant)
	return grant, found
}

// SignRequest signs req.URL and mutates it only after complete successful issuance.
func SignRequest(
	ctx context.Context,
	request *http.Request,
	payload capability.Payload,
	profile capability.URLProfile,
	signer capability.Signer,
	limits capability.Limits,
	bodyDigest []byte,
) error {
	if request == nil || request.URL == nil {
		return capability.ErrInvalidConfiguration
	}
	signed, err := capability.SignURL(ctx, payload, capability.URLRequest{
		Method: request.Method, RawURL: request.URL.String(), BodyDigest: bodyDigest,
	}, profile, signer, limits)
	if err != nil {
		return err
	}
	parsed, _ := url.Parse(signed)
	request.URL = parsed
	return nil
}

func validateOrigin(raw string, profile capability.URLProfile) (string, error) {
	absoluteProfile := len(profile.AllowedSchemes) > 0
	if absoluteProfile != (raw != "") {
		return "", capability.ErrInvalidConfiguration
	}
	if raw == "" {
		return "", nil
	}
	origin, err := url.Parse(raw)
	if err != nil {
		return "", capability.ErrInvalidConfiguration
	}
	if !origin.IsAbs() {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.User != nil {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.Host == "" {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.Path != "" {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.RawQuery != "" {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.ForceQuery {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.Fragment != "" {
		return "", capability.ErrInvalidConfiguration
	}
	if raw != origin.Scheme+"://"+origin.Host {
		return "", capability.ErrInvalidConfiguration
	}
	if origin.Host != strings.ToLower(origin.Host) {
		return "", capability.ErrInvalidConfiguration
	}
	if !contains(profile.AllowedSchemes, origin.Scheme) {
		return "", capability.ErrInvalidConfiguration
	}
	if !contains(profile.AllowedAuthorities, origin.Host) {
		return "", capability.ErrInvalidConfiguration
	}
	return origin.String(), nil
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
