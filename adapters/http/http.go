// Package capabilityhttp integrates verified signed-URL grants with net/http
// without hiding application authorization or bounded-use consumption. Start
// with NewVerifier and trusted static Origin/Issuer; SignRequest only mutates
// an explicitly supplied outgoing URL. It owns no server/client/body lifecycle
// or worker. Profiles and callbacks stay borrowed and immutable; shared use
// requires cooperative concurrent-safe collaborators. The local signed-URL
// policy is DEC-006/007/011, not HTTP Message Signatures or automatic effects.
package capabilityhttp

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-capability/v2"
)

// Clock supplies request-time wall clock values.
type Clock interface {
	// Now supplies trusted wall time, concurrently and promptly without reading
	// untrusted request fields.
	Now() time.Time
}

// BodyDigest obtains an already computed SHA-256 digest. It must not consume a
// request body unless it also restores it for the application. Bound untrusted
// pre-authentication work, honor request context and support concurrent calls.
// Returned digest is borrowed for that call; panics are not contained.
type BodyDigest func(*http.Request) ([]byte, error)

// ErrorHandler owns synchronous failure rendering/redaction. It may run
// concurrently; bound work and never expose tokens or underlying diagnostics.
// Handler panics are not contained; nil configuration selects fixed 401 text.
type ErrorHandler func(http.ResponseWriter, *http.Request, error)

// VerifierOptions configures signed-URL verification for one immutable profile.
type VerifierOptions struct {
	// Issuer is the required trusted namespace, never inferred from the request.
	Issuer string
	// Profile is validated by value, but its slice storage remains borrowed and immutable
	// for verifier lifetime.
	Profile capability.URLProfile
	// Resolver is mandatory borrowed trusted issuer/key policy; shared use must be
	// concurrency-safe.
	Resolver capability.Resolver
	// Origin is trusted static scheme/authority required for absolute profiles, never
	// request Host or forwarding data.
	Origin string
	// Clock is mandatory borrowed safe wall clock; callbacks must return promptly and
	// support concurrent use.
	Clock Clock
	// Skew is nonnegative payload time tolerance, not an HTTP deadline.
	Skew time.Duration
	// Limits is explicit positive parser policy, copied by value.
	Limits capability.Limits
	// Revocations is optional borrowed post-authentication policy; nil disables revocation.
	Revocations capability.RevocationChecker
	// BodyDigest must be present exactly when required; bound pre-authentication work and
	// restore consumed bodies.
	BodyDigest BodyDigest
	// ErrorHandler is optional synchronous failure reporting; nil selects fixed 401 text,
	// custom handlers own redaction.
	ErrorHandler ErrorHandler
}

// Verifier verifies request URLs and carries grants. Construct with NewVerifier;
// zero is unusable. Shared use requires immutable profile slices and safe
// clock/resolver/digest/error callbacks; they can block or panic synchronously.
type Verifier struct {
	issuer       string
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
// configuration for absolute profiles; request host/forwarding headers are ignored.
// Profile slices and callbacks stay borrowed for lifetime, not defensively
// cloned. Failure returns nil; nil interfaces reject, typed nil is not detected.
func NewVerifier(options VerifierOptions) (*Verifier, error) {
	if options.Issuer == "" || len(options.Issuer) > options.Limits.MaxFieldBytes || !utf8.ValidString(options.Issuer) {
		return nil, capability.ErrInvalidConfiguration
	}
	for _, character := range options.Issuer {
		if character < 0x20 || character == 0x7f {
			return nil, capability.ErrInvalidConfiguration
		}
	}
	switch options.Resolver {
	case nil:
		return nil, capability.ErrInvalidConfiguration
	}
	switch options.Clock {
	case nil:
		return nil, capability.ErrInvalidConfiguration
	}
	if cmp.Less(options.Skew, time.Duration(0)) {
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
		issuer:  options.Issuer,
		profile: options.Profile, resolver: options.Resolver, origin: origin,
		clock: options.Clock, skew: options.Skew, limits: options.Limits,
		revocations: options.Revocations, bodyDigest: options.BodyDigest,
		errorHandler: errorHandler,
	}, nil
}

// VerifyRequest verifies a request but does not authorize or consume its grant.
// Nil request/URL refuses. BodyDigest runs before authentication; the caller
// must bound untrusted reads and restore bytes for later handlers. Digest errors
// are sanitized to ErrURLBinding/context categories; no panic or forced timeout
// boundary is added. Only selected static origin plus RequestURI is trusted.
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
		Issuer: verifier.issuer,
		Now:    verifier.clock.Now(), Skew: verifier.skew, Limits: verifier.limits,
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
// Nil next produces a fixed 500; verification failure invokes ErrorHandler.
// Custom handler redaction/panics and downstream effects remain caller-owned.
// It creates no worker and carries the same grant visible through caphttp.
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

// GrantFromContext returns the middleware Grant or zero/false for nil/absent
// context. Presence is authentication attribution, not authorization or use count.
func GrantFromContext(ctx context.Context) (capability.Grant, bool) {
	if ctx == nil {
		return capability.Grant{}, false
	}
	grant, found := ctx.Value(grantContextKey{}).(capability.Grant)
	return grant, found
}

// SignRequest signs request.URL and replaces it only after successful issuance.
// Caller owns exclusive URL mutation and supplies already computed body digest.
// No body read, HTTP send, header rewriting or rollback of signer effects occurs.
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
