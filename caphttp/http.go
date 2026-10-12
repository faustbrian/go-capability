// Package caphttp is the compatibility facade for the target-oriented HTTP
// adapter. Start with NewVerifier; policy/clock/callback ownership and failure
// behavior are delegated to adapters/http. Instances own no server, client,
// worker or body lifecycle; shared use requires safe borrowed collaborators.
//
// Deprecated: use github.com/faustbrian/go-capability/v2/adapters/http. This
// package remains supported through the documented compatibility interval.
package caphttp

import (
	"context"
	"net/http"
	"time"

	"github.com/faustbrian/go-capability/v2"
	capabilityhttp "github.com/faustbrian/go-capability/v2/adapters/http"
)

// Clock supplies request-time wall clock values.
type Clock interface {
	// Now supplies trusted wall time, concurrently and promptly without reading
	// untrusted request fields.
	Now() time.Time
}

// BodyDigest obtains an already computed SHA-256 digest. It must not consume a
// request body unless it also restores it for the application. Bound untrusted
// pre-authentication work and support concurrent calls. No core callback timeout
// or panic containment is provided.
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

// Verifier preserves the released compatibility-path type identity while
// delegating all behavior to the canonical adapter. Zero is unusable; shared
// use requires immutable borrowed profile storage and safe callbacks.
type Verifier struct {
	canonical *capabilityhttp.Verifier
}

// NewVerifier validates and delegates to adapters/http, returning nil on error.
// Profile slice storage and callbacks remain borrowed; trusted Origin/Issuer
// are static configuration, never inferred from incoming forwarding fields.
func NewVerifier(options VerifierOptions) (*Verifier, error) {
	verifier, err := capabilityhttp.NewVerifier(capabilityhttp.VerifierOptions{
		Issuer:  options.Issuer,
		Profile: options.Profile, Resolver: options.Resolver, Origin: options.Origin,
		Clock: options.Clock, Skew: options.Skew, Limits: options.Limits,
		Revocations: options.Revocations, BodyDigest: capabilityhttp.BodyDigest(options.BodyDigest),
		ErrorHandler: capabilityhttp.ErrorHandler(options.ErrorHandler),
	})
	if err != nil {
		return nil, err
	}
	return &Verifier{canonical: verifier}, nil
}

// VerifyRequest delegates authentication without Authorize/Consume. The
// canonical body-digest callback runs before authentication and must bound
// untrusted work/restore reads; callback blocking/panics remain caller-owned.
func (verifier *Verifier) VerifyRequest(request *http.Request) (capability.Grant, error) {
	return verifier.canonical.VerifyRequest(request)
}

// Middleware verifies and carries a Grant. The next handler remains responsible
// for authorization, consumption, and protected side-effect ordering. Nil next
// receives fixed 500; custom failure redaction remains caller-owned. The carried
// grant is also visible through adapters/http.GrantFromContext.
func (verifier *Verifier) Middleware(next http.Handler) http.Handler {
	return verifier.canonical.Middleware(next)
}

// GrantFromContext returns the middleware Grant or zero/false for nil/absent
// context. Presence is authentication attribution, not authorization or use count.
func GrantFromContext(ctx context.Context) (capability.Grant, bool) {
	return capabilityhttp.GrantFromContext(ctx)
}

// SignRequest delegates explicit exclusive URL mutation after successful
// issuance. It does not read/send bodies or own HTTP client/redirect policy.
func SignRequest(
	ctx context.Context,
	request *http.Request,
	payload capability.Payload,
	profile capability.URLProfile,
	signer capability.Signer,
	limits capability.Limits,
	bodyDigest []byte,
) error {
	return capabilityhttp.SignRequest(ctx, request, payload, profile, signer, limits, bodyDigest)
}
