// Package caphttp is the compatibility facade for the target-oriented HTTP
// adapter.
//
// Deprecated: use github.com/faustbrian/go-capability/adapters/http. This
// package remains supported through the documented compatibility interval.
package caphttp

import (
	"context"
	"net/http"
	"time"

	"github.com/faustbrian/go-capability"
	capabilityhttp "github.com/faustbrian/go-capability/adapters/http"
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

// Verifier preserves the released compatibility-path type identity while
// delegating all behavior to the canonical adapter.
type Verifier struct {
	canonical *capabilityhttp.Verifier
}

// NewVerifier validates an HTTP integration.
func NewVerifier(options VerifierOptions) (*Verifier, error) {
	verifier, err := capabilityhttp.NewVerifier(capabilityhttp.VerifierOptions{
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

// VerifyRequest verifies a request but does not authorize or consume its grant.
func (verifier *Verifier) VerifyRequest(request *http.Request) (capability.Grant, error) {
	return verifier.canonical.VerifyRequest(request)
}

// Middleware verifies and carries a Grant. The next handler remains responsible
// for authorization, consumption, and protected side-effect ordering.
func (verifier *Verifier) Middleware(next http.Handler) http.Handler {
	return verifier.canonical.Middleware(next)
}

// GrantFromContext returns the verified grant carried by Middleware.
func GrantFromContext(ctx context.Context) (capability.Grant, bool) {
	return capabilityhttp.GrantFromContext(ctx)
}

// SignRequest signs request.URL after complete successful issuance.
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
