package capability_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-capability/v2/adapters/memory"
)

// BenchmarkIssueHMACSHA256 measures canonical payload/header encoding and
// deterministic signing of validPayload; key construction is outside timing.
func BenchmarkIssueHMACSHA256(b *testing.B) {
	signer, _ := capability.NewHMACSHA256Signer(
		"benchmark-key", []byte("0123456789abcdef0123456789abcdef"),
	)
	payload := validPayload()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	}
}

// BenchmarkVerifyHMACSHA256 excludes issuance/key setup and verifies one fixed
// token with an in-process resolver, fixed time and no revocation/consumption.
func BenchmarkVerifyHMACSHA256(b *testing.B) {
	token, verifier := hmacFixture(b)
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: "https://issuer.example", Verifier: verifier}, nil
	})
	options := capability.VerifyOptions{Issuer: "https://issuer.example", Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = capability.Verify(context.Background(), token, resolver, options)
	}
}

// BenchmarkSignURLHMACSHA256 measures GET signing of one absolute download URL
// with one query field; signer/profile/payload setup is excluded.
func BenchmarkSignURLHMACSHA256(b *testing.B) {
	signer, _ := capability.NewHMACSHA256Signer(
		"benchmark-key", []byte("0123456789abcdef0123456789abcdef"),
	)
	payload := validPayload()
	payload.Resource = ""
	payload.Operation = ""
	profile := benchmarkURLProfile()
	request := capability.URLRequest{Method: http.MethodGet, RawURL: "https://files.example/report/42?download=1"}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = capability.SignURL(context.Background(), payload, request, profile, signer, capability.DefaultLimits())
	}
}

// BenchmarkVerifyURLHMACSHA256 excludes signing/key setup and verifies a fixed
// canonical GET URL with a local resolver, no body digest or external service.
func BenchmarkVerifyURLHMACSHA256(b *testing.B) {
	signer, _ := capability.NewHMACSHA256Signer(
		"benchmark-key", []byte("0123456789abcdef0123456789abcdef"),
	)
	verifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	payload := validPayload()
	payload.Resource = ""
	payload.Operation = ""
	profile := benchmarkURLProfile()
	signed, _ := capability.SignURL(context.Background(), payload, capability.URLRequest{
		Method: http.MethodGet, RawURL: "https://files.example/report/42?download=1",
	}, profile, signer, capability.DefaultLimits())
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: "https://issuer.example", Verifier: verifier}, nil
	})
	options := capability.VerifyOptions{Issuer: "https://issuer.example", Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = capability.VerifyURL(context.Background(), capability.URLRequest{
			Method: http.MethodGet, RawURL: signed,
		}, profile, resolver, options)
	}
}

// BenchmarkMemoryConsume repeatedly increments one live tuple under one lock;
// clock/store setup is excluded. First admission differs from hot repeats and
// eventual exhaustion; this is not durable-store throughput or contention proof.
func BenchmarkMemoryConsume(b *testing.B) {
	clock := benchmarkClock{now: testNow}
	store, _ := capabilitymemory.NewConsumptionStore(clock)
	request := capability.Consumption{Issuer: "ordinary-issuer", CapabilityID: "benchmark", ExpiresAt: testNow.Add(time.Hour), MaxUses: ^uint32(0)}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = store.Consume(context.Background(), request)
	}
}

// BenchmarkMemoryRevocationCheck measures negative reads of an empty set with
// one fixed query. Construction is excluded; it does not measure populated hits.
func BenchmarkMemoryRevocationCheck(b *testing.B) {
	store := capabilitymemory.NewRevocations()
	query := capability.RevocationQuery{Issuer: "issuer", CapabilityID: "capability", IssuedAt: testNow}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = store.Check(context.Background(), query)
	}
}

// BenchmarkMemoryRevokeCapability measures repeated identical writes after
// initial admission, not unique-key capacity growth. Store setup is excluded.
func BenchmarkMemoryRevokeCapability(b *testing.B) {
	store := capabilitymemory.NewRevocations()
	b.ReportAllocs()
	for b.Loop() {
		_ = store.RevokeCapability(context.Background(), "issuer", "capability")
	}
}

func benchmarkURLProfile() capability.URLProfile {
	return capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
		QueryParameters: []string{"download"},
	}
}

type benchmarkClock struct{ now time.Time }

func (clock benchmarkClock) Now() time.Time { return clock.now }
