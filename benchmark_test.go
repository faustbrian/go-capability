package capability_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-capability/memory"
)

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

func BenchmarkVerifyHMACSHA256(b *testing.B) {
	token, verifier := hmacFixture(b)
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = capability.Verify(context.Background(), token, resolver, options)
	}
}

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
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	options := capability.VerifyOptions{Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits()}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = capability.VerifyURL(context.Background(), capability.URLRequest{
			Method: http.MethodGet, RawURL: signed,
		}, profile, resolver, options)
	}
}

func BenchmarkMemoryConsume(b *testing.B) {
	clock := benchmarkClock{now: testNow}
	store, _ := memory.NewConsumptionStore(clock)
	request := capability.Consumption{CapabilityID: "benchmark", ExpiresAt: testNow.Add(time.Hour), MaxUses: ^uint32(0)}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = store.Consume(context.Background(), request)
	}
}

func BenchmarkMemoryRevocationCheck(b *testing.B) {
	store := memory.NewRevocations()
	query := capability.RevocationQuery{Issuer: "issuer", CapabilityID: "capability", IssuedAt: testNow}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = store.Check(context.Background(), query)
	}
}

func BenchmarkMemoryRevokeCapability(b *testing.B) {
	store := memory.NewRevocations()
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
