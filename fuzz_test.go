package capability_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

func FuzzParseNeverAcceptsTwoPayloadRepresentations(f *testing.F) {
	canonical, err := capability.CanonicalPayload(validPayload(), capability.DefaultLimits())
	if err != nil {
		f.Fatalf("CanonicalPayload() error = %v", err)
	}
	for _, seed := range [][]byte{canonical, {}, {0xff}, []byte(`{}`), append(append([]byte(nil), canonical...), '\n')} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > capability.DefaultLimits().MaxTokenBytes+1 {
			return
		}
		payload, err := capability.ParsePayload(input, capability.DefaultLimits())
		if err != nil {
			return
		}
		reencoded, err := capability.CanonicalPayload(payload, capability.DefaultLimits())
		if err != nil {
			t.Fatalf("accepted payload cannot be encoded: %v", err)
		}
		if !bytes.Equal(input, reencoded) {
			t.Fatalf("accepted non-canonical payload: %q != %q", input, reencoded)
		}
	})
}

func FuzzSignedURLRoundTripIsDeterministic(f *testing.F) {
	for _, seed := range []string{
		"https://files.example/report/42?download=1",
		"https://FILES.example:443/%E2%82%AC?download=",
		"/relative?download=1",
		"https://files.example/a/../b?download=1&download=2#fragment",
	} {
		f.Add(seed)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("fuzz-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	})
	profile := capability.URLProfile{
		Name: "fuzz-v1", SignatureParameter: "cap", AllowRelative: true,
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
		QueryParameters: []string{"download"},
	}
	f.Fuzz(func(t *testing.T, rawURL string) {
		if len(rawURL) > 4096 {
			return
		}
		payload := validPayload()
		payload.Resource = ""
		payload.Operation = ""
		signed, err := capability.SignURL(context.Background(), payload, capability.URLRequest{
			Method: "GET", RawURL: rawURL,
		}, profile, signer, capability.DefaultLimits())
		if err != nil {
			return
		}
		grant, err := capability.VerifyURL(context.Background(), capability.URLRequest{
			Method: "GET", RawURL: signed,
		}, profile, resolver, capability.VerifyOptions{
			Now: testNow, Skew: time.Minute, Limits: capability.DefaultLimits(),
		})
		if err != nil {
			t.Fatalf("signed URL was not verifiable: %v", err)
		}
		payload.Resource = ""
		payload.Operation = ""
		resigned, err := capability.SignURL(context.Background(), payload, capability.URLRequest{
			Method: "GET", RawURL: grant.Payload().Resource,
		}, profile, signer, capability.DefaultLimits())
		if err != nil || resigned == "" {
			t.Fatalf("canonical resource could not be re-signed: %q, %v", resigned, err)
		}
	})
}

func FuzzParseTokenIsBounded(f *testing.F) {
	token, _ := hmacFixtureForFuzz(f)
	for _, seed := range []string{token, "", "cap1....", "cap1.e30.e30.c2ln", string([]byte{0xff})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > capability.DefaultLimits().MaxTokenBytes+1 {
			return
		}
		_, _ = capability.Parse(input, capability.DefaultLimits())
	})
}

func hmacFixtureForFuzz(f *testing.F) (string, capability.Verifier) {
	f.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	token, err := capability.Issue(f.Context(), validPayload(), signer, capability.DefaultLimits())
	if err != nil {
		f.Fatalf("Issue() error = %v", err)
	}
	return token, verifier
}
