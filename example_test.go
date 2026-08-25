package capability_test

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-capability"
)

func ExampleIssue() {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("example-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	payload := capability.Payload{
		Version: 1, Issuer: "https://issuer.example",
		Audiences: []string{"download"}, Bearer: true,
		Resource: "reports/42", Operation: "download",
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute),
		ID: "example-capability",
	}
	token, _ := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "example-key", Verifier: verifier}})
	grant, _ := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{
		Now: now, Limits: capability.DefaultLimits(),
	})
	err := grant.Authorize(capability.Use{
		Audience: "download", Resource: "reports/42", Operation: "download",
	})
	fmt.Println(err == nil)
	// Output: true
}

func ExampleSignURL() {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	signer, _ := capability.NewHMACSHA256Signer(
		"example-key", []byte("0123456789abcdef0123456789abcdef"),
	)
	payload := capability.Payload{
		Version: 1, Issuer: "https://issuer.example",
		Audiences: []string{"download"}, Bearer: true,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute),
		ID: "example-url",
	}
	profile := capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes:     []string{"https"},
		AllowedAuthorities: []string{"files.example"},
		QueryParameters:    []string{"download"},
	}
	signed, _ := capability.SignURL(context.Background(), payload, capability.URLRequest{
		Method: "GET", RawURL: "https://files.example/report/42?download=1",
	}, profile, signer, capability.DefaultLimits())
	fmt.Println(len(signed) > len("https://files.example/report/42?download=1"))
	// Output: true
}
