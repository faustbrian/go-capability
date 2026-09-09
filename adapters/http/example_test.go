package capabilityhttp_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-capability/adapters/http"
)

func ExampleSignRequest() {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	signer, _ := capability.NewHMACSHA256Signer(
		"current", []byte("0123456789abcdef0123456789abcdef"),
	)
	request, _ := http.NewRequest(http.MethodGet, "https://files.example/report/42", nil)
	profile := capability.URLProfile{
		Name: "download-v1", SignatureParameter: "cap",
		AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"},
	}
	payload := capability.Payload{
		Version: 1, Issuer: "https://issuer.example", Audiences: []string{"download-service"},
		Bearer: true, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "cap-42",
	}
	err := capabilityhttp.SignRequest(
		context.Background(), request, payload, profile, signer, capability.DefaultLimits(), nil,
	)
	fmt.Println(err == nil, strings.HasPrefix(request.URL.RawQuery, "cap="))
	// Output: true true
}
