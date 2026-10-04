#!/usr/bin/env bash
set -euo pipefail

module_directory="$(cd "$(dirname "$0")/.." && pwd)"
consumer="$(mktemp -d "${TMPDIR:-/tmp}/capability-consumer.XXXXXX")"
cleanup() {
    find "${consumer}" -type f -delete
    find "${consumer}" -depth -type d -empty -delete
}
trap cleanup EXIT HUP INT TERM

# This is an owned-source rehearsal, not evidence that a public v2 release
# resolves. Keep generated module state and build cache disposable.
export GOCACHE="${consumer}/gocache"
export GOWORK=off
export GOMAXPROCS="${GOMAXPROCS:-2}"

cd "${consumer}"
GOWORK=off go mod init example.com/capability-consumer >/dev/null
GOWORK=off go mod edit -go=1.27.0 \
    -require=github.com/faustbrian/go-capability/v2@v2.0.0 \
    -replace="github.com/faustbrian/go-capability/v2=${module_directory}"

cat > consumer_test.go <<'EOF'
package consumer_test

import (
    "context"
    "errors"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-capability/v2/adapters/http"
	"github.com/faustbrian/go-capability/v2/adapters/memory"
    "github.com/faustbrian/go-capability/v2/caphttp"
    "github.com/faustbrian/go-capability/v2/memory"
    "github.com/faustbrian/go-capability/v2/postgres"
    "github.com/faustbrian/go-capability/v2/valkey"
)

var _ capability.ConsumptionStore = (*capabilitymemory.ConsumptionStore)(nil)
var _ capability.ConsumptionStore = (*memory.ConsumptionStore)(nil)
var _ capability.ConsumptionStore = (*postgres.ConsumptionStore)(nil)
var _ capability.ConsumptionStore = (*valkey.ConsumptionStore)(nil)
var _ = capabilityhttp.SignRequest
var _ = caphttp.SignRequest
var _ = postgres.MigrateLegacyConsumption

type fixedClock struct { now time.Time }
func (clock fixedClock) Now() time.Time { return clock.now }

func TestIssueVerifyAuthorize(t *testing.T) {
    now := time.Unix(1_786_276_800, 0).UTC()
    key := make([]byte, 32)
    signer, err := capability.NewHMACSHA256Signer("consumer-key", key)
    if err != nil {
        t.Fatal(err)
    }
    verifier, err := capability.NewHMACSHA256Verifier(key)
    if err != nil {
        t.Fatal(err)
    }
    token, err := capability.Issue(context.Background(), capability.Payload{
        Version: 1, Issuer: "consumer", Audiences: []string{"download"}, Bearer: true,
        Resource: "reports/42", Operation: "download", IssuedAt: now,
        NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "consumer-capability", MaxUses: 1,
    }, signer, capability.DefaultLimits())
    if err != nil {
        t.Fatal(err)
    }
    keys, err := capability.NewKeySet([]capability.Key{{Issuer: "consumer", ID: "consumer-key", Verifier: verifier}})
    if err != nil {
        t.Fatal(err)
    }
    grant, err := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{
        Issuer: "consumer", Now: now, Limits: capability.DefaultLimits(),
    })
    if err != nil {
        t.Fatal(err)
    }
    if err := grant.Authorize(capability.Use{
        Issuer: "consumer", Audience: "download", Resource: "reports/42", Operation: "download",
    }); err != nil {
        t.Fatal(err)
    }
    canonical, err := capabilitymemory.NewConsumptionStore(fixedClock{now: now})
    if err != nil { t.Fatal(err) }
    compatibility, err := memory.NewConsumptionStoreWithLimits(fixedClock{now: now}, memory.StoreLimits{MaxRecords: 1, MaxStringBytes: 64})
    if err != nil { t.Fatal(err) }
    for _, store := range []capability.ConsumptionStore{canonical, compatibility} {
        result, err := grant.Consume(context.Background(), store)
        if err != nil || result.Use != 1 || result.Remaining != 0 { t.Fatal("ordinary consumer accounting failed") }
    }
}

func TestHTTPUseOnceConsumesBeforeBusinessAction(t *testing.T) {
    ctx := context.Background()
    now := time.Unix(1_786_276_800, 0).UTC()
    key := make([]byte, 32)
    signer, err := capability.NewHMACSHA256Signer("consumer-key", key)
    if err != nil { t.Fatal(err) }
    signatureVerifier, err := capability.NewHMACSHA256Verifier(key)
    if err != nil { t.Fatal(err) }
    keys, err := capability.NewKeySet([]capability.Key{{Issuer: "consumer", ID: "consumer-key", Verifier: signatureVerifier}})
    if err != nil { t.Fatal(err) }
    profile := capability.URLProfile{Name: "download-v1", SignatureParameter: "cap", AllowedSchemes: []string{"https"}, AllowedAuthorities: []string{"files.example"}}
    signed, err := capability.SignURL(ctx, capability.Payload{
        Version: 1, Issuer: "consumer", Audiences: []string{"download"}, Bearer: true,
        IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "http-use-once", MaxUses: 1,
    }, capability.URLRequest{Method: http.MethodGet, RawURL: "https://files.example/report/42"}, profile, signer, capability.DefaultLimits())
    if err != nil { t.Fatal(err) }
    verifier, err := capabilityhttp.NewVerifier(capabilityhttp.VerifierOptions{Issuer: "consumer", Profile: profile, Resolver: keys, Origin: "https://files.example", Clock: fixedClock{now: now}, Limits: capability.DefaultLimits()})
    if err != nil { t.Fatal(err) }
    store, err := capabilitymemory.NewConsumptionStoreWithLimits(fixedClock{now: now}, capabilitymemory.StoreLimits{MaxRecords: 1, MaxStringBytes: 64})
    if err != nil { t.Fatal(err) }
    businessCalls := 0
    var consumeErr error
    var result capability.ConsumptionResult
    handler := verifier.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
        grant, found := capabilityhttp.GrantFromContext(request.Context())
        if !found { t.Fatal("verified grant missing") }
        if err := grant.Authorize(capability.Use{Issuer: "consumer", Audience: "download", Resource: "https://files.example/report/42", Operation: http.MethodGet}); err != nil { t.Fatal("ordinary authorization failed") }
        result, consumeErr = grant.Consume(request.Context(), store)
        if consumeErr != nil { http.Error(writer, "use refused", http.StatusForbidden); return }
        businessCalls++
        writer.WriteHeader(http.StatusNoContent)
    }))
    first := httptest.NewRecorder()
    handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, signed, nil))
    if first.Code != http.StatusNoContent || businessCalls != 1 || consumeErr != nil || result.Use != 1 { t.Fatal("first ordinary HTTP use did not consume before business action") }
    second := httptest.NewRecorder()
    handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, signed, nil))
    if second.Code != http.StatusForbidden || businessCalls != 1 || !errors.Is(consumeErr, capability.ErrReplayExhausted) || result != (capability.ConsumptionResult{}) { t.Fatal("repeated valid HTTP grant reached business action") }
}
EOF

GOWORK=off go test -p 1 -count=1 ./...
