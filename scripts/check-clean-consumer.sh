#!/usr/bin/env bash
set -euo pipefail

module_directory="$(cd "$(dirname "$0")/.." && pwd)"
consumer="$(mktemp -d "${TMPDIR:-/tmp}/capability-consumer.XXXXXX")"
cleanup() {
    chmod -R u+w "${consumer}" 2>/dev/null || true
    rm -rf -- "${consumer}"
}
trap cleanup EXIT HUP INT TERM

cd "${consumer}"
GOWORK=off go mod init example.com/capability-consumer >/dev/null
GOWORK=off go mod edit -go=1.26.6 \
    -require=github.com/faustbrian/golib/pkg/capability@v0.0.0 \
    -replace="github.com/faustbrian/golib/pkg/capability=${module_directory}"

cat > consumer_test.go <<'EOF'
package consumer_test

import (
    "context"
    "testing"
    "time"

    "github.com/faustbrian/golib/pkg/capability"
    "github.com/faustbrian/golib/pkg/capability/caphttp"
    "github.com/faustbrian/golib/pkg/capability/memory"
    "github.com/faustbrian/golib/pkg/capability/postgres"
    "github.com/faustbrian/golib/pkg/capability/valkey"
)

var _ capability.ConsumptionStore = (*memory.ConsumptionStore)(nil)
var _ capability.ConsumptionStore = (*postgres.ConsumptionStore)(nil)
var _ capability.ConsumptionStore = (*valkey.ConsumptionStore)(nil)
var _ = caphttp.SignRequest

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
        NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "consumer-capability",
    }, signer, capability.DefaultLimits())
    if err != nil {
        t.Fatal(err)
    }
    keys, err := capability.NewKeySet([]capability.Key{{ID: "consumer-key", Verifier: verifier}})
    if err != nil {
        t.Fatal(err)
    }
    grant, err := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{
        Now: now, Limits: capability.DefaultLimits(),
    })
    if err != nil {
        t.Fatal(err)
    }
    if err := grant.Authorize(capability.Use{
        Audience: "download", Resource: "reports/42", Operation: "download",
    }); err != nil {
        t.Fatal(err)
    }
}
EOF

GOWORK=off go test ./...
