package identitycapability

import (
	"context"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

type issuanceOriginReader interface {
	ReadIssuanceOrigin(context.Context, *database.Pool, capability.Proof, capability.Purpose) (capability.Grant, identity.CommandID, uint32, error)
	ValidateIssuedProof(context.Context, *database.Pool, capability.Proof, capability.Purpose) (capability.Grant, identity.CommandID, uint32, error)
}

func TestIssuanceOriginRejectsMissingCompositionWithoutProjection(t *testing.T) {
	i, _, _, _ := issuerFixture(t)
	reader, ok := any(i).(issuanceOriginReader)
	if !ok {
		t.Fatal("issuer lacks purpose-explicit original issuance reader")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		for _, purpose := range []capability.Purpose{"", "identity.password.reset-complete", "bad\npurpose"} {
			for _, call := range []func(context.Context, *database.Pool, capability.Proof, capability.Purpose) (capability.Grant, identity.CommandID, uint32, error){reader.ReadIssuanceOrigin, reader.ValidateIssuedProof} {
				grant, command, version, err := call(ctx, nil, capability.Proof{}, purpose)
				if err == nil || grant.Payload().Version != 0 || command != "" || version != 0 {
					t.Fatal("invalid original reader retained projection")
				}
			}
		}
	}
	var zero *Issuer
	r := any(zero).(issuanceOriginReader)
	if grant, command, version, err := r.ValidateIssuedProof(context.Background(), nil, capability.Proof{}, "identity.password.reset-complete"); err == nil || grant.Payload().Version != 0 || command != "" || version != 0 {
		t.Fatal("zero issuer admitted proof")
	}
}
