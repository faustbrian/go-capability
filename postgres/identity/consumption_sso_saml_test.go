package identitycapability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestPrepareSSOSAMLSigninConsumptionPreservesOnlyOriginalGrant(t *testing.T) {
	issuer, _, b, payload := ssoOAuth2IssuerFixture(t)
	sibling, siblingPayload := b, payload
	b.OperationID, b.SchemaID = "identity.sso.saml-start", "identity.sso.saml-start.v1"
	payload.Operation, payload.ExpiresAt = "identity.sso.saml-acs", payload.IssuedAt.Add(5*time.Minute)
	ctx := context.Background()
	prepared, err := issuer.Prepare(ctx, b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("issue an original SAML grant", err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(ctx, func(context.Context, []byte) error { return nil }) })
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	want := plan.Grants[0]
	for range 2 {
		got, err := issuer.PrepareSSOSAMLSigninConsumption(ctx, b, proof, want.ReplayKeyVersion)
		if err != nil || got != want || got.Purpose != "identity.sso.saml-acs" || got.MaxUses != 1 {
			t.Fatal("original SAML grant and replay scope changed", err)
		}
	}
	other, err := issuer.Prepare(ctx, sibling, []capability.Payload{siblingPayload})
	if err != nil {
		t.Fatal("keep the sibling proof valid for its own operation", err)
	}
	foreignProof := other.state.proofs[0]
	t.Cleanup(func() { _ = foreignProof.Transfer(ctx, func(context.Context, []byte) error { return nil }) })
	if got, err := issuer.PrepareSSOSAMLSigninConsumption(ctx, b, foreignProof, want.ReplayKeyVersion); !errors.Is(err, identity.ForbiddenError{}) || got != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("foreign signed OAuth purpose selected the SAML consume profile", err)
	}
	var invalid identity.InvalidInputError
	if got, err := issuer.PrepareSSOSAMLSigninConsumption(ctx, sibling, proof, want.ReplayKeyVersion); !errors.As(err, &invalid) || got != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("an OAuth start bound the SAML proof", err)
	}
	for _, alter := range []func(*identity.CommandBinding){
		func(a *identity.CommandBinding) { a.AnonymousFlowID += "-different" },
		func(a *identity.CommandBinding) { a.TenantID = "foreign-tenant" },
		func(a *identity.CommandBinding) { a.CorrelationID = "foreign-correlation" },
	} {
		other := b
		alter(&other)
		if got, err := issuer.PrepareSSOSAMLSigninConsumption(ctx, other, proof, want.ReplayKeyVersion); err == nil || got != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("foreign original binding acquired a preparation plan")
		}
	}
	issuer.clock = func() time.Time { return payload.ExpiresAt }
	if got, err := issuer.PrepareSSOSAMLSigninConsumption(ctx, b, proof, want.ReplayKeyVersion); !errors.Is(err, identity.ForbiddenError{}) || got != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("the original SAML grant remained available at exact expiry", err)
	}
}
