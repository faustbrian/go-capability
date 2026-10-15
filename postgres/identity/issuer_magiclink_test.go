package identitycapability

import (
	"bytes"
	"context"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func magicLinkIssuerBinding(b identity.CommandBinding) identity.CommandBinding {
	b = registrationIssuerBinding(b)
	b.OperationID, b.SchemaID = "identity.magic-link.request", "magic-link-request"
	return b
}

func TestMagicLinkIssuerPreservesAnonymousOriginAndEncryptedCustody(t *testing.T) {
	i, config, binding, payload := issuerFixture(t)
	b := magicLinkIssuerBinding(binding)
	payload.Subject, payload.Operation = "existing-user", "identity.magic-link.consume"
	p, err := i.PrepareMagicLinkRecipient(context.Background(), b, "existing-user", payload)
	if err != nil {
		t.Fatal("magic-link recipient denied", err)
	}
	plan, err := p.Plan()
	if err != nil || plan.MagicLinkRecipientUserID != "existing-user" || plan.ResetRecipientUserID != "" || plan.RegistrationUserID != "" || p.state.binding != b || len(plan.Grants) != 1 {
		t.Fatal("magic-link selection changed anonymous origin", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("magic-link declaration rejected", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil {
		t.Fatal("original encrypted custody failed", err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b {
		t.Fatal("anonymous origin lost", err)
	}
	grant := restored.state.grants[0]
	if grant.Payload().Subject != "existing-user" || grant.Payload().Operation != payload.Operation || grant.EnvelopeDigest() != plan.Grants[0].ProofFingerprint {
		t.Fatal("restore reissued or retargeted grant")
	}
	again, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("retry replaced original ciphertext", err)
	}
	for _, change := range []func(*identitypostgres.CapabilityIssuancePlan){
		func(p *identitypostgres.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = "foreign" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = "" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = p.MagicLinkRecipientUserID },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = p.MagicLinkRecipientUserID },
		func(p *identitypostgres.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.password.reset-complete"
		},
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
	} {
		changed := plan
		changed.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
		change(&changed)
		if out, err := codec.RestorePreparation(context.Background(), b, 7, changed, wire); err == nil || out.state != nil {
			t.Fatal("foreign magic-link declaration restored")
		}
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("restored bearer revealed"); return nil }) == nil {
		t.Fatal("restore renewed disclosure")
	}
	if _, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil {
		t.Fatal("ordinary issuance acquired anonymous selection")
	}
	if _, err := i.PrepareResetRecipient(context.Background(), b, "existing-user", payload); err == nil {
		t.Fatal("reset issuance acquired magic-link authority")
	}
}

func TestMagicLinkIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, binding, payload := issuerFixture(t)
	b := magicLinkIssuerBinding(binding)
	payload.Subject, payload.Operation = "existing-user", "identity.magic-link.consume"
	for _, change := range []func(*identity.CommandBinding, *identity.UserID, *capability.Payload){
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) {
			b.UserID = "existing-user"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.AnonymousFlowID = "" },
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) {
			b.OperationID = "identity.password.reset-request"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.SchemaVersion++ },
		func(_ *identity.CommandBinding, u *identity.UserID, _ *capability.Payload) { *u = "" },
		func(_ *identity.CommandBinding, u *identity.UserID, _ *capability.Payload) { *u = "\x00" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Subject = "foreign" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Tenant = "foreign" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) {
			p.Operation = "identity.password.reset-complete"
		},
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Bearer = true },
	} {
		changed, target, p := b, identity.UserID("existing-user"), payload
		change(&changed, &target, &p)
		if out, err := i.PrepareMagicLinkRecipient(context.Background(), changed, target, p); err == nil || out.state != nil {
			t.Fatal("foreign magic-link profile accepted")
		}
	}
}
