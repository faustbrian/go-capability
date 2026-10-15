package identitycapability

import (
	"bytes"
	"context"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func resetIssuerBinding(b identity.CommandBinding) identity.CommandBinding {
	b = registrationIssuerBinding(b)
	b.OperationID, b.SchemaID = "identity.password.reset-request", "password-reset-request"
	return b
}

func TestResetRecipientIssuerPreservesOriginAndEncryptedCustody(t *testing.T) {
	i, config, binding, payload := issuerFixture(t)
	b := resetIssuerBinding(binding)
	payload.Subject, payload.Operation = "existing-user", "identity.password.reset-complete"
	p, err := i.PrepareResetRecipient(context.Background(), b, "existing-user", payload)
	if err != nil {
		t.Fatal("existing-recipient reset denied", err)
	}
	plan, err := p.Plan()
	if err != nil || plan.ResetRecipientUserID != "existing-user" || plan.RegistrationUserID != "" || p.state.binding != b || len(plan.Grants) != 1 {
		t.Fatal("reset selection changed anonymous origin", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("closed reset declaration rejected", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil {
		t.Fatal("encrypted original custody failed", err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b {
		t.Fatal("original anonymous binding not restored", err)
	}
	g := restored.state.grants[0]
	if g.Payload().Subject != "existing-user" || g.Payload().Operation != payload.Operation || g.EnvelopeDigest() != plan.Grants[0].ProofFingerprint {
		t.Fatal("restoration reissued or retargeted grant")
	}
	again, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("retry did not preserve original encrypted bytes", err)
	}
	for _, change := range []func(*identitypostgres.CapabilityIssuancePlan){
		func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = "foreign" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = "" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = p.ResetRecipientUserID },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.identifier.verify" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
	} {
		changed := plan
		changed.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
		change(&changed)
		if out, err := codec.RestorePreparation(context.Background(), b, 7, changed, wire); err == nil || out.state != nil {
			t.Fatal("foreign reset declaration restored")
		}
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("restored bearer revealed"); return nil }) == nil {
		t.Fatal("restoration renewed disclosure custody")
	}
	if _, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil {
		t.Fatal("ordinary issuance acquired anonymous selection")
	}
	if _, err := i.PrepareRegistration(context.Background(), b, "existing-user", []capability.Payload{payload}); err == nil {
		t.Fatal("signup issuance acquired reset authority")
	}
}

func TestResetRecipientIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, binding, payload := issuerFixture(t)
	b := resetIssuerBinding(binding)
	payload.Subject, payload.Operation = "existing-user", "identity.password.reset-complete"
	for _, change := range []func(*identity.CommandBinding, *identity.UserID, *capability.Payload){
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) {
			b.UserID = "existing-user"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.AnonymousFlowID = "" },
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) {
			b.OperationID = "identity.password.signup"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.SchemaVersion++ },
		func(_ *identity.CommandBinding, u *identity.UserID, _ *capability.Payload) { *u = "" },
		func(_ *identity.CommandBinding, u *identity.UserID, _ *capability.Payload) { *u = "\x00" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Subject = "foreign" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Tenant = "foreign" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) {
			p.Operation = "identity.identifier.verify"
		},
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Bearer = true },
	} {
		changed, target, p := b, identity.UserID("existing-user"), payload
		change(&changed, &target, &p)
		if out, err := i.PrepareResetRecipient(context.Background(), changed, target, p); err == nil || out.state != nil {
			t.Fatal("foreign reset profile accepted")
		}
	}
}
