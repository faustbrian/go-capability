package identitycapability

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The native risk profile already has an actual, resolved user and credential.
// Ordinary issuance preserves that scope; no anonymous recipient override is
// needed. This fixture proves original custody, not genuine recovery admission.
func TestPhoneResetIssuerUsesExistingUserBoundOriginalCustody(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	b.ActorID, b.ActorKind, b.RecordID = "user", authorization.SubjectUser, "password"
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.phone.password-reset-request", "identity.phone.password-reset-request.native-v1", 1
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "phone-reset", 1, string(b.CommandID)
	payload.Resource, payload.Operation = "identity.password/password", "identity.phone.password-reset-complete"
	payload.IssuedAt, payload.NotBefore, payload.CorrelationID = config.Crypto.Clock(), config.Crypto.Clock(), string(b.CommandID)
	payload.Caveats = map[string]string{"password.recovery-path": "phone_password_reset", "phone.preauth": "original-browser", "phone.challenge": "original-sms", "phone.attempt": string(b.CommandID), "phone.factor": "totp:5:independent-factor", "phone.policy": "3:6"}
	p, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("existing user-bound issuance denied phone purpose", err)
	}
	plan, err := p.Plan()
	if err != nil || plan.ResetRecipientUserID != "" || plan.RegistrationUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" || p.state.binding != b || len(plan.Grants) != 1 || plan.Grants[0].Purpose != "identity.phone.password-reset-complete" {
		t.Fatal("phone issuance acquired alternate subject authority", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("existing issuer rejected native user-bound declaration", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil {
		t.Fatal("original phone custody checkpoint failed", err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b {
		t.Fatal("phone origin was not restored unchanged", err)
	}
	grant := restored.state.grants[0]
	got := grant.Payload()
	if got.Subject != payload.Subject || got.Tenant != payload.Tenant || got.Operation != payload.Operation || got.Resource != payload.Resource || got.ExpiresAt != payload.ExpiresAt || !reflect.DeepEqual(got.Caveats, payload.Caveats) || grant.EnvelopeDigest() != plan.Grants[0].ProofFingerprint {
		t.Fatal("restoration renewed or retargeted canonical phone grant")
	}
	again, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("retry replaced original encrypted custody", err)
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("restored bearer revealed"); return nil }) == nil {
		t.Fatal("restoration renewed bearer disclosure")
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) {
			b.OperationID = "identity.password.reset-request"
			b.SchemaID = "password-reset-request"
		},
	} {
		changed := b
		change(&changed)
		if out, err := codec.RestorePreparation(context.Background(), changed, 7, plan, wire); err == nil || out.state != nil {
			t.Fatal("foreign request restored original phone custody")
		}
	}
	for _, change := range []func(*kernel.CapabilityIssuancePlan){
		func(p *kernel.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		func(p *kernel.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.password.reset-complete" },
	} {
		changed := plan
		changed.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
		change(&changed)
		if out, err := codec.RestorePreparation(context.Background(), b, 7, changed, wire); err == nil || out.state != nil {
			t.Fatal("foreign plan restored original phone custody")
		}
	}
	if i.Stage(context.Background(), kernel.Work{}, restored) == nil {
		t.Fatal("phone issuance bypassed coordinator phase custody")
	}
	if out, err := i.PrepareResetRecipient(context.Background(), b, "user", payload); err == nil || out.state != nil {
		t.Fatal("legacy email recipient override admitted native phone request")
	}
}
