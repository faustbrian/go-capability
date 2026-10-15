package identitycapability

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestManagedVerificationConsumptionPreservesOriginalProfile(t *testing.T) {
	i, c, binding, payload := issuerFixture(t)
	payload.ID, payload.IssuedAt, payload.NotBefore = "managed-proof", c.Crypto.Clock(), c.Crypto.Clock()
	binding.ActorID, binding.ActorKind = "confirmation-service", authorization.SubjectServiceAccount
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = "identity.email.verification-confirm", "identity.email.verification-confirm.managed-v1", 1
	binding.PolicyID, binding.PolicyVersion, binding.CorrelationID, binding.RecordID = "email-policy", 1, string(binding.CommandID), "identifier"
	payload.Caveats = map[string]string{"email.profile": "management-v1", "email.confirm_operation": "identity.email.verification-confirm", "email.intent": strings.Repeat("a", 64), "email.binding_key_version": "1"}
	proof, _, err := i.service.Issue(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := i.service.Verify(t.Context(), proof, "identity.identifier.verify", c.Audience)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := any(i).(interface {
		PrepareManagedVerificationConsumption(context.Context, identity.CommandBinding, capability.Proof, [32]byte, uint32) (kernel.CapabilityPlan, error)
	})
	if !ok {
		t.Fatal("issuer cannot prepare managed-email verification consumption")
	}
	got, err := owner.PrepareManagedVerificationConsumption(t.Context(), binding, proof, grant.EnvelopeDigest(), 1)
	expected, expectedErr := i.grantPlan(binding, binding.UserID, grant, 1)
	if err != nil || expectedErr != nil || got != expected {
		t.Fatal("management preparation rewrote original proof", err)
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.UserID = "other" },
		func(b *identity.CommandBinding) { b.RecordID = "other" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.email.change-confirm" },
		func(b *identity.CommandBinding) { b.SchemaID = "identity.email.verification-confirm.native-v1" },
	} {
		other := binding
		mutate(&other)
		if out, err := owner.PrepareManagedVerificationConsumption(t.Context(), other, proof, grant.EnvelopeDigest(), 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("foreign confirmation scope admitted")
		}
	}
	for _, mutate := range []func(map[string]string){
		func(v map[string]string) { v["email.profile"] = "registration-v1" },
		func(v map[string]string) { v["email.confirm_operation"] = "identity.email.change-confirm" },
		func(v map[string]string) { v["email.intent"] = strings.Repeat("A", 64) },
		func(v map[string]string) { v["email.binding_key_version"] = "01" },
		func(v map[string]string) { v["extra"] = "foreign" },
	} {
		other := payload
		other.Caveats = maps.Clone(payload.Caveats)
		mutate(other.Caveats)
		p, _, err := i.service.Issue(t.Context(), other)
		if err != nil {
			t.Fatal(err)
		}
		g, err := i.service.Verify(t.Context(), p, "identity.identifier.verify", c.Audience)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := owner.PrepareManagedVerificationConsumption(t.Context(), binding, p, g.EnvelopeDigest(), 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("signed foreign profile admitted")
		}
	}
	registration := binding
	registration.SchemaID = "identity.email.verification-confirm.native-v1"
	if out, err := i.PrepareRegistrationVerificationConsumption(t.Context(), registration, proof, grant.EnvelopeDigest(), 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("management proof admitted by signup preparation")
	}
}

func TestManagedChangeConsumptionCannotBecomeVerificationOnly(t *testing.T) {
	i, c, binding, payload := issuerFixture(t)
	owner, ok := any(i).(interface {
		PrepareManagedChangeConsumption(context.Context, identity.CommandBinding, capability.Proof, [32]byte, uint32) (kernel.CapabilityPlan, error)
	})
	if !ok {
		t.Fatal("issuer lacks exact managed primary-change consumption")
	}
	payload.ID, payload.IssuedAt, payload.NotBefore = "managed-change", c.Crypto.Clock(), c.Crypto.Clock()
	binding.ActorID, binding.ActorKind = "confirmation-service", authorization.SubjectServiceAccount
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = "identity.email.change-confirm", "identity.email.change-confirm.managed-v1", 1
	binding.PolicyID, binding.PolicyVersion, binding.CorrelationID, binding.RecordID = "email-policy", 1, string(binding.CommandID), "identifier"
	payload.Caveats = map[string]string{"email.profile": "management-v1", "email.confirm_operation": "identity.email.change-confirm", "email.intent": strings.Repeat("a", 64), "email.binding_key_version": "1"}
	proof, _, err := i.service.Issue(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := i.service.Verify(t.Context(), proof, "identity.identifier.verify", c.Audience)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := owner.PrepareManagedChangeConsumption(t.Context(), binding, proof, grant.EnvelopeDigest(), 1)
	if err != nil || plan.Purpose != "identity.identifier.verify" || plan.ProofFingerprint != grant.EnvelopeDigest() || plan.CapabilityID != payload.ID {
		t.Fatal("change rewrote original capability", err)
	}
	wrong := binding
	wrong.OperationID, wrong.SchemaID = "identity.email.verification-confirm", "identity.email.verification-confirm.managed-v1"
	if _, err := owner.PrepareManagedChangeConsumption(t.Context(), wrong, proof, grant.EnvelopeDigest(), 1); err == nil {
		t.Fatal("verification command borrowed primary change")
	}
	if _, err := i.PrepareManagedVerificationConsumption(t.Context(), wrong, proof, grant.EnvelopeDigest(), 1); err == nil {
		t.Fatal("change proof became verification-only")
	}
}
