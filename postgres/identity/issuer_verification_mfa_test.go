package identitycapability

import (
	"context"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestVerificationMFAIssuerConservesExplicitParentAndSubject(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	b = registrationIssuerBinding(b)
	b.UserID, b.AnonymousFlowID = identity.UserID(payload.Subject), ""
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.email.verification-signin", "email-verification-signin", 1
	b.RecordID, b.PolicyVersion = "AgICAgICAgICAgICAgICAg", 2
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err := b.ValidateFor(op); err != nil {
		t.Fatal("malformed verification test binding", err)
	}
	payload.ID, payload.Operation = "AQEBAQEBAQEBAQEBAQEBAQ", "identity.mfa.complete"
	payload.CorrelationID = b.RecordID
	payload.Resource = "mfa/continuations/" + payload.ID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.Caveats = map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": strings.Repeat("07", 32)}
	declaration := kernel.CapabilityIssuancePlan{MFAContinuationUserID: b.UserID}
	if subject, valid := issuerPlanSubject(b, declaration); !valid || subject != b.UserID {
		t.Fatal("separately committed verification parent cannot retain explicit recipient")
	}
	prepared, err := i.PrepareVerificationMFAContinuation(context.Background(), b, payload)
	if err != nil {
		t.Fatal("verification-origin challenge rejected", err)
	}
	plan, err := prepared.Plan()
	if err != nil || prepared.state.binding != b || plan.MFAContinuationUserID != b.UserID || len(plan.Grants) != 1 || plan.Grants[0].CapabilityID != payload.ID {
		t.Fatal("parent, explicit subject or child identity changed", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 3, plan, wire)
	if err != nil || restored.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint || restored.state.grants[0].Payload().ExpiresAt != payload.ExpiresAt {
		t.Fatal("restore replaced original child or deadline", err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"missing parent":     func(b *identity.CommandBinding) { b.RecordID = "" },
		"self parent":        func(b *identity.CommandBinding) { b.RecordID = string(b.CommandID) },
		"malformed parent":   func(b *identity.CommandBinding) { b.RecordID = "not-a-command-id" },
		"foreign user":       func(b *identity.CommandBinding) { b.UserID = "another-user" },
		"missing subject":    func(b *identity.CommandBinding) { b.UserID = "" },
		"anonymous override": func(b *identity.CommandBinding) { b.AnonymousFlowID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"foreign owner":      func(b *identity.CommandBinding) { b.OperationID = "identity.password.signin" },
		"foreign schema":     func(b *identity.CommandBinding) { b.SchemaVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			mutate(&bad)
			if _, valid := issuerPlanSubject(bad, declaration); valid {
				t.Fatal("foreign verification scope selected challenge subject")
			}
			if _, err := codec.RestorePreparation(context.Background(), bad, 3, plan, wire); err == nil {
				t.Fatal("encrypted child restored under substituted original scope")
			}
		})
	}
	foreign := b
	foreign.RecordID = "AwMDAwMDAwMDAwMDAwMDAw"
	if _, err := codec.RestorePreparation(context.Background(), foreign, 3, plan, wire); err == nil {
		t.Fatal("child restored under a different well-formed committed parent")
	}
	if _, err := i.PrepareMFAContinuation(context.Background(), b, payload); err == nil {
		t.Fatal("historical anonymous API silently broadened to verification")
	}
	payload.CorrelationID = "AwMDAwMDAwMDAwMDAwMDAw"
	if _, err := i.PrepareVerificationMFAContinuation(context.Background(), b, payload); err == nil {
		t.Fatal("signed child retargeted to a foreign confirmation parent")
	}
}
