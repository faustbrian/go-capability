package identitycapability

import (
	"context"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestPasskeyMFAIssuerRetainsExactOriginalPrimaryAndChild(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "policy", 1, "correlation"
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.passkey.signin-verify", "identity.passkey.signin-verify.native-v1", 1
	b.RecordID, b.ActorID, b.ActorKind = string(b.CommandID), identity.ActorID(b.UserID), authorization.SubjectUser
	b.AnonymousFlowID = ""
	payload.ID, payload.Operation = "AQEBAQEBAQEBAQEBAQEBAQ", "identity.mfa.complete"
	payload.CorrelationID, payload.Resource = string(b.CommandID), "mfa/continuations/"+payload.ID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.Caveats = map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": strings.Repeat("07", 32)}
	prepared, err := i.PreparePasskeyMFAContinuation(context.Background(), b, payload)
	if err != nil {
		t.Fatal("explicit native passkey child preparation denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || plan.MFAContinuationUserID != b.UserID || len(plan.Grants) != 1 || plan.Grants[0].CapabilityID != payload.ID {
		t.Fatal("original subject or child changed", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 2, plan, wire)
	if err != nil || restored.state == nil || restored.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint || restored.state.grants[0].Payload().ExpiresAt != payload.ExpiresAt {
		t.Fatal("restoration changed original signed child or expiry", err)
	}
	for name, change := range map[string]func(*identity.CommandBinding){
		"foreign subject":    func(b *identity.CommandBinding) { b.UserID = "another-user" },
		"foreign actor":      func(b *identity.CommandBinding) { b.ActorID = "another-user" },
		"platform actor":     func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		"anonymous":          func(b *identity.CommandBinding) { b.AnonymousFlowID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"missing original":   func(b *identity.CommandBinding) { b.RecordID = "" },
		"different original": func(b *identity.CommandBinding) { b.RecordID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"foreign tenant":     func(b *identity.CommandBinding) { b.TenantID = "another-tenant" },
		"foreign schema":     func(b *identity.CommandBinding) { b.SchemaID = "identity.passkey.signin-verify.other" },
		"foreign version":    func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"foreign operation":  func(b *identity.CommandBinding) { b.OperationID = "identity.password.signin" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			change(&bad)
			if out, err := i.PreparePasskeyMFAContinuation(context.Background(), bad, payload); err == nil || out.state != nil {
				t.Fatal("foreign original acquired signed child")
			}
			if out, err := codec.RestorePreparation(context.Background(), bad, 2, plan, wire); err == nil || out.state != nil {
				t.Fatal("foreign original restored child custody")
			}
		})
	}
	if _, err := i.PrepareMFAContinuation(context.Background(), b, payload); err == nil {
		t.Fatal("historical anonymous API silently broadened")
	}
	for _, correlation := range []string{"", "AwMDAwMDAwMDAwMDAwMDAw"} {
		bad := payload
		bad.CorrelationID = correlation
		if _, err := i.PreparePasskeyMFAContinuation(context.Background(), b, bad); err == nil {
			t.Fatal("signed child detached from original primary")
		}
	}
	mixed := plan
	mixed.RegistrationUserID = b.UserID
	if _, ok := issuerPlanSubject(b, mixed); ok {
		t.Fatal("mixed authority selected passkey child subject")
	}
	if _, err := i.PreparePasskeyMFAContinuation(nilContextForTest(), b, payload); err == nil {
		t.Fatal("nil context admitted")
	}
}
