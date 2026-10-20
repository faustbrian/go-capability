package identitycapability

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestMFAIssuerPreservesChallengeIDAndEncryptedCustody(t *testing.T) {
	i, config, binding, payload := issuerFixture(t)
	b := magicLinkIssuerBinding(binding)
	b.OperationID, b.SchemaID = "identity.magic-link.consume", "magic-link-consume"
	payload.ID, payload.Subject, payload.Operation = "AQEBAQEBAQEBAQEBAQEBAQ", "existing-user", "identity.mfa.complete"
	payload.Resource = "mfa/continuations/" + payload.ID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.Caveats = map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": strings.Repeat("07", 32)}
	p, err := i.PrepareMFAContinuation(context.Background(), b, payload)
	if err != nil {
		t.Fatal("bounded original challenge denied", err)
	}
	plan, err := p.Plan()
	if err != nil || plan.MFAContinuationUserID != "existing-user" || plan.MagicLinkRecipientUserID != "" || plan.ResetRecipientUserID != "" || plan.RegistrationUserID != "" || len(plan.Grants) != 1 || plan.Grants[0].CapabilityID != payload.ID || p.state.binding != b {
		t.Fatal("challenge identity or anonymous origin changed", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil {
		t.Fatal("original encrypted challenge custody failed", err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint || restored.state.grants[0].Payload().ID != payload.ID || restored.state.grants[0].Payload().ExpiresAt != payload.ExpiresAt {
		t.Fatal("restore replaced challenge identity, bytes or expiry", err)
	}
	again, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("retry replaced encrypted challenge", err)
	}
	changed := plan
	changed.MFAContinuationUserID = "foreign-user"
	if out, err := codec.RestorePreparation(context.Background(), b, 7, changed, wire); err == nil || out.state != nil {
		t.Fatal("encrypted challenge retargeted")
	}
	if _, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil {
		t.Fatal("ordinary issuance selected anonymous challenge subject")
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"missing ID":         func(p *capability.Payload) { p.ID = "" },
		"foreign resource":   func(p *capability.Payload) { p.Resource = "session/continuations/" + p.ID },
		"missing scope":      func(p *capability.Payload) { delete(p.Caveats, "mfa.scope") },
		"zero scope":         func(p *capability.Payload) { p.Caveats["mfa.scope"] = strings.Repeat("0", 64) },
		"extra caveat":       func(p *capability.Payload) { p.Caveats["other.scope"] = "unbound" },
		"extended lifetime":  func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
		"changed not-before": func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(time.Second) },
		"foreign tenant":     func(p *capability.Payload) { p.Tenant = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := payload
			bad.Caveats = map[string]string{"mfa.profile": payload.Caveats["mfa.profile"], "mfa.scope": payload.Caveats["mfa.scope"]}
			mutate(&bad)
			if out, err := i.PrepareMFAContinuation(context.Background(), b, bad); err == nil || out.state != nil {
				t.Fatal("foreign or unbounded challenge signed")
			}
		})
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"authenticated subject":  func(b *identity.CommandBinding) { b.UserID = "existing-user" },
		"missing anonymous flow": func(b *identity.CommandBinding) { b.AnonymousFlowID = "" },
		"request not consumption": func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID = "identity.magic-link.request", "magic-link-request"
		},
		"foreign schema": func(b *identity.CommandBinding) { b.SchemaVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			mutate(&bad)
			if out, err := i.PrepareMFAContinuation(context.Background(), bad, payload); err == nil || out.state != nil {
				t.Fatal("foreign command selected challenge subject")
			}
		})
	}
	if out, err := i.PrepareMFAContinuation(nilContextForTest(), b, payload); err == nil || out.state != nil {
		t.Fatal("nil context acquired custody")
	}
	var absent *Issuer
	if out, err := absent.PrepareMFAContinuation(context.Background(), b, payload); err == nil || out.state != nil {
		t.Fatal("nil issuer acquired custody")
	}
}

func TestMFAIssuerAdmitsOnlyClosedPasswordSigninOrigin(t *testing.T) {
	testMFAIssuerClosedSigninOrigin(t, "identity.password.signin", "password-signin")
}

func TestMFAIssuerAdmitsOnlyClosedUsernameSigninOrigin(t *testing.T) {
	testMFAIssuerClosedSigninOrigin(t, "identity.username.signin", "username-signin")
}

func TestMFAIssuerAdmitsOnlyClosedPhonePasswordSigninOrigin(t *testing.T) {
	testMFAIssuerClosedSigninOrigin(t, "identity.phone.password-signin", "phone-password-signin")
}

func testMFAIssuerClosedSigninOrigin(t *testing.T, operation, schema string) {
	t.Helper()
	i, config, binding, payload := issuerFixture(t)
	b := magicLinkIssuerBinding(binding)
	b.OperationID, b.SchemaID = operation, schema
	payload.ID, payload.Subject, payload.Operation = "AQEBAQEBAQEBAQEBAQEBAQ", "existing-user", "identity.mfa.complete"
	payload.Resource = "mfa/continuations/" + payload.ID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.Caveats = map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": strings.Repeat("07", 32)}
	issued, err := i.PrepareMFAContinuation(context.Background(), b, payload)
	if err != nil {
		t.Fatal("genuine signin origin denied", err)
	}
	plan, err := issued.Plan()
	if err != nil || plan.MFAContinuationUserID != identity.UserID(payload.Subject) || plan.Grants[0].CapabilityID != payload.ID || issued.state.binding != b {
		t.Fatal("signin origin retargeted", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("original signin declaration rejected", err)
	}
	if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil || out.state != nil {
		t.Fatal("ordinary issuance selected anonymous signin subject")
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), issued, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 1, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b || restored.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint || restored.state.grants[0].Payload().ID != payload.ID || restored.state.grants[0].Payload().ExpiresAt != payload.ExpiresAt {
		t.Fatal("original signin child identity, browser or expiry changed", err)
	}
	for _, origin := range [][2]string{
		{"identity.magic-link.consume", "magic-link-consume"},
		{"identity.password.signin", "password-signin"},
		{"identity.username.signin", "username-signin"},
		{"identity.phone.password-signin", "phone-password-signin"},
	} {
		if origin[0] == operation {
			continue
		}
		foreign := b
		foreign.OperationID, foreign.SchemaID = origin[0], origin[1]
		if _, err := codec.RestorePreparation(context.Background(), foreign, 1, plan, wire); err == nil {
			t.Fatal("signin child restored under another primary origin")
		}
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.SchemaID = "magic-link-consume" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.password.reset-complete" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.phone.password-signin.foreign" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.RecordID = string(b.CommandID) },
		func(b *identity.CommandBinding) { b.UserID = "existing-user" },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "" },
	} {
		bad := b
		change(&bad)
		if _, err := i.PrepareMFAContinuation(context.Background(), bad, payload); err == nil {
			t.Fatal("foreign anonymous signin profile admitted")
		}
		if _, err := codec.RestorePreparation(context.Background(), bad, 1, plan, wire); err == nil {
			t.Fatal("foreign anonymous signin profile restored")
		}
	}
	foreignBrowser := b
	otherBrowser, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	foreignBrowser.AnonymousFlowID = string(otherBrowser)
	if _, err := codec.RestorePreparation(context.Background(), foreignBrowser, 1, plan, wire); err == nil {
		t.Fatal("signin child restored under another browser")
	}
}
