package identitycapability

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func ssoBreakGlassIssuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, time.Time) {
	t.Helper()
	_, config, b, _ := issuerFixture(t)
	config.Audience = "identity.sso.break-glass"
	i, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	b.ActorID, b.ActorKind = "issuing-administrator", authorization.SubjectUser
	b.UserID = "independent-recipient"
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.sso.break-glass.issue", "identity.sso.break-glass.issue.native-v1", 1
	b.RecordID, b.PolicyID, b.PolicyVersion = "exact-organization", "administration-policy", 9
	b.CorrelationID = "original-break-glass-issuance"
	return i, config, b, config.Crypto.Clock()
}

func TestSSOBreakGlassIssuerOwnsExactSignedScopeAndRestoration(t *testing.T) {
	i, config, b, issuedAt := ssoBreakGlassIssuerFixture(t)
	prepared, err := i.PrepareSSOBreakGlass(context.Background(), b, 7, issuedAt)
	if err != nil {
		t.Fatal("dedicated break-glass preparation failed", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 || i.ValidateCapabilityIssuance(b, plan) != nil {
		t.Fatal("dedicated break-glass plan invalid", err)
	}
	metadata := plan.Grants[0]
	if metadata.Purpose != "identity.sso.break-glass.consume" || metadata.MaxUses != 1 || metadata.ExpiresAt != issuedAt.Add(15*time.Minute) {
		t.Fatal("break-glass metadata changed purpose, lifetime or one-use custody")
	}
	if b.PolicyVersion != 9 || string(b.ActorID) == string(b.UserID) {
		t.Fatal("fixture collapsed authorization policy or independent recipient")
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 3, func(ctx context.Context, _ uint16, token []byte) error {
		grant, err := capability.Verify(ctx, string(token), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: issuedAt, Limits: config.Crypto.Limits})
		if err != nil {
			t.Fatal("original break-glass envelope did not authenticate", err)
		}
		want := capability.Payload{Version: 1, ID: metadata.CapabilityID, Issuer: config.Crypto.Issuer, Audiences: []string{"identity.sso.break-glass"}, Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID, Operation: "identity.sso.break-glass.consume", CorrelationID: b.CorrelationID, IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(15 * time.Minute), MaxUses: 1, Caveats: map[string]string{"sso.break-glass.policy-version": "7"}}
		if !reflect.DeepEqual(grant.Payload(), want) || grant.EnvelopeDigest() != metadata.ProofFingerprint {
			t.Fatal("signed break-glass scope or policy revision changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal("checkpoint original break-glass custody", err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 3, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b || !reflect.DeepEqual(restored.state.grants[0].Payload(), prepared.state.grants[0].Payload()) {
		t.Fatal("restoration changed original break-glass authority", err)
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("restoration disclosed a credential"); return nil }) == nil {
		t.Fatal("restoration renewed disclosure custody")
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"recipient":            func(b *identity.CommandBinding) { b.UserID += "-foreign" },
		"administrator":        func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
		"organization":         func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"correlation":          func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"authorization policy": func(b *identity.CommandBinding) { b.PolicyVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if _, err := codec.RestorePreparation(context.Background(), foreign, 3, plan, wire); err == nil {
				t.Fatal("foreign original scope restored break-glass custody")
			}
		})
	}
}

func TestSSOBreakGlassIssuerRejectsGenericAndMalformedPreparation(t *testing.T) {
	i, config, binding, issuedAt := ssoBreakGlassIssuerFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"operation":            func(b *identity.CommandBinding) { b.OperationID = "identity.profile.update" },
		"schema":               func(b *identity.CommandBinding) { b.SchemaID += "-foreign" },
		"schema version":       func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"organization":         func(b *identity.CommandBinding) { b.RecordID = "" },
		"recipient":            func(b *identity.CommandBinding) { b.UserID = "" },
		"actor":                func(b *identity.CommandBinding) { b.ActorID = "" },
		"service actor":        func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		"anonymous flow":       func(b *identity.CommandBinding) { b.AnonymousFlowID = "foreign-flow" },
		"correlation":          func(b *identity.CommandBinding) { b.CorrelationID = "" },
		"authorization policy": func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			b := binding
			mutate(&b)
			if _, err := i.PrepareSSOBreakGlass(context.Background(), b, 7, issuedAt); err == nil {
				t.Fatal("malformed break-glass scope prepared")
			}
		})
	}
	for _, version := range []uint64{0, ^uint64(0)} {
		if _, err := i.PrepareSSOBreakGlass(context.Background(), binding, version, issuedAt); err == nil {
			t.Fatal("non-successor-capable break-glass policy prepared")
		}
	}
	for _, instant := range []time.Time{time.Time{}, issuedAt.Add(time.Nanosecond), issuedAt.In(time.FixedZone("foreign", 3600))} {
		if _, err := i.PrepareSSOBreakGlass(context.Background(), binding, 7, instant); err == nil {
			t.Fatal("noncanonical break-glass issue time prepared")
		}
	}
	config.Audience = "identity"
	foreign, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.PrepareSSOBreakGlass(context.Background(), binding, 7, issuedAt); err == nil {
		t.Fatal("foreign-audience issuer prepared break-glass credential")
	}
	payload := capability.Payload{Version: 1, Issuer: config.Crypto.Issuer, Audiences: []string{"identity.sso.break-glass"}, Subject: string(binding.UserID), Tenant: string(binding.TenantID), Resource: binding.RecordID, Operation: "identity.sso.break-glass.consume", CorrelationID: binding.CorrelationID, IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(15 * time.Minute), MaxUses: 1, Caveats: map[string]string{"sso.break-glass.policy-version": "7"}}
	if _, err := i.Prepare(context.Background(), binding, []capability.Payload{payload}); err == nil {
		t.Fatal("generic preparation manufactured dedicated break-glass credential")
	}
	ordinary := binding
	ordinary.OperationID, ordinary.SchemaID = "identity.profile.update", "profile-update"
	if _, err := i.Prepare(context.Background(), ordinary, []capability.Payload{payload}); err == nil {
		t.Fatal("ordinary operation manufactured break-glass consume purpose")
	}
	payload.Operation = "identity.identifier.verify"
	if _, err := i.Prepare(context.Background(), binding, []capability.Payload{payload}); err == nil {
		t.Fatal("break-glass issue operation manufactured another purpose")
	}
}

func TestSSOBreakGlassIssuerRejectsPlanCrossWorkflowOverrides(t *testing.T) {
	i, _, b, issuedAt := ssoBreakGlassIssuerFixture(t)
	prepared, err := i.PrepareSSOBreakGlass(context.Background(), b, 7, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := prepared.Plan()
	for name, mutate := range map[string]func(*kernel.CapabilityIssuancePlan){
		"registration": func(p *kernel.CapabilityIssuancePlan) { p.RegistrationUserID = b.UserID },
		"reset":        func(p *kernel.CapabilityIssuancePlan) { p.ResetRecipientUserID = b.UserID },
		"magiclink":    func(p *kernel.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = b.UserID },
		"MFA":          func(p *kernel.CapabilityIssuancePlan) { p.MFAContinuationUserID = b.UserID },
		"second grant": func(p *kernel.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
		"purpose":      func(p *kernel.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.identifier.verify" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := plan
			candidate.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
			mutate(&candidate)
			if i.ValidateCapabilityIssuance(b, candidate) == nil {
				t.Fatal("cross-workflow override borrowed break-glass issuance")
			}
		})
	}
}

func TestSSOBreakGlassIssuerRejectsSignedBroaderGrantOnReplay(t *testing.T) {
	i, _, b, issuedAt := ssoBreakGlassIssuerFixture(t)
	prepared, err := i.PrepareSSOBreakGlass(context.Background(), b, 7, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	original := prepared.state.grants[0].Payload()
	for name, mutate := range map[string]func(*capability.Payload){
		"organization":          func(p *capability.Payload) { p.Resource += "-foreign" },
		"recipient":             func(p *capability.Payload) { p.Subject += "-foreign" },
		"correlation":           func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"longer lifetime":       func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"shorter lifetime":      func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(-time.Second) },
		"different activation":  func(p *capability.Payload) { p.NotBefore = p.NotBefore.Add(-time.Second) },
		"extra caveat":          func(p *capability.Payload) { p.Caveats["foreign"] = "scope" },
		"zero revision":         func(p *capability.Payload) { p.Caveats["sso.break-glass.policy-version"] = "0" },
		"noncanonical revision": func(p *capability.Payload) { p.Caveats["sso.break-glass.policy-version"] = "07" },
		"overflowing successor": func(p *capability.Payload) { p.Caveats["sso.break-glass.policy-version"] = "18446744073709551615" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := original
			candidate.Caveats = map[string]string{"sso.break-glass.policy-version": "7"}
			mutate(&candidate)
			proof, _, err := i.service.Issue(context.Background(), candidate)
			if err != nil {
				t.Fatal("cryptographic fixture could not sign structurally valid broader payload", err)
			}
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			grant, err := i.service.Verify(context.Background(), proof, "identity.sso.break-glass.consume", "identity.sso.break-glass")
			if err != nil {
				t.Fatal("broader signed fixture did not authenticate", err)
			}
			if _, err := i.grantSubjectPlan(b, string(b.UserID), grant, i.current); err == nil {
				t.Fatal("broader signed grant borrowed break-glass staging or restoration metadata")
			}
		})
	}
}
