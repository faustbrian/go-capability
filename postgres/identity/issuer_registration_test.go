package identitycapability

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func registrationIssuerBinding(b identity.CommandBinding) identity.CommandBinding {
	b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
	b.ActorID, b.ActorKind = "signup-actor", authorization.SubjectUser
	b.OperationID, b.PolicyID, b.PolicyVersion = "identity.password.signup", "signup-policy", 1
	b.SchemaID, b.SchemaVersion, b.CorrelationID = "password-signup", 1, "signup-correlation"
	return b
}

func TestRegistrationIssuerOwnsNewSubjectAndOriginalBinding(t *testing.T) {
	i, _, binding, payload := issuerFixture(t)
	b := registrationIssuerBinding(binding)
	payload.Subject = "new-user"
	prepared, err := i.PrepareRegistration(context.Background(), b, "new-user", []capability.Payload{payload})
	if err != nil {
		t.Fatal("valid anonymous registration denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || plan.RegistrationUserID != "new-user" || prepared.state.binding != b {
		t.Fatal("registration intent retargeted", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("frozen registration plan rejected", err)
	}
	if prepared.state.grants[0].Payload().Subject != "new-user" {
		t.Fatal("wrong signed subject")
	}
	plan.RegistrationUserID, plan.Grants[0].ReplayDigest = "different-user", [32]byte{}
	frozen, _ := prepared.Plan()
	if frozen.RegistrationUserID != "new-user" || frozen.Grants[0].ReplayDigest == ([32]byte{}) {
		t.Fatal("caller mutated custody")
	}
	var fingerprint [32]byte
	if err := prepared.TransferForDelivery(context.Background(), 0, func(_ context.Context, token []byte) error { fingerprint = sha256.Sum256(token); return nil }); err != nil {
		t.Fatal(err)
	}
	if fingerprint != frozen.Grants[0].ProofFingerprint || fingerprint == frozen.Grants[0].ReplayDigest {
		t.Fatal("registration provenance lost")
	}
	if prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("second disclosure"); return nil }) == nil {
		t.Fatal("proof revealed twice")
	}
	if _, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil {
		t.Fatal("ordinary preparation opened anonymous override")
	}
}

func TestRegistrationIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, binding, payload := issuerFixture(t)
	b := registrationIssuerBinding(binding)
	payload.Subject = "new-user"
	for _, mutate := range []func(*identity.CommandBinding, *identity.UserID, *capability.Payload){
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.UserID = "new-user" },
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.AnonymousFlowID = "" },
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) {
			b.OperationID = "identity.password.signin"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *capability.Payload) { b.SchemaVersion++ },
		func(_ *identity.CommandBinding, u *identity.UserID, _ *capability.Payload) { *u = "" },
		func(_ *identity.CommandBinding, u *identity.UserID, _ *capability.Payload) { *u = "\x00" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Subject = "other-user" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) { p.Tenant = "other-tenant" },
		func(_ *identity.CommandBinding, _ *identity.UserID, p *capability.Payload) {
			p.Operation = "identity.identifier.attach"
		},
	} {
		changed, target, p := b, identity.UserID("new-user"), payload
		mutate(&changed, &target, &p)
		if _, err := i.PrepareRegistration(context.Background(), changed, target, []capability.Payload{p}); err == nil {
			t.Fatal("foreign registration profile admitted")
		}
	}
}

func TestUsernameRegistrationIssuerRetainsDistinctOriginalOrigin(t *testing.T) {
	i, _, binding, payload := issuerFixture(t)
	b := registrationIssuerBinding(binding)
	b.OperationID, b.SchemaID = "identity.username.signup", "username-signup"
	payload.Subject = "new-user"
	prepared, err := i.PrepareRegistration(context.Background(), b, "new-user", []capability.Payload{payload})
	if err != nil {
		t.Fatal("username origin cannot use existing registration issuer", err)
	}
	plan, err := prepared.Plan()
	if err != nil || prepared.state.binding != b || plan.RegistrationUserID != "new-user" || i.ValidateCapabilityIssuance(b, plan) != nil {
		t.Fatal("issuer relabeled or lost original username registration", err)
	}
	if _, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil {
		t.Fatal("ordinary issuer acquired anonymous registration authority")
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.SchemaID = "password-signup" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.username.signin" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.UserID = "new-user" },
	} {
		wrong := b
		mutate(&wrong)
		if _, err := i.PrepareRegistration(context.Background(), wrong, "new-user", []capability.Payload{payload}); err == nil {
			t.Fatal("cross-profile registration origin accepted")
		}
	}
}
