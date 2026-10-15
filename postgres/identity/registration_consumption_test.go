package identitycapability

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type registrationConsumptionPreparer interface {
	PrepareRegistrationVerificationConsumption(context.Context, identity.CommandBinding, capability.Proof, [32]byte, uint32) (kernel.CapabilityPlan, error)
}

func TestRegistrationConsumptionPreservesAnonymousProofProfile(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	now := config.Crypto.Clock()
	payload.ID, payload.IssuedAt, payload.NotBefore = "registration-proof", now, now
	payload.Caveats = map[string]string{"email.profile": "registration-v1", "email.confirm_operation": "identity.email.verification-confirm", "email.intent": strings.Repeat("a", 64), "email.binding_key_version": "1"}
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := i.service.Verify(context.Background(), proof, "identity.identifier.verify", config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	b.ActorID, b.ActorKind = "confirmation-service", authorization.SubjectServiceAccount
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.email.verification-confirm", "identity.email.verification-confirm.native-v1", 1
	b.PolicyID, b.PolicyVersion, b.CorrelationID, b.RecordID = "email-policy", 1, string(b.CommandID), "identifier"
	reader, ok := any(i).(registrationConsumptionPreparer)
	if !ok {
		t.Fatal("issuer has no anonymous registration confirmation consumption preparation")
	}
	envelope := grant.EnvelopeDigest()
	plan, err := reader.PrepareRegistrationVerificationConsumption(context.Background(), b, proof, envelope, 1)
	expected, expectedErr := i.grantPlan(b, b.UserID, grant, 1)
	if err != nil || expectedErr != nil || plan != expected || plan.Purpose != "identity.identifier.verify" || plan.ProofFingerprint != envelope || plan.ReplayKeyVersion != 1 || len(grant.Payload().Caveats) != 4 {
		t.Fatal("confirmation rewrote original proof identity", err)
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.RecordID = "foreign" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.identifier.verify" },
		func(b *identity.CommandBinding) { b.SchemaVersion = 2 },
		func(b *identity.CommandBinding) { b.SchemaID = "foreign" },
	} {
		wrong := b
		change(&wrong)
		out, err := reader.PrepareRegistrationVerificationConsumption(context.Background(), wrong, proof, envelope, 1)
		if err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("foreign confirmation retained participant input")
		}
	}
	for _, version := range []uint32{0, 3} {
		out, err := reader.PrepareRegistrationVerificationConsumption(context.Background(), b, proof, envelope, version)
		if err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("unretained replay key admitted")
		}
	}
	for _, digest := range [][32]byte{{}, {1}} {
		out, err := reader.PrepareRegistrationVerificationConsumption(context.Background(), b, proof, digest, 1)
		if err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("foreign envelope admitted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := reader.PrepareRegistrationVerificationConsumption(cancelled, b, proof, envelope, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("cancelled confirmation retained plan")
	}
	_, _, sessionProof := identifierConsumptionFixture(t)
	sessionGrant, err := i.service.Verify(context.Background(), sessionProof, "identity.identifier.verify", config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := reader.PrepareRegistrationVerificationConsumption(context.Background(), b, sessionProof, sessionGrant.EnvelopeDigest(), 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("session proof reinterpreted as anonymous registration")
	}
	for _, change := range []func(map[string]string){
		func(c map[string]string) { c["email.profile"] = "session-v1" },
		func(c map[string]string) { c["email.confirm_operation"] = "identity.email.change-confirm" },
		func(c map[string]string) { c["email.intent"] = strings.Repeat("A", 64) },
		func(c map[string]string) { c["email.intent"] = "invalid" },
		func(c map[string]string) { c["email.binding_key_version"] = "01" },
		func(c map[string]string) { c["email.binding_key_version"] = "0" },
		func(c map[string]string) { c["extra"] = "value" },
	} {
		wrong := payload
		wrong.Caveats = maps.Clone(payload.Caveats)
		change(wrong.Caveats)
		p, _, err := i.service.Issue(context.Background(), wrong)
		if err != nil {
			t.Fatal(err)
		}
		g, err := i.service.Verify(context.Background(), p, "identity.identifier.verify", config.Audience)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := reader.PrepareRegistrationVerificationConsumption(context.Background(), b, p, g.EnvelopeDigest(), 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("valid signature bypassed registration profile")
		}
	}
	for _, name := range []string{"revoked", "unavailable", "expired", "panic"} {
		c := config
		switch name {
		case "revoked":
			c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
		case "unavailable":
			c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
				return false, errors.New("private failure")
			})
		case "panic":
			c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private failure") })
		case "expired":
			c.Crypto.Clock = func() time.Time { return payload.ExpiresAt }
		}
		owner, err := NewIssuer(c)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := any(owner).(registrationConsumptionPreparer).PrepareRegistrationVerificationConsumption(context.Background(), b, proof, envelope, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("current verification failure retained input", name)
		}
	}
}
