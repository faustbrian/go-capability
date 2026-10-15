package identitycapability

import (
	"context"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type magicLinkConsumptionPreparer interface {
	PrepareMagicLinkConsumption(context.Context, identity.CommandBinding, identity.UserID, identity.IdentifierID, capability.Proof, [32]byte, uint32) (kernel.CapabilityPlan, error)
}

func TestPrepareMagicLinkConsumptionPreservesOriginalAnonymousProof(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	b = magicLinkIssuerBinding(b)
	b.OperationID, b.SchemaID = "identity.magic-link.consume", "magic-link-consume"
	payload.ID, payload.Subject, payload.Operation, payload.Resource = "magic-proof", "existing-user", b.OperationID, "identity.magiclink/email-id"
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.Caveats = map[string]string{"magiclink.identifier": "email-id"}
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := i.service.Verify(context.Background(), proof, "identity.magic-link.consume", config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := any(i).(magicLinkConsumptionPreparer)
	if !ok {
		t.Fatal("original anonymous magic-link consumption preparation is missing")
	}
	envelope := grant.EnvelopeDigest()
	plan, err := reader.PrepareMagicLinkConsumption(context.Background(), b, "existing-user", "email-id", proof, envelope, 1)
	expected, expectedErr := i.grantPlan(b, "existing-user", grant, 1)
	if err != nil || expectedErr != nil || plan != expected || plan.Purpose != "identity.magic-link.consume" || plan.ReplayKeyVersion != 1 || b.UserID != "" {
		t.Fatal("original anonymous proof identity changed", err)
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := rotated.PrepareMagicLinkConsumption(context.Background(), b, "existing-user", "email-id", proof, envelope, 1); err != nil || again != plan {
		t.Fatal("rotation renewed original consumption identity", err)
	}
	for _, mutate := range []func(*identity.CommandBinding, *identity.UserID, *identity.IdentifierID, *[32]byte, *uint32){
		func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.IdentifierID, _ *[32]byte, _ *uint32) {
			b.UserID = "existing-user"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.IdentifierID, _ *[32]byte, _ *uint32) {
			b.TenantID = "foreign"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.IdentifierID, _ *[32]byte, _ *uint32) {
			b.OperationID = "identity.password.reset-complete"
		},
		func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.IdentifierID, _ *[32]byte, _ *uint32) {
			b.AnonymousFlowID = ""
		},
		func(_ *identity.CommandBinding, u *identity.UserID, _ *identity.IdentifierID, _ *[32]byte, _ *uint32) {
			*u = "foreign"
		},
		func(_ *identity.CommandBinding, _ *identity.UserID, id *identity.IdentifierID, _ *[32]byte, _ *uint32) {
			*id = "foreign"
		},
		func(_ *identity.CommandBinding, _ *identity.UserID, _ *identity.IdentifierID, e *[32]byte, _ *uint32) {
			*e = [32]byte{1}
		},
		func(_ *identity.CommandBinding, _ *identity.UserID, _ *identity.IdentifierID, _ *[32]byte, v *uint32) {
			*v = 3
		},
	} {
		wrong, user, id, digest, version := b, identity.UserID("existing-user"), identity.IdentifierID("email-id"), envelope, uint32(1)
		mutate(&wrong, &user, &id, &digest, &version)
		if out, err := reader.PrepareMagicLinkConsumption(context.Background(), wrong, user, id, proof, digest, version); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("foreign scope/envelope/replay identity admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := reader.PrepareMagicLinkConsumption(ctx, b, "existing-user", "email-id", proof, envelope, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("cancelled preparation retained input")
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("preparation consumed proof custody", err)
	}
	if out, err := reader.PrepareMagicLinkConsumption(context.Background(), b, "existing-user", "email-id", proof, envelope, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("terminal proof regained custody")
	}
}

func TestPrepareMagicLinkConsumptionRejectsSignedForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":              func(p *capability.Payload) { p.Tenant = "foreign" },
		"recipient":           func(p *capability.Payload) { p.Subject = "foreign" },
		"identifier resource": func(p *capability.Payload) { p.Resource = "identity.magiclink/foreign" },
		"identifier caveat":   func(p *capability.Payload) { p.Caveats["magiclink.identifier"] = "foreign" },
		"reset substitution":  func(p *capability.Payload) { p.Operation = "identity.password.reset-complete" },
		"multi-use":           func(p *capability.Payload) { p.MaxUses = 2 },
		"reusable":            func(p *capability.Payload) { p.MaxUses = 0 },
		"multiple audiences":  func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":              func(p *capability.Payload) { p.Subject = ""; p.Bearer = true },
	} {
		t.Run(name, func(t *testing.T) {
			i, config, b, payload := issuerFixture(t)
			b = magicLinkIssuerBinding(b)
			b.OperationID, b.SchemaID = "identity.magic-link.consume", "magic-link-consume"
			payload.ID, payload.Subject, payload.Operation, payload.Resource = "foreign-profile-proof", "existing-user", b.OperationID, "identity.magiclink/email-id"
			payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
			payload.Caveats = map[string]string{"magiclink.identifier": "email-id"}
			mutate(&payload)
			proof, _, err := i.service.Issue(context.Background(), payload)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := i.PrepareMagicLinkConsumption(context.Background(), b, "existing-user", "email-id", proof, grant.EnvelopeDigest(), 1); err == nil || out != (kernel.CapabilityPlan{}) {
				t.Fatal("signed foreign profile produced consuming input")
			}
		})
	}
	var i *Issuer
	if out, err := i.PrepareMagicLinkConsumption(nilContextForTest(), identity.CommandBinding{}, "", "", capability.Proof{}, [32]byte{}, 0); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("zero composition admitted")
	}
}
