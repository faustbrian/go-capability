package identitycapability

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type mfaConsumptionPreparer interface {
	PrepareMFAConsumption(context.Context, identity.CommandBinding, identity.UserID, identity.CommandID, [32]byte, string, capability.Proof, [32]byte, uint32) (kernel.CapabilityPlan, error)
}

func mfaConsumptionFixture(t *testing.T) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload, [32]byte) {
	t.Helper()
	i, config, b, p := issuerFixture(t)
	b = magicLinkIssuerBinding(b)
	b.OperationID, b.SchemaID = "identity.mfa.totp-verify", "mfa-totp-verify"
	p.ID, p.Subject, p.Operation = "AQEBAQEBAQEBAQEBAQEBAQ", "existing-user", "identity.mfa.complete"
	p.Resource = "mfa/continuations/" + p.ID
	p.IssuedAt, p.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	digest := [32]byte{7}
	p.Caveats = map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": hex.EncodeToString(digest[:])}
	return i, config, b, p, digest
}

func TestPrepareMFAConsumptionPreservesOriginalChild(t *testing.T) {
	i, config, b, p, scope := mfaConsumptionFixture(t)
	origin := b
	origin.OperationID, origin.SchemaID = "identity.magic-link.consume", "magic-link-consume"
	prepared, err := i.PrepareMFAContinuation(context.Background(), origin, p)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	grant, err := i.service.Verify(context.Background(), proof, "identity.mfa.complete", config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := any(i).(mfaConsumptionPreparer)
	if !ok {
		t.Fatal("native MFA child consumption preparation is missing")
	}
	for _, method := range []string{"totp-verify", "otp-verify", "recovery-use", "security-key-assert-verify"} {
		binding := b
		binding.OperationID = "identity.mfa." + method
		binding.SchemaID = "mfa-" + method
		plan, err := reader.PrepareMFAConsumption(context.Background(), binding, "existing-user", identity.CommandID(p.ID), scope, p.Issuer, proof, grant.EnvelopeDigest(), 2)
		if err != nil || plan != issued.Grants[0] || plan.Purpose != "identity.mfa.complete" || plan.ProofFingerprint != grant.EnvelopeDigest() {
			t.Fatal("original MFA child was replaced", method, err)
		}
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reader.PrepareMFAConsumption(context.Background(), b, "existing-user", identity.CommandID(p.ID), scope, p.Issuer, proof, grant.EnvelopeDigest(), 2)
	if err != nil {
		t.Fatal(err)
	}
	rotatedReader := any(rotated).(mfaConsumptionPreparer)
	again, err := rotatedReader.PrepareMFAConsumption(context.Background(), b, "existing-user", identity.CommandID(p.ID), scope, p.Issuer, proof, grant.EnvelopeDigest(), 2)
	if err != nil || again != plan {
		t.Fatal("rotation replaced original replay identity", err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding, *identity.UserID, *identity.CommandID, *[32]byte, *string, *[32]byte, *uint32){
		"tenant": func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			b.TenantID = "foreign"
		},
		"authenticated subject": func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			b.UserID = "existing-user"
		},
		"flow absent": func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			b.AnonymousFlowID = ""
		},
		"operation": func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			b.OperationID = "identity.magic-link.consume"
			b.SchemaID = "magic-link-consume"
		},
		"schema": func(b *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			b.SchemaVersion++
		},
		"subject": func(_ *identity.CommandBinding, u *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			*u = "foreign"
		},
		"child": func(_ *identity.CommandBinding, _ *identity.UserID, id *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			*id = "AgICAgICAgICAgICAgICAg"
		},
		"scope": func(_ *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, d *[32]byte, _ *string, _ *[32]byte, _ *uint32) {
			d[0]++
		},
		"issuer": func(_ *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, s *string, _ *[32]byte, _ *uint32) {
			*s = "https://foreign.test"
		},
		"envelope": func(_ *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, e *[32]byte, _ *uint32) {
			e[0]++
		},
		"replay key": func(_ *identity.CommandBinding, _ *identity.UserID, _ *identity.CommandID, _ *[32]byte, _ *string, _ *[32]byte, v *uint32) {
			*v = 3
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding, user, id, digest, issuer, envelope, version := b, identity.UserID("existing-user"), identity.CommandID(p.ID), scope, p.Issuer, grant.EnvelopeDigest(), uint32(2)
			mutate(&binding, &user, &id, &digest, &issuer, &envelope, &version)
			if out, e := reader.PrepareMFAConsumption(context.Background(), binding, user, id, digest, issuer, proof, envelope, version); e == nil || out != (kernel.CapabilityPlan{}) {
				t.Fatal("foreign MFA consumption admitted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, e := reader.PrepareMFAConsumption(ctx, b, "existing-user", identity.CommandID(p.ID), scope, p.Issuer, proof, grant.EnvelopeDigest(), 2); e == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("cancelled call retained plan")
	}
	if err = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("preparation consumed custody", err)
	}
	if out, e := reader.PrepareMFAConsumption(context.Background(), b, "existing-user", identity.CommandID(p.ID), scope, p.Issuer, proof, grant.EnvelopeDigest(), 2); e == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("terminal proof regained custody")
	}
}

func TestPrepareMFAConsumptionRejectsSignedForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"foreign tenant":       func(p *capability.Payload) { p.Tenant = "foreign" },
		"foreign recipient":    func(p *capability.Payload) { p.Subject = "foreign" },
		"foreign issuer":       func(p *capability.Payload) { p.Issuer = "https://foreign.test" },
		"foreign resource":     func(p *capability.Payload) { p.Resource = "session/continuations/" + p.ID },
		"foreign profile":      func(p *capability.Payload) { p.Caveats["mfa.profile"] = "other" },
		"extra caveat":         func(p *capability.Payload) { p.Caveats["other"] = "unbound" },
		"missing scope":        func(p *capability.Payload) { delete(p.Caveats, "mfa.scope") },
		"zero scope":           func(p *capability.Payload) { p.Caveats["mfa.scope"] = hex.EncodeToString(make([]byte, 32)) },
		"foreign purpose":      func(p *capability.Payload) { p.Operation = "identity.magic-link.consume" },
		"multiple audiences":   func(p *capability.Payload) { p.Audiences = []string{"identity", "other"} },
		"multiple uses":        func(p *capability.Payload) { p.MaxUses = 2 },
		"reusable":             func(p *capability.Payload) { p.MaxUses = 0 },
		"bearer":               func(p *capability.Payload) { p.Subject = ""; p.Bearer = true },
		"extended expiry":      func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
		"different not-before": func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			i, config, b, p, scope := mfaConsumptionFixture(t)
			mutate(&p)
			fixtureService := i.service
			if name == "foreign issuer" {
				// Authenticate a genuine foreign-owned grant independently;
				// the consumer still uses its original configured issuer.
				config.Crypto.Issuer = p.Issuer
				original := config.Crypto.Resolver
				config.Crypto.Resolver = capability.ResolverFunc(func(ctx context.Context, id string, algorithm capability.Algorithm) (capability.ResolvedKey, error) {
					key, err := original.Resolve(ctx, id, algorithm)
					key.Issuer = p.Issuer
					return key, err
				})
				var err error
				fixtureService, err = capability.NewService(config.Crypto)
				if err != nil {
					t.Fatal(err)
				}
			}
			proof, _, err := fixtureService.Issue(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			// Use the real envelope digest, not a mismatched-envelope shortcut.
			grant, err := fixtureService.Verify(context.Background(), proof, capability.Purpose(p.Operation), "identity")
			if err != nil {
				t.Fatal(err)
			}
			original := grant.EnvelopeDigest()
			if out, e := i.PrepareMFAConsumption(context.Background(), b, "existing-user", "AQEBAQEBAQEBAQEBAQEBAQ", scope, "https://identity.example.test", proof, original, 1); e == nil || out != (kernel.CapabilityPlan{}) {
				t.Fatal("signed foreign profile admitted")
			}
		})
	}
}

func TestPrepareMFAConsumptionVerificationFailuresRemainClosed(t *testing.T) {
	for _, mode := range []string{"expired", "revoked", "unavailable", "panic", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			i, config, b, p, scope := mfaConsumptionFixture(t)
			proof, _, err := i.service.Issue(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			grant, err := i.service.Verify(context.Background(), proof, "identity.mfa.complete", "identity")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "expired":
				config.Crypto.Clock = func() time.Time { return p.ExpiresAt }
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private detail")
				})
			case "panic":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private detail") })
			case "deadline":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			}
			i, err = NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			out, err := i.PrepareMFAConsumption(ctx, b, "existing-user", identity.CommandID(p.ID), scope, p.Issuer, proof, grant.EnvelopeDigest(), 1)
			if err == nil || out != (kernel.CapabilityPlan{}) {
				t.Fatal("verification failure produced plan")
			}
			var denied identity.ForbiddenError
			var unavailable identity.UnavailableError
			var deadline identity.DeadlineExceededError
			switch mode {
			case "unavailable", "panic":
				if !errors.As(err, &unavailable) {
					t.Fatal("availability classification lost", err)
				}
			case "deadline":
				if !errors.As(err, &deadline) {
					t.Fatal("deadline classification lost", err)
				}
			default:
				if !errors.As(err, &denied) {
					t.Fatal("denial classification lost", err)
				}
			}
		})
	}
}
