package identitycapability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

func preparationFixture(t testing.TB, i *Issuer, c IssuerConfig) (*IssuancePreparationCodec, IssuancePreparationConfig) {
	t.Helper()
	config := IssuancePreparationConfig{Deployment: "test", ActiveEnvelopeKey: "envelope-v1", EnvelopeKeys: map[string][]byte{"envelope-v1": make([]byte, 32)}, VerificationKeys: []PreparationVerificationKey{{ID: "signing-v1", HMAC: []byte("0123456789abcdef0123456789abcdef")}}, Clock: c.Crypto.Clock}
	config.EnvelopeKeys["envelope-v1"][0] = 7
	codec, err := NewIssuancePreparationCodec(i, config)
	if err != nil {
		t.Fatal(err)
	}
	return codec, config
}

func TestIssuancePreparationFrozenAnonymousBatch(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	b = registrationIssuerBinding(b)
	v.Subject = "registered-user"
	inputs := make([]capability.Payload, 16)
	for n := range inputs {
		inputs[n] = v
	}
	p, err := i.PrepareRegistration(context.Background(), b, "registered-user", inputs)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, _ := preparationFixture(t, i, c)
	var borrowed []byte
	count := 0
	wire, err := codec.CheckpointPreparation(context.Background(), p, 7, func(_ context.Context, n uint16, token []byte) error {
		count++
		borrowed = token
		if sha256.Sum256(token) != plan.Grants[n].ProofFingerprint {
			t.Fatal("reordered original")
		}
		return nil
	})
	if err != nil || count != 16 {
		t.Fatal("batch", err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed bearer retained")
	}
	copyWire, err := codec.CheckpointPreparation(context.Background(), p, 7, func(context.Context, uint16, []byte) error { t.Fatal("repeat disclosure"); return nil })
	if err != nil || !bytes.Equal(wire, copyWire) {
		t.Fatal("checkpoint changed", err)
	}
	copyWire[0] ^= 1
	if _, err := codec.CheckpointPreparation(context.Background(), p, 8, nil); err == nil {
		t.Fatal("generation rebound")
	}
	out, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil {
		t.Fatal(err)
	}
	if out.state.binding.UserID != "" || out.state.plan.RegistrationUserID != "registered-user" || len(out.state.grants) != 16 {
		t.Fatal("anonymous command retargeted")
	}
	for n, g := range out.state.grants {
		if g.Payload().Subject != "registered-user" || g.EnvelopeDigest() != plan.Grants[n].ProofFingerprint {
			t.Fatal("original authority changed")
		}
	}
	plan.Grants[0].ReplayDigest = [32]byte{}
	got, _ := out.Plan()
	if got.Grants[0].ReplayDigest == ([32]byte{}) {
		t.Fatal("aliased declaration")
	}
	if i.Stage(context.Background(), identitypostgres.Work{}, out) == nil {
		t.Fatal("fabricated Work")
	}
}

func TestIssuancePreparationAuthenticatesEveryBindingAndPlanField(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, _ := preparationFixture(t, i, c)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < reflect.TypeOf(b).NumField(); n++ {
		t.Run(reflect.TypeOf(b).Field(n).Name, func(t *testing.T) {
			changed := b
			field := reflect.ValueOf(&changed).Elem().Field(n)
			switch field.Kind() {
			case reflect.String:
				field.SetString(field.String() + "x")
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			default:
				t.Fatalf("uncovered binding kind %v", field.Kind())
			}
			if out, err := codec.RestorePreparation(context.Background(), changed, 1, plan, wire); err == nil || out.state != nil {
				t.Fatal("foreign binding restored")
			}
		})
	}
	for _, change := range []func(*identitypostgres.CapabilityIssuancePlan){
		func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = "foreign" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Contributor.Version++ },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].CapabilityID += "x" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.identifier.attach" },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].ReplayKeyVersion = 1 },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].ReplayDigest[0] ^= 1 },
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].ProofFingerprint[0] ^= 1 },
		func(p *identitypostgres.CapabilityIssuancePlan) {
			p.Grants[0].ExpiresAt = p.Grants[0].ExpiresAt.Add(time.Second)
		},
		func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].MaxUses++ },
	} {
		changed := plan
		changed.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
		change(&changed)
		if out, err := codec.RestorePreparation(context.Background(), b, 1, changed, wire); err == nil || out.state != nil {
			t.Fatal("foreign metadata restored")
		}
	}
	if _, err := codec.RestorePreparation(context.Background(), b, 2, plan, wire); err == nil {
		t.Fatal("foreign generation")
	}
}

func TestIssuancePreparationRotationAndLocalOnlyVerification(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, config := preparationFixture(t, i, c)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.CurrentReplayKeyVersion = 3
	c.RetainedReplayKeys[3] = [32]byte{9}
	c.Crypto.Resolver = capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		t.Fatal("remote issuer resolver invoked")
		return capability.ResolvedKey{Issuer: "https://identity.example.test"}, errors.New("unavailable")
	})
	fresh, err := NewIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	config.ActiveEnvelopeKey = "envelope-v2"
	config.EnvelopeKeys["envelope-v2"] = bytes.Repeat([]byte{8}, 32)
	restarted, err := NewIssuancePreparationCodec(fresh, config)
	if err != nil {
		t.Fatal(err)
	}
	out, err := restarted.RestorePreparation(context.Background(), b, 1, plan, wire)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := out.Plan()
	if !reflect.DeepEqual(got, plan) {
		t.Fatal("rotation rewrote original")
	}
	delete(config.EnvelopeKeys, "envelope-v1")
	missing, _ := NewIssuancePreparationCodec(fresh, config)
	if _, err := missing.RestorePreparation(context.Background(), b, 1, plan, wire); err == nil {
		t.Fatal("missing key fallback")
	}
	config.EnvelopeKeys["envelope-v1"] = bytes.Repeat([]byte{8}, 32)
	wrong, _ := NewIssuancePreparationCodec(fresh, config)
	if _, err := wrong.RestorePreparation(context.Background(), b, 1, plan, wire); err == nil {
		t.Fatal("wrong key accepted")
	}
	// The existing immutable codec copied configuration material before rotation.
	if _, err := codec.RestorePreparation(context.Background(), b, 1, plan, wire); err != nil {
		t.Fatal("caller mutated retained keys", err)
	}
	config.EnvelopeKeys["envelope-v1"] = make([]byte, 32)
	config.EnvelopeKeys["envelope-v1"][0] = 7
	config.Clock = func() time.Time { return v.ExpiresAt }
	expired, _ := NewIssuancePreparationCodec(fresh, config)
	if _, err := expired.RestorePreparation(context.Background(), b, 1, plan, wire); err == nil {
		t.Fatal("expiry renewed")
	}
}

func TestIssuancePreparationFailureDestroysAllTransferCustody(t *testing.T) {
	for _, kind := range []string{"error", "panic", "cancel", "already-transferred"} {
		t.Run(kind, func(t *testing.T) {
			i, c, b, v := issuerFixture(t)
			p, err := i.Prepare(context.Background(), b, []capability.Payload{v, v})
			if err != nil {
				t.Fatal(err)
			}
			codec, _ := preparationFixture(t, i, c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "already-transferred" {
				_ = p.TransferForDelivery(ctx, 0, func(context.Context, []byte) error { return nil })
			}
			var borrowed []byte
			wire, err := codec.CheckpointPreparation(ctx, p, 1, func(_ context.Context, _ uint16, token []byte) error {
				borrowed = token
				if kind == "panic" {
					panic("secret diagnostic")
				}
				if kind == "cancel" {
					cancel()
					return nil
				}
				return errors.New("secret diagnostic")
			})
			if err == nil || wire != nil || strings.Contains(fmt.Sprint(err), "secret diagnostic") {
				t.Fatal("failed custody usable or diagnostic leaked")
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("borrowed bytes retained")
			}
			if _, err := p.Plan(); err == nil {
				t.Fatal("failed batch still usable")
			}
			for n := uint16(0); n < 2; n++ {
				if p.TransferForDelivery(context.Background(), n, func(context.Context, []byte) error { t.Fatal("failed transfer reopened"); return nil }) == nil {
					t.Fatal("reopened")
				}
			}
		})
	}
}

func TestIssuancePreparationRetainedVerificationPolicy(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, config := preparationFixture(t, i, c)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing-signing-key", "wrong-signing-key", "disabled", "revoked", "not-active", "missing-replay-key", "deployment", "audience", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			copyConfig := config
			copyConfig.VerificationKeys = append([]PreparationVerificationKey(nil), config.VerificationKeys...)
			copyIssuer := c
			switch kind {
			case "missing-signing-key":
				copyConfig.VerificationKeys[0].ID = "signing-v2"
			case "wrong-signing-key":
				copyConfig.VerificationKeys[0].HMAC = bytes.Repeat([]byte{6}, 32)
			case "disabled":
				copyConfig.VerificationKeys[0].Disabled = true
			case "revoked":
				copyConfig.VerificationKeys[0].Revoked = true
			case "not-active":
				copyConfig.VerificationKeys[0].NotBefore = v.ExpiresAt
			case "missing-replay-key":
				copyIssuer.CurrentReplayKeyVersion = 1
				copyIssuer.RetainedReplayKeys = map[uint32][32]byte{1: {1}}
			case "deployment":
				copyConfig.Deployment = "another-deployment"
			case "audience":
				copyIssuer.Audience = "another-audience"
			case "expiry":
				copyConfig.Clock = func() time.Time { return v.ExpiresAt }
			}
			fresh, err := NewIssuer(copyIssuer)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewIssuancePreparationCodec(fresh, copyConfig)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := restarted.RestorePreparation(context.Background(), b, 1, plan, wire); err == nil || out.state != nil {
				t.Fatal("unavailable or foreign authority accepted")
			}
		})
	}
}

func TestIssuancePreparationUsesLocalEd25519(t *testing.T) {
	_, c, b, v := issuerFixture(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	signer, err := capability.NewEd25519Signer("ed-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewEd25519Verifier(public)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "ed-v1", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	c.Crypto.Signer = signer
	c.Crypto.Resolver = keys
	i, err := NewIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	_, config := preparationFixture(t, i, c)
	config.VerificationKeys = []PreparationVerificationKey{{ID: "ed-v1", Ed25519: public}}
	codec, err := NewIssuancePreparationCodec(i, config)
	if err != nil {
		t.Fatal(err)
	}
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	wire, err := codec.CheckpointPreparation(context.Background(), p, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := codec.RestorePreparation(context.Background(), b, 1, plan, wire); err != nil || out.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint {
		t.Fatal("Ed25519 original not restored", err)
	}
}

func TestIssuancePreparationRejectsInvalidLocalConfiguration(t *testing.T) {
	i, c, _, _ := issuerFixture(t)
	_, original := preparationFixture(t, i, c)
	for _, change := range []func(*IssuancePreparationConfig){
		func(c *IssuancePreparationConfig) { c.Clock = nil },
		func(c *IssuancePreparationConfig) { c.Deployment = "" },
		func(c *IssuancePreparationConfig) { c.ActiveEnvelopeKey = "missing" },
		func(c *IssuancePreparationConfig) { c.EnvelopeKeys = nil },
		func(c *IssuancePreparationConfig) {
			c.EnvelopeKeys = map[string][]byte{"envelope-v1": make([]byte, 32)}
		},
		func(c *IssuancePreparationConfig) { c.EnvelopeKeys = map[string][]byte{"envelope-v1": {1}} },
		func(c *IssuancePreparationConfig) { c.VerificationKeys = nil },
		func(c *IssuancePreparationConfig) {
			c.VerificationKeys = append(c.VerificationKeys, c.VerificationKeys[0])
		},
		func(c *IssuancePreparationConfig) {
			c.VerificationKeys = []PreparationVerificationKey{{ID: "both", HMAC: bytes.Repeat([]byte{4}, 32), Ed25519: bytes.Repeat([]byte{5}, 32)}}
		},
		func(c *IssuancePreparationConfig) {
			c.VerificationKeys = []PreparationVerificationKey{{ID: "zero", HMAC: make([]byte, 32)}}
		},
	} {
		config := original
		change(&config)
		if _, err := NewIssuancePreparationCodec(i, config); err == nil {
			t.Fatal("invalid local policy accepted")
		}
	}
}

func TestIssuancePreparationRejectsMalformedAuthenticatedRecords(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, _ := preparationFixture(t, i, c)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 1
	for _, record := range [][]byte{nil, wire[:len(wire)-1], append(append([]byte(nil), wire...), 0), bad, make([]byte, maximumIssuancePreparation+1)} {
		if out, err := codec.RestorePreparation(context.Background(), b, 1, plan, record); err == nil || out.state != nil {
			t.Fatal("malformed ciphertext accepted")
		}
	}
	aad, err := codec.preparationContext(b, 1, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{{0}, {0, 0}, {0, 17}, {0, 1}, {0, 1, 0, 0, 0, 2, 255, 255, 255, 255}} {
		env, err := codec.envelopes.Encrypt(context.Background(), secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: codec.active, Context: aad})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := env.MarshalBinary()
		if out, err := codec.RestorePreparation(context.Background(), b, 1, plan, append([]byte(issuancePreparationHeader), encoded...)); err == nil || out.state != nil {
			t.Fatal("malformed authenticated plaintext accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := codec.RestorePreparation(ctx, b, 1, plan, wire); !errors.As(err, new(identity.CancelledError)) {
		t.Fatal("cancellation lost", err)
	}
	for _, value := range []any{codec, PreparationVerificationKey{HMAC: []byte("secret diagnostic")}, IssuancePreparationConfig{ActiveEnvelopeKey: "secret diagnostic"}} {
		if strings.Contains(fmt.Sprintf("%#v", value), "secret diagnostic") {
			t.Fatal("format leak")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("automatic serialization")
		}
	}
}

func FuzzIssuancePreparationRestoration(f *testing.F) {
	i, c, b, v := issuerFixture(f)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		f.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, _ := preparationFixture(f, i, c)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 1, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(issuancePreparationHeader))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maximumIssuancePreparation+1 {
			t.Skip()
		}
		out, err := codec.RestorePreparation(context.Background(), b, 1, plan, wire)
		if err != nil {
			if out.state != nil {
				t.Fatal("partial custody")
			}
			return
		}
		got, _ := out.Plan()
		if !reflect.DeepEqual(got, plan) || len(out.state.grants) != 1 {
			t.Fatal("restored metadata mismatch")
		}
		if out.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("fuzz restoration reopened proof"); return nil }) == nil {
			t.Fatal("restoration reveals")
		}
	})
}

func TestIssuancePreparationRestoresWithoutReopeningDelivery(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	codec, config := preparationFixture(t, i, c)
	var original [32]byte
	wire, err := codec.CheckpointPreparation(context.Background(), p, 3, func(_ context.Context, _ uint16, token []byte) error { original = sha256.Sum256(token); return nil })
	if err != nil {
		t.Fatal("original issuance has no durable checkpoint", err)
	}
	if original != plan.Grants[0].ProofFingerprint {
		t.Fatal("replacement envelope")
	}
	fresh, err := NewIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewIssuancePreparationCodec(fresh, config)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restarted.RestorePreparation(context.Background(), b, 3, plan, wire)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := restored.Plan()
	if !reflect.DeepEqual(plan, got) {
		t.Fatal("original metadata changed")
	}
	for _, alias := range []PreparedIssuance{p, restored} {
		if alias.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("reopened delivery"); return nil }) == nil {
			t.Fatal("transfer reopened")
		}
	}
}
