package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

type resetConsumptionPreparer interface {
	PreparePasswordResetConsumption(context.Context, identity.Command, uint32) (kernel.CapabilityPlan, error)
}

func prepareResetConsumption(t *testing.T, i *Issuer, ctx context.Context, c identity.Command, version uint32) (kernel.CapabilityPlan, error) {
	t.Helper()
	p, ok := any(i).(resetConsumptionPreparer)
	if !ok {
		t.Fatal("native original reset consumption preparation is missing")
	}
	return p.PreparePasswordResetConsumption(ctx, c, version)
}

func resetConsumptionFixture(t *testing.T, mutate func(*capability.Payload)) (*Issuer, IssuerConfig, identity.Command, capability.Proof, capability.Grant) {
	t.Helper()
	i, config, b, payload := issuerFixture(t)
	b.ActorID, b.ActorKind, b.RecordID = "user", authorization.SubjectUser, "password"
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.password.reset-complete", "password-reset-complete", 1
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "password", 1, string(b.CommandID)
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "native.scope", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic"}}}}
	payload.ID, payload.Resource, payload.Operation = "reset-proof", "identity.password/password", b.OperationID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	if mutate != nil {
		mutate(&payload)
	}
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal("synthetic issuance failed", err)
	}
	grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience)
	if err != nil {
		t.Fatal("synthetic verification failed", err)
	}
	command, err := identity.NewFeaturePasswordResetCommand(spec, "$synthetic$replacement", proof)
	if err != nil {
		t.Fatal(err)
	}
	return i, config, command, proof, grant
}

func TestPrepareResetConsumptionPreservesOriginalRetainedReplay(t *testing.T) {
	i, config, command, proof, grant := resetConsumptionFixture(t, nil)
	plan, err := prepareResetConsumption(t, i, context.Background(), command, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload, envelope := grant.Payload(), grant.EnvelopeDigest()
	key := config.RetainedReplayKeys[1]
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("golib/capability/identity-replay/v1\x00"))
	for _, field := range []string{payload.Tenant, payload.Operation} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		mac.Write(size[:])
		mac.Write([]byte(field))
	}
	mac.Write(envelope[:])
	var expected [32]byte
	copy(expected[:], mac.Sum(nil))
	if plan.ReplayDigest != expected || plan.ProofFingerprint != envelope || plan.ReplayKeyVersion != 1 || plan.CapabilityID != payload.ID || plan.Purpose != "identity.password.reset-complete" || plan.ExpiresAt != payload.ExpiresAt || plan.MaxUses != 1 {
		t.Fatal("original reset metadata changed")
	}
	for n := 0; n < 2; n++ {
		again, e := prepareResetConsumption(t, i, context.Background(), command, 1)
		if e != nil || again != plan {
			t.Fatal("read-only preparation changed original replay")
		}
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := prepareResetConsumption(t, rotated, context.Background(), command, 1); err != nil || again != plan {
		t.Fatal("rotation renewed original replay")
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != envelope {
			t.Fatal("preparation substituted original proof")
		}
		return nil
	}); err != nil {
		t.Fatal("preparation consumed custody", err)
	}
	if out, err := prepareResetConsumption(t, i, context.Background(), command, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("terminal shared proof alias admitted")
	}
}

// The original raw-input command must reserve the same signed credential
// before hashing. Requiring generated material here would force the workflow
// to hash before its authoritative preparation admission.
func TestPrepareResetConsumptionFromOriginalInput(t *testing.T) {
	i, _, generated, proof, _ := resetConsumptionFixture(t, nil)
	spec, _ := generated.PasswordResetFeature()
	secret, err := primitive.NewSecret([]byte("synthetic-new-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	input, err := identity.NewFeaturePasswordResetInputCommand(spec, secret, proof)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := prepareResetConsumption(t, i, context.Background(), generated, 1)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := prepareResetConsumption(t, i, context.Background(), input, 1)
	if err != nil || actual != expected {
		t.Fatal("original reset cannot reserve without generating a hash", err)
	}
	spec.Binding.RecordID = "foreign"
	foreign, err := identity.NewFeaturePasswordResetInputCommand(spec, secret, proof)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := prepareResetConsumption(t, i, context.Background(), foreign, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("original input bypassed signed credential scope")
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("read-only input preparation consumed original proof", err)
	}
	if out, err := prepareResetConsumption(t, i, context.Background(), input, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("terminal input proof admitted")
	}
}

func TestPrepareResetConsumptionRejectsScopeAndInvalidComposition(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":     func(p *capability.Payload) { p.Tenant = "foreign" },
		"subject":    func(p *capability.Payload) { p.Subject = "foreign" },
		"credential": func(p *capability.Payload) { p.Resource = "identity.password/foreign" },
		"purpose":    func(p *capability.Payload) { p.Operation = "identity.password.change" },
		"bearer":     func(p *capability.Payload) { p.Bearer = true; p.Subject = "" },
		"uses":       func(p *capability.Payload) { p.MaxUses = 2 },
		"reusable":   func(p *capability.Payload) { p.MaxUses = 0 },
		"audiences":  func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
	} {
		t.Run(name, func(t *testing.T) {
			i, _, c, _, _ := resetConsumptionFixture(t, mutate)
			out, err := prepareResetConsumption(t, i, context.Background(), c, 1)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || out != (kernel.CapabilityPlan{}) {
				t.Fatal("reset scope denial lost typed classification or returned metadata")
			}
		})
	}
	i, _, command, _, _ := resetConsumptionFixture(t, nil)
	for _, version := range []uint32{0, 4} {
		if out, err := prepareResetConsumption(t, i, context.Background(), command, version); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("unretained replay key admitted")
		}
	}
	spec, _ := command.PasswordResetFeature()
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []identity.Command{{}, plain} {
		if out, err := prepareResetConsumption(t, i, context.Background(), c, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("proof-free reset admitted")
		}
	}
	if out, err := prepareResetConsumption(t, nil, nil, command, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("zero composition admitted")
	}
	if out, err := prepareResetConsumption(t, nil, context.Background(), command, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("nil issuer admitted")
	}
	if out, err := prepareResetConsumption(t, i, nil, command, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := prepareResetConsumption(t, i, ctx, command, 1)
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) || out != (kernel.CapabilityPlan{}) {
		t.Fatal("cancelled preparation returned authority")
	}
}

func TestPrepareResetConsumptionRechecksConfiguredAuthority(t *testing.T) {
	_, original, command, _, grant := resetConsumptionFixture(t, nil)
	for _, name := range []string{"expired", "not-before", "audience", "signature", "revoked", "unavailable", "zero-clock", "panic", "deadline"} {
		t.Run(name, func(t *testing.T) {
			config := original
			switch name {
			case "expired":
				config.Crypto.Clock = func() time.Time { return grant.Payload().ExpiresAt }
			case "not-before":
				config.Crypto.Clock = func() time.Time { return grant.Payload().NotBefore.Add(-time.Second) }
			case "audience":
				config.Audience = "other-audience"
			case "signature":
				v, err := capability.NewHMACSHA256Verifier([]byte("different-key-01234567890123456789"))
				if err != nil {
					t.Fatal(err)
				}
				config.Crypto.Resolver, err = capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: v}})
				if err != nil {
					t.Fatal(err)
				}
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("synthetic-private-detail")
				})
			case "zero-clock":
				config.Crypto.Clock = func() time.Time { return time.Time{} }
			case "panic":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("synthetic-private-detail") })
			case "deadline":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			}
			i, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if name == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 10*time.Millisecond)
				defer stop()
			}
			out, err := prepareResetConsumption(t, i, ctx, command, 1)
			if err == nil || out != (kernel.CapabilityPlan{}) || strings.Contains(err.Error(), "synthetic-private-detail") {
				t.Fatal("failed verification exposed metadata or diagnostics")
			}
			var unavailable identity.UnavailableError
			var deadline identity.DeadlineExceededError
			var forbidden identity.ForbiddenError
			switch name {
			case "unavailable", "zero-clock", "panic":
				if !errors.As(err, &unavailable) {
					t.Fatal("availability classification lost")
				}
			case "deadline":
				if !errors.As(err, &deadline) {
					t.Fatal("deadline classification lost")
				}
			default:
				if !errors.As(err, &forbidden) {
					t.Fatal("invalid authority classification lost")
				}
			}
		})
	}
}

type resetNeverSigner struct{ capability.Signer }

func (resetNeverSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unexpected-reset-signing")
}

func TestPrepareResetConsumptionConcurrentReadOnlyCustody(t *testing.T) {
	_, config, command, proof, grant := resetConsumptionFixture(t, nil)
	// Construct the signed original before installing a signer that cannot sign.
	config.Crypto.Signer = resetNeverSigner{config.Crypto.Signer}
	i, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	want, err := prepareResetConsumption(t, i, ctx, command, 1)
	if err != nil {
		t.Fatal("read-only preparation attempted signing", err)
	}
	type result struct {
		plan kernel.CapabilityPlan
		err  error
	}
	results := make(chan result, 8)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range cap(results) {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			plan, err := i.PreparePasswordResetConsumption(ctx, command, 1)
			results <- result{plan, err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for got := range results {
		if got.err != nil || got.plan != want {
			t.Fatal("concurrent preparation changed original custody")
		}
	}
	if err := proof.Transfer(ctx, func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != grant.EnvelopeDigest() {
			t.Fatal("concurrent preparation replaced proof")
		}
		return nil
	}); err != nil {
		t.Fatal("concurrent preparation consumed proof")
	}
}
