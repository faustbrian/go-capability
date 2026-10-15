package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type privacyConsumptionPreparer interface {
	PreparePrivacyExportConsumption(context.Context, identity.Command, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func preparePrivacyConsumption(t *testing.T, i *Issuer, ctx context.Context, command identity.Command, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	p, ok := any(i).(privacyConsumptionPreparer)
	if !ok {
		t.Fatal("native privacy consumption preparation is missing")
	}
	return p.PreparePrivacyExportConsumption(ctx, command, proof, version)
}

func privacyConsumptionFixture(t *testing.T) (*Issuer, IssuerConfig, identity.Command, capability.Proof) {
	t.Helper()
	i, config, b, _ := issuerFixture(t)
	const scope = "AQEBAQEBAQEBAQEBAQEBAQ"
	b.TenantID, b.UserID, b.ActorID, b.ActorKind = scope, scope, scope, authorization.SubjectUser
	b.OperationID, b.PolicyID, b.PolicyVersion = "identity.privacy-export.request", "privacy", 1
	b.SchemaID, b.SchemaVersion, b.CorrelationID = "identity-privacy-export", 1, string(b.CommandID)
	c := identity.PrivacyExportRequestCommand{Binding: b, SessionID: "session", SessionVersion: 1, ExpectedIdentityVersion: 3, ExpectedAuthorityVersion: 4, ExpectedPrivacyEpoch: 5, MaximumBytes: 256 << 20, ArtifactTTL: 24 * time.Hour}
	for _, id := range identity.PrivacyExportContributorsV1() {
		c.Projections = append(c.Projections, identity.PrivacyExportProjectionSpecV1{ContributorID: id, ProjectionID: identity.PrivacyExportSubjectJournalV1})
	}
	now := config.Crypto.Clock()
	payload, err := identity.BuildPrivacyExportProofPayload(identity.PrivacyExportProofSpec{Command: c, Issuer: "https://identity.example.test", Audience: config.Audience, ID: "privacy-proof", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	c.Proof, err = i.service.Verify(context.Background(), proof, capability.Purpose(b.OperationID), config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewPrivacyExportRequestCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	return i, config, command, proof
}

func TestPreparePrivacyConsumptionOwnsOriginalReplay(t *testing.T) {
	i, config, command, proof := privacyConsumptionFixture(t)
	plan, err := preparePrivacyConsumption(t, i, context.Background(), command, proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := command.RequestPrivacyExport()
	envelope, payload := c.Proof.EnvelopeDigest(), c.Proof.Payload()
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
	if plan.ReplayDigest != expected || plan.ProofFingerprint != envelope || plan.ReplayKeyVersion != 1 || plan.CapabilityID != payload.ID || plan.Purpose != capability.Purpose(payload.Operation) || plan.MaxUses != 1 || plan.ExpiresAt != payload.ExpiresAt {
		t.Fatal("original proof metadata changed")
	}
	again, err := preparePrivacyConsumption(t, i, context.Background(), command, proof, 1)
	if err != nil || again != plan {
		t.Fatal("repeat preparation changed original input", err)
	}
	// Rotation does not select a new default when the original version is given.
	rotatedConfig := config
	rotatedConfig.CurrentReplayKeyVersion = 3
	rotatedConfig.RetainedReplayKeys = map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(rotatedConfig)
	if err != nil {
		t.Fatal(err)
	}
	again, err = preparePrivacyConsumption(t, rotated, context.Background(), command, proof, 1)
	if err != nil || again != plan {
		t.Fatal("rotation renewed original metadata", err)
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != envelope {
			t.Fatal("proof was replaced")
		}
		return nil
	}); err != nil {
		t.Fatal("preparation consumed proof custody", err)
	}
}

func TestPreparePrivacyConsumptionRejectsInvalidCustody(t *testing.T) {
	i, _, command, proof := privacyConsumptionFixture(t)
	_, _, _, other := privacyConsumptionFixture(t)
	for name, p := range map[string]capability.Proof{"zero": {}, "other-intent": other} {
		t.Run(name, func(t *testing.T) {
			out, err := preparePrivacyConsumption(t, i, context.Background(), command, p, 1)
			var denied identity.ForbiddenError
			if !errors.As(err, &denied) || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("substitution admitted", err)
			}
		})
	}
	for _, version := range []uint32{0, 3} {
		if _, err := preparePrivacyConsumption(t, i, context.Background(), command, proof, version); err == nil {
			t.Fatal("unretained replay key accepted")
		}
	}
	_, identifier, _ := identifierConsumptionFixture(t)
	if _, err := i.PrepareIdentifierConsumption(context.Background(), command, proof, 1); err == nil {
		t.Fatal("privacy command entered identifier preparation")
	}
	for _, unsupported := range []identity.Command{{}, identifier} {
		if _, err := preparePrivacyConsumption(t, i, context.Background(), unsupported, proof, 1); err == nil {
			t.Fatal("incompatible command accepted")
		}
	}
	if _, err := preparePrivacyConsumption(t, i, nil, command, proof, 1); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := preparePrivacyConsumption(t, nil, context.Background(), command, proof, 1); err == nil {
		t.Fatal("nil issuer accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := preparePrivacyConsumption(t, i, ctx, command, proof, 1)
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) {
		t.Fatal("cancellation lost", err)
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := preparePrivacyConsumption(t, i, context.Background(), command, proof, 1); err == nil {
		t.Fatal("transferred proof accepted")
	}
}

func TestPreparePrivacyConsumptionRejectsAnotherTrustedEnvelope(t *testing.T) {
	_, config, command, proof := privacyConsumptionFixture(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, err := capability.NewHMACSHA256Verifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	config.Crypto.Resolver, err = capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: v}, {Issuer: "https://identity.example.test", ID: "signing-v2", Verifier: v}})
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	alternate := config.Crypto
	alternate.Signer, err = capability.NewHMACSHA256Signer("signing-v2", secret)
	if err != nil {
		t.Fatal(err)
	}
	s, err := capability.NewService(alternate)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := command.RequestPrivacyExport()
	other, _, err := s.Issue(context.Background(), c.Proof.Payload())
	if err != nil {
		t.Fatal(err)
	}
	// The alternative is genuinely trusted and valid, not a bad-signature case.
	grant, err := i.service.Verify(context.Background(), other, capability.Purpose(c.Binding.OperationID), config.Audience)
	if err != nil || grant.EnvelopeDigest() == c.Proof.EnvelopeDigest() {
		t.Fatal("fixture does not distinguish valid original custody", err)
	}
	out, err := preparePrivacyConsumption(t, i, context.Background(), command, other, 1)
	var denied identity.ForbiddenError
	if !errors.As(err, &denied) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("another trusted signature replaced original proof", err)
	}
	if _, err := preparePrivacyConsumption(t, i, context.Background(), command, proof, 1); err != nil {
		t.Fatal("denial destroyed original custody", err)
	}
}

func TestPreparePrivacyConsumptionRechecksConfiguredAuthority(t *testing.T) {
	_, original, command, proof := privacyConsumptionFixture(t)
	c, _ := command.RequestPrivacyExport()
	for _, name := range []string{"expired", "not-before", "audience", "signature", "revoked", "unavailable", "zero-clock", "panic", "deadline"} {
		t.Run(name, func(t *testing.T) {
			config := original
			switch name {
			case "expired":
				config.Crypto.Clock = func() time.Time { return c.Proof.Payload().ExpiresAt }
			case "not-before":
				config.Crypto.Clock = func() time.Time { return c.Proof.Payload().NotBefore.Add(-time.Second) }
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
					return false, errors.New("private failure")
				})
			case "zero-clock":
				config.Crypto.Clock = func() time.Time { return time.Time{} }
			case "panic":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private failure") })
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
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			out, err := preparePrivacyConsumption(t, i, ctx, command, proof, 1)
			if err == nil || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("failed verification returned consumption metadata")
			}
			var denied identity.ForbiddenError
			var unavailable identity.UnavailableError
			var deadline identity.DeadlineExceededError
			switch name {
			case "unavailable", "zero-clock", "panic":
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

func TestPreparePrivacyConsumptionConcurrentReadOnlyCustody(t *testing.T) {
	i, _, command, proof := privacyConsumptionFixture(t)
	p, ok := any(i).(privacyConsumptionPreparer)
	if !ok {
		t.Fatal("native privacy consumption preparation is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	want, err := p.PreparePrivacyExportConsumption(ctx, command, proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		plan identitypostgres.CapabilityPlan
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
			plan, err := p.PreparePrivacyExportConsumption(ctx, command, proof, 1)
			results <- result{plan, err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for got := range results {
		if got.err != nil || got.plan != want {
			t.Fatal("concurrent preparation changed original custody", got.err)
		}
	}
	if err := proof.Transfer(ctx, func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("concurrent preparation consumed custody", err)
	}
}
