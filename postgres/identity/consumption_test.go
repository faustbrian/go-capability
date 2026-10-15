package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func identifierConsumptionFixture(t testing.TB) (*Issuer, identity.Command, capability.Proof) {
	t.Helper()
	i, c, b, _ := issuerFixture(t)
	b.ActorID, b.ActorKind = "user", authorization.SubjectUser
	b.OperationID, b.PolicyID, b.PolicyVersion = "identity.identifier.verify", "identity", 1
	b.SchemaID, b.SchemaVersion, b.RecordID = "identity-identifier", 1, "identifier"
	b.CorrelationID = string(b.CommandID)
	spec := identity.IdentifierCommand{Binding: b, SessionID: "session", SessionVersion: 1, Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: "identifier", Action: identity.IdentifierVerify, ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}}
	now := c.Crypto.Clock()
	p, err := identity.BuildIdentifierProofPayload(identity.IdentifierProofSpec{Command: spec, Issuer: "https://identity.example.test", Audience: c.Audience, ID: "proof", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal("build unsigned intent", err)
	}
	proof, _, err := i.service.Issue(context.Background(), p)
	if err != nil {
		t.Fatal("issue fixture", err)
	}
	spec.Proof, err = i.service.Verify(context.Background(), proof, capability.Purpose(b.OperationID), c.Audience)
	if err != nil {
		t.Fatal("verify fixture", err)
	}
	command, err := identity.NewIdentifierCommand(spec)
	if err != nil {
		t.Fatal("build command", err)
	}
	return i, command, proof
}

func TestPrepareIdentifierConsumptionRejectsSubstitutionAndInvalidCustody(t *testing.T) {
	i, command, proof := identifierConsumptionFixture(t)
	_, _, foreign := identifierConsumptionFixture(t)
	for name, p := range map[string]capability.Proof{"zero": {}, "another-command": foreign} {
		t.Run(name, func(t *testing.T) {
			out, err := i.PrepareIdentifierConsumption(context.Background(), command, p, 1)
			var denied identity.ForbiddenError
			if !errors.As(err, &denied) || out.ReplayDigest != ([32]byte{}) {
				t.Fatal("substitution admitted", err)
			}
		})
	}
	for _, version := range []uint32{0, 3} {
		if _, err := i.PrepareIdentifierConsumption(context.Background(), command, proof, version); err == nil {
			t.Fatal("unretained version accepted")
		}
	}
	if _, err := i.PrepareIdentifierConsumption(context.Background(), identity.Command{}, proof, 1); err == nil {
		t.Fatal("zero command accepted")
	}
	if _, err := i.PrepareIdentifierConsumption(nilContextForTest(), command, proof, 1); err == nil {
		t.Fatal("nil context accepted")
	}
	var zero *Issuer
	if _, err := zero.PrepareIdentifierConsumption(context.Background(), command, proof, 1); err == nil {
		t.Fatal("nil issuer accepted")
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := i.PrepareIdentifierConsumption(cancelCtx, command, proof, 1)
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) {
		t.Fatal("cancellation lost", err)
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := i.PrepareIdentifierConsumption(context.Background(), command, proof, 1); err == nil {
		t.Fatal("transferred proof admitted")
	}
}

func TestPrepareIdentifierConsumptionRechecksConfiguredAuthority(t *testing.T) {
	_, command, proof := identifierConsumptionFixture(t)
	for _, name := range []string{"foreign-key", "expired", "revoked", "unavailable", "zero-clock", "panic", "deadline"} {
		t.Run(name, func(t *testing.T) {
			_, config, _, _ := issuerFixture(t)
			switch name {
			case "zero-clock":
				config.Crypto.Clock = func() time.Time { return time.Time{} }
			case "foreign-key":
				verifier, err := capability.NewHMACSHA256Verifier([]byte("different-key-01234567890123456789"))
				if err != nil {
					t.Fatal(err)
				}
				config.Crypto.Resolver, err = capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: verifier}})
				if err != nil {
					t.Fatal(err)
				}
			case "expired":
				spec, _ := command.ChangeIdentifier()
				config.Crypto.Clock = func() time.Time { return spec.Proof.Payload().ExpiresAt }
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private failure")
				})
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
			out, err := i.PrepareIdentifierConsumption(ctx, command, proof, 1)
			if err == nil || out.ReplayDigest != ([32]byte{}) {
				t.Fatal("authority failure admitted")
			}
			var forbidden identity.ForbiddenError
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
				if !errors.As(err, &forbidden) {
					t.Fatal("denial classification lost", err)
				}
			}
		})
	}
}

func TestPrepareIdentifierConsumptionOwnsRetainedReplayDerivation(t *testing.T) {
	i, command, proof := identifierConsumptionFixture(t)
	plan, err := i.PrepareIdentifierConsumption(context.Background(), command, proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := command.ChangeIdentifier()
	payload, envelope := spec.Proof.Payload(), spec.Proof.EnvelopeDigest()
	key := [32]byte{1}
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
	if plan.ReplayKeyVersion != 1 || plan.ReplayDigest != expected || plan.ProofFingerprint != envelope || plan.CapabilityID != payload.ID || plan.ExpiresAt != payload.ExpiresAt || plan.MaxUses != 1 || plan.Purpose != capability.Purpose(payload.Operation) {
		t.Fatal("original metadata changed")
	}
	again, err := i.PrepareIdentifierConsumption(context.Background(), command, proof, 1)
	if err != nil || again != plan {
		t.Fatal("read-only preparation not repeatable", err)
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != envelope {
			t.Fatal("envelope replaced")
		}
		return nil
	}); err != nil {
		t.Fatal("preparation consumed custody", err)
	}
}
