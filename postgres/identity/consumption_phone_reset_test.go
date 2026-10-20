package identitycapability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

type phoneResetConsumptionPreparer interface {
	PreparePhonePasswordResetConsumption(context.Context, identity.Command, uint32) (kernel.CapabilityPlan, error)
}

func preparePhoneResetConsumption(t *testing.T, i *Issuer, ctx context.Context, command identity.Command, version uint32) (kernel.CapabilityPlan, error) {
	t.Helper()
	p, ok := any(i).(phoneResetConsumptionPreparer)
	if !ok {
		t.Fatal("native original phone reset consumption preparation is missing")
	}
	return p.PreparePhonePasswordResetConsumption(ctx, command, version)
}

// This fixture tests only cryptographic preparation of the sealed joint input.
// It does not establish phone possession, current factors or reset permission.
func phoneResetConsumptionFixture(t *testing.T, mutate func(*capability.Payload)) (*Issuer, IssuerConfig, identity.Command, identity.Command, capability.Proof, capability.Grant) {
	t.Helper()
	i, config, b, payload := issuerFixture(t)
	b.ActorID, b.ActorKind, b.RecordID = "user", authorization.SubjectUser, "password"
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.phone.password-reset-complete", "identity.phone.password-reset-complete.native-v1", 1
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "phone-reset", 1, string(b.CommandID)
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "native.scope", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic"}}}}
	payload.ID, payload.Resource, payload.Operation = "phone-reset-proof", "identity.password/password", b.OperationID
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
	secret, err := primitive.NewSecret([]byte("synthetic-phone-reset-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Destroy)
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	input, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, secret, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := identity.NewFeaturePhonePasswordResetCommand(spec, "$synthetic$phone-replacement", proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	input, err = identity.BindPhonePasswordResetPreAuth(input, cookie)
	if err != nil {
		t.Fatal(err)
	}
	generated, err = identity.BindPhonePasswordResetPreAuth(generated, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return i, config, input, generated, proof, grant
}

func TestPreparePhoneResetConsumptionPreservesOriginalJointCustodyAndReplay(t *testing.T) {
	i, config, input, generated, proof, grant := phoneResetConsumptionFixture(t, nil)
	plan, err := preparePhoneResetConsumption(t, i, context.Background(), input, 1)
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
	if plan.ReplayDigest != expected || plan.ProofFingerprint != envelope || plan.ReplayKeyVersion != 1 || plan.CapabilityID != payload.ID || plan.Purpose != "identity.phone.password-reset-complete" || plan.ExpiresAt != payload.ExpiresAt || plan.MaxUses != 1 {
		t.Fatal("original phone reset metadata changed")
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []identity.Command{input, generated} {
		for _, issuer := range []*Issuer{i, rotated} {
			if again, err := preparePhoneResetConsumption(t, issuer, context.Background(), c, 1); err != nil || again != plan {
				t.Fatal("preparation or rotation changed original replay or expiry", err)
			}
		}
		cookie, ok := c.PhonePasswordResetPreAuthCookie()
		if !ok || cookie.Token() == "" {
			t.Fatal("preparation lost original browser custody")
		}
		if _, ok := c.Feature(); ok {
			t.Fatal("joint phone reset downgraded to generic metadata")
		}
		if out, err := prepareResetConsumption(t, i, context.Background(), c, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("email reset admitted joint phone command")
		}
	}
	password, inputProof, sms, totp, ok := input.PhonePasswordResetInputCustody()
	if !ok || password.Use(func(raw []byte) error {
		if string(raw) != "synthetic-phone-reset-password" {
			t.Fatal("original password changed")
		}
		return nil
	}) != nil || inputProof.ValidateBounds(32, 4096) != nil {
		t.Fatal("preparation consumed original input custody")
	}
	hash, generatedProof, generatedSMS, generatedTOTP, ok := generated.PhonePasswordResetCustody()
	if !ok || hash != "$synthetic$phone-replacement" || generatedProof.ValidateBounds(32, 4096) != nil {
		t.Fatal("preparation consumed or changed generated custody")
	}
	for _, pair := range [][2]auth.OneTimeCode{{sms, generatedSMS}, {totp, generatedTOTP}} {
		want, _ := pair[0].CommandDigest([32]byte{1}, "test")
		got, err := pair[1].CommandDigest([32]byte{1}, "test")
		if err != nil || got != want {
			t.Fatal("original independent code custody changed")
		}
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != envelope {
			t.Fatal("preparation substituted original proof")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only preparation consumed proof", err)
	}
	for _, c := range []identity.Command{input, generated} {
		if out, err := preparePhoneResetConsumption(t, i, context.Background(), c, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("terminal shared proof alias admitted")
		}
	}
}

func TestPreparePhoneResetConsumptionRejectsForeignSignedScope(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":         func(p *capability.Payload) { p.Tenant = "foreign" },
		"subject":        func(p *capability.Payload) { p.Subject = "foreign" },
		"password":       func(p *capability.Payload) { p.Resource = "identity.password/foreign" },
		"phone-resource": func(p *capability.Payload) { p.Resource = "identity.phone/password" },
		"email-purpose":  func(p *capability.Payload) { p.Operation = "identity.password.reset-complete" },
		"bearer":         func(p *capability.Payload) { p.Bearer = true; p.Subject = "" },
		"uses":           func(p *capability.Payload) { p.MaxUses = 2 },
		"reusable":       func(p *capability.Payload) { p.MaxUses = 0 },
		"audiences":      func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
	} {
		t.Run(name, func(t *testing.T) {
			i, _, input, generated, _, _ := phoneResetConsumptionFixture(t, mutate)
			for _, c := range []identity.Command{input, generated} {
				out, err := preparePhoneResetConsumption(t, i, context.Background(), c, 1)
				var forbidden identity.ForbiddenError
				if !errors.As(err, &forbidden) || out != (kernel.CapabilityPlan{}) {
					t.Fatal("phone scope denial lost classification or returned metadata")
				}
			}
		})
	}
}

func TestPreparePhoneResetConsumptionRejectsUnsealedAndLegacyCommands(t *testing.T) {
	i, _, input, _, _, _ := phoneResetConsumptionFixture(t, nil)
	spec, _ := input.PhonePasswordResetInputFeature()
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	_, _, email, _, _ := resetConsumptionFixture(t, nil)
	for _, command := range []identity.Command{{}, plain, email} {
		out, err := preparePhoneResetConsumption(t, i, context.Background(), command, 1)
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || out != (kernel.CapabilityPlan{}) {
			t.Fatal("unsealed or email command acquired phone consumption")
		}
	}
	for _, version := range []uint32{0, 4} {
		if out, err := preparePhoneResetConsumption(t, i, context.Background(), input, version); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("unretained original replay key admitted")
		}
	}
	emailIssuer, _, emailWithPhoneGrant, _, _ := resetConsumptionFixture(t, func(p *capability.Payload) { p.Operation = "identity.phone.password-reset-complete" })
	if out, err := prepareResetConsumption(t, emailIssuer, context.Background(), emailWithPhoneGrant, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("email reset consumed a phone-purpose grant")
	}
	for _, pair := range []struct {
		issuer *Issuer
		ctx    context.Context
	}{{nil, context.Background()}, {i, nil}} {
		if out, err := preparePhoneResetConsumption(t, pair.issuer, pair.ctx, input, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("invalid composition admitted")
		}
	}
}

func TestPreparePhoneResetConsumptionRechecksOriginalAuthority(t *testing.T) {
	_, original, input, generated, _, grant := phoneResetConsumptionFixture(t, nil)
	for _, name := range []string{"expired", "not-before", "audience", "signature", "revoked", "unavailable", "panic", "cancelled", "deadline"} {
		t.Run(name, func(t *testing.T) {
			config := original
			ctx := context.Background()
			switch name {
			case "expired":
				config.Crypto.Clock = func() time.Time { return grant.Payload().ExpiresAt }
			case "not-before":
				config.Crypto.Clock = func() time.Time { return grant.Payload().NotBefore.Add(-time.Second) }
			case "audience":
				config.Audience = "other-audience"
			case "signature":
				verifier, _ := capability.NewHMACSHA256Verifier([]byte("different-key-01234567890123456789"))
				config.Crypto.Resolver, _ = capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: verifier}})
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("synthetic-private-detail")
				})
			case "panic":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("synthetic-private-detail") })
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "deadline":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Millisecond)
				defer cancel()
			}
			i, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []identity.Command{input, generated} {
				out, err := preparePhoneResetConsumption(t, i, ctx, c, 1)
				if err == nil || out != (kernel.CapabilityPlan{}) || strings.Contains(err.Error(), "synthetic-private-detail") {
					t.Fatal("failed original verification exposed metadata or diagnostics")
				}
				var unavailable identity.UnavailableError
				var deadline identity.DeadlineExceededError
				var cancelled identity.CancelledError
				var forbidden identity.ForbiddenError
				switch name {
				case "unavailable", "panic":
					if !errors.As(err, &unavailable) {
						t.Fatal("availability classification lost")
					}
				case "deadline":
					if !errors.As(err, &deadline) {
						t.Fatal("deadline classification lost")
					}
				case "cancelled":
					if !errors.As(err, &cancelled) {
						t.Fatal("cancellation classification lost")
					}
				default:
					if !errors.As(err, &forbidden) {
						t.Fatal("denial classification lost")
					}
				}
			}
		})
	}
}
