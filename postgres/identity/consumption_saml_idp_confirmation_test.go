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
)

type samlIDPConfirmationConsumptionPreparer interface {
	PrepareSSOSAMLIDPConfirmationConsumption(context.Context, identity.CommandBinding, capability.Proof, [32]byte, uint32, time.Time) (kernel.CapabilityPlan, error)
}

func prepareSAMLIDPConfirmationConsumption(t testing.TB, i *Issuer, ctx context.Context, b identity.CommandBinding, proof capability.Proof, envelope [32]byte, version uint32, cutoff time.Time) (kernel.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(i).(samlIDPConfirmationConsumptionPreparer)
	if !ok {
		t.Fatal("original unsolicited SAML confirmation consumption preparation is missing")
	}
	return preparer.PrepareSSOSAMLIDPConfirmationConsumption(ctx, b, proof, envelope, version, cutoff)
}

func samlIDPConfirmationConsumptionFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload, time.Time) {
	t.Helper()
	i, config, b, p := issuerFixture(t)
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.sso.saml-idp-init", "sso-enterprise-saml-idp-init-v1", 1
	b.RecordID, b.ActorID, b.ActorKind = "pending-confirmation", "saml-adapter", authorization.SubjectServiceAccount
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "enterprise-saml", 1, "confirmation-correlation"
	p.ID, p.Resource, p.Operation, p.CorrelationID = "saml-confirmation-proof", b.RecordID, b.OperationID, b.CorrelationID
	p.IssuedAt, p.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	p.Caveats = map[string]string{"saml.intent": "original-provider-and-browser-intent"}
	return i, config, b, p, p.ExpiresAt.Add(time.Microsecond)
}

func TestPrepareSSOSAMLIDPConfirmationConsumptionPreservesOriginalGrant(t *testing.T) {
	i, config, b, payload, cutoff := samlIDPConfirmationConsumptionFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	envelope := grant.EnvelopeDigest()
	key := config.RetainedReplayKeys[1]
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("golib/capability/identity-replay/v1\x00"))
	for _, field := range []string{payload.Tenant, payload.Operation} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(field))
	}
	_, _ = mac.Write(envelope[:])
	var replay [32]byte
	copy(replay[:], mac.Sum(nil))
	want := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: capability.Purpose(payload.Operation), ReplayKeyVersion: 1, ReplayDigest: replay, ProofFingerprint: envelope, ExpiresAt: payload.ExpiresAt, MaxUses: 1}
	plan, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), b, proof, envelope, 1, cutoff)
	if err != nil || plan != want {
		t.Fatal("original envelope, expiry or retained replay identity changed", err)
	}
	config.CurrentReplayKeyVersion, config.RetainedReplayKeys = 3, map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	for range 8 {
		calls.Go(func() {
			got, err := prepareSAMLIDPConfirmationConsumption(t, rotated, context.Background(), b, proof, envelope, 1, cutoff)
			if err != nil || got != want {
				t.Error("rotation or overlapping preparation replaced original custody", err)
			}
		})
	}
	calls.Wait()
	if got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), b, proof, envelope, 1, payload.ExpiresAt); err != nil || got != want {
		t.Fatal("equal original cutoff denied or renewed expiry", err)
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != envelope {
			t.Error("original proof bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal("preparation consumed original proof custody", err)
	}
	if got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), b, proof, envelope, 1, cutoff); !errors.Is(err, identity.ForbiddenError{}) || got != (kernel.CapabilityPlan{}) {
		t.Fatal("transferred proof regained custody", err)
	}
}

func TestPrepareSSOSAMLIDPConfirmationConsumptionRejectsForeignBinding(t *testing.T) {
	i, config, b, payload, cutoff := samlIDPConfirmationConsumptionFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"SP-initiated profile": func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID = "identity.sso.saml-start", "identity.sso.saml-start.v1"
		},
		"foreign schema":         func(b *identity.CommandBinding) { b.SchemaID += "-foreign" },
		"foreign schema version": func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"missing record":         func(b *identity.CommandBinding) { b.RecordID = "" },
		"missing user":           func(b *identity.CommandBinding) { b.UserID = "" },
		"anonymous flow":         func(b *identity.CommandBinding) { b.AnonymousFlowID = "pre-auth-flow" },
		"user actor":             func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
		"missing actor":          func(b *identity.CommandBinding) { b.ActorID = "" },
		"missing policy":         func(b *identity.CommandBinding) { b.PolicyID = "" },
		"missing policy version": func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
		"missing correlation":    func(b *identity.CommandBinding) { b.CorrelationID = "" },
		"link mode":              func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			var invalid identity.InvalidInputError
			if got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), foreign, proof, grant.EnvelopeDigest(), 1, cutoff); !errors.As(err, &invalid) || got != (kernel.CapabilityPlan{}) {
				t.Fatal("foreign confirmation composition admitted or misclassified", err)
			}
		})
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"user":        func(b *identity.CommandBinding) { b.UserID += "-foreign" },
		"record":      func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
	} {
		t.Run("signed "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), foreign, proof, grant.EnvelopeDigest(), 1, cutoff); !errors.Is(err, identity.ForbiddenError{}) || got != (kernel.CapabilityPlan{}) {
				t.Fatal("foreign signed confirmation scope admitted", err)
			}
		})
	}
}

func TestPrepareSSOSAMLIDPConfirmationConsumptionRejectsSignedReplacements(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"issuer":                             func(p *capability.Payload) { p.Issuer = "https://foreign.example.test" },
		"tenant":                             func(p *capability.Payload) { p.Tenant += "-foreign" },
		"user":                               func(p *capability.Payload) { p.Subject += "-foreign" },
		"record":                             func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":                        func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"missing correlation":                func(p *capability.Payload) { p.CorrelationID = "" },
		"SP-initiated purpose":               func(p *capability.Payload) { p.Operation = "identity.sso.saml-callback" },
		"OIDC purpose":                       func(p *capability.Payload) { p.Operation = "identity.sso.oidc-callback" },
		"foreign audience":                   func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences":                 func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":                             func(p *capability.Payload) { p.Bearer, p.Subject = true, "" },
		"multiple uses":                      func(p *capability.Payload) { p.MaxUses = 2 },
		"reusable":                           func(p *capability.Payload) { p.MaxUses = 0 },
		"over five minutes":                  func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
		"earlier validity over five minutes": func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			i, config, b, payload, cutoff := samlIDPConfirmationConsumptionFixture(t)
			mutate(&payload)
			cutoff = payload.ExpiresAt.Add(time.Microsecond)
			proof, grant := signedAnonymousUpgrade(t, config, payload)
			if got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), b, proof, grant.EnvelopeDigest(), 1, cutoff); err == nil || got != (kernel.CapabilityPlan{}) {
				t.Fatal("signed foreign confirmation profile produced a consuming plan")
			}
		})
	}
	for name, change := range map[string]func(*[32]byte, *uint32, *time.Time){
		"replacement envelope": func(e *[32]byte, _ *uint32, _ *time.Time) { *e = [32]byte{9} },
		"missing envelope":     func(e *[32]byte, _ *uint32, _ *time.Time) { *e = [32]byte{} },
		"unretained key":       func(_ *[32]byte, v *uint32, _ *time.Time) { *v = 9 },
		"missing key":          func(_ *[32]byte, v *uint32, _ *time.Time) { *v = 0 },
		"earlier cutoff":       func(_ *[32]byte, _ *uint32, c *time.Time) { *c = c.Add(-2 * time.Microsecond) },
		"zero cutoff":          func(_ *[32]byte, _ *uint32, c *time.Time) { *c = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			i, config, b, payload, cutoff := samlIDPConfirmationConsumptionFixture(t)
			proof, grant := signedAnonymousUpgrade(t, config, payload)
			envelope, version := grant.EnvelopeDigest(), uint32(1)
			change(&envelope, &version, &cutoff)
			if got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), b, proof, envelope, version, cutoff); err == nil || got != (kernel.CapabilityPlan{}) {
				t.Fatal("replacement origin metadata produced a consuming plan")
			}
		})
	}
}

func TestPrepareSSOSAMLIDPConfirmationConsumptionRejectsExpiryDespiteSkew(t *testing.T) {
	_, config, b, payload, cutoff := samlIDPConfirmationConsumptionFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	observed := payload.ExpiresAt.Add(-time.Nanosecond)
	config.Crypto.Clock = func() time.Time { return observed }
	config.Crypto.Skew = time.Minute
	i, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, instant := range []time.Time{payload.ExpiresAt.Add(-time.Nanosecond), payload.ExpiresAt, cutoff, cutoff.Add(time.Nanosecond)} {
		observed = instant
		if _, err := i.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience); err != nil {
			t.Fatal("skew fixture did not reach strict expiry boundary", err)
		}
		got, err := prepareSAMLIDPConfirmationConsumption(t, i, context.Background(), b, proof, grant.EnvelopeDigest(), 1, cutoff)
		if instant.Before(payload.ExpiresAt) {
			if err != nil || got.ExpiresAt != payload.ExpiresAt {
				t.Fatal("strict cutoff shortened or renewed original wire expiry", err)
			}
		} else if !errors.Is(err, identity.ForbiddenError{}) || got != (kernel.CapabilityPlan{}) {
			t.Fatal("verification skew extended original confirmation lifetime", err)
		}
	}
}

func TestPrepareSSOSAMLIDPConfirmationConsumptionContainsAuthorityFailure(t *testing.T) {
	_, originalConfig, b, payload, cutoff := samlIDPConfirmationConsumptionFixture(t)
	proof, grant := signedAnonymousUpgrade(t, originalConfig, payload)
	for _, mode := range []string{"revoked", "offline", "panic", "zero-clock", "final-clock-panic", "cancelled", "cancelled-after-success", "unknown-key"} {
		t.Run(mode, func(t *testing.T) {
			config, ctx := originalConfig, context.Background()
			var want error = identity.ForbiddenError{}
			switch mode {
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "offline":
				want = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private confirmation diagnostics")
				})
			case "panic":
				want = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					panic("private confirmation diagnostics")
				})
			case "zero-clock", "final-clock-panic":
				want = identity.UnavailableError{}
				verified := false
				config.Crypto.Clock = func() time.Time {
					if verified {
						if mode == "final-clock-panic" {
							panic("private confirmation diagnostics")
						}
						return time.Time{}
					}
					return payload.IssuedAt
				}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { verified = true; return false, nil })
			case "cancelled", "cancelled-after-success":
				want = identity.CancelledError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				if mode == "cancelled" {
					cancel()
				} else {
					config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { cancel(); return false, nil })
				}
			case "unknown-key":
				want = identity.UnavailableError{}
				config.Crypto.Resolver = capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
					return capability.ResolvedKey{}, capability.ErrKeyResolution
				})
			}
			i, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			got, err := prepareSAMLIDPConfirmationConsumption(t, i, ctx, b, proof, grant.EnvelopeDigest(), 1, cutoff)
			if !errors.Is(err, want) || got != (kernel.CapabilityPlan{}) || strings.Contains(err.Error(), "private confirmation diagnostics") {
				t.Fatal("verification uncertainty admitted, leaked or misclassified", err)
			}
		})
	}
}
