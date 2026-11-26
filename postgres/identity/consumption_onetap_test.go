package identitycapability

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type oneTapCallbackConsumptionPreparer interface {
	PrepareOneTapCallbackConsumption(context.Context, identity.CommandBinding, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareOneTapCallbackConsumption(t testing.TB, issuer *Issuer, ctx context.Context, start identity.CommandBinding, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(issuer).(oneTapCallbackConsumptionPreparer)
	if !ok {
		t.Fatal("original One Tap callback consumption preparation is missing")
	}
	return preparer.PrepareOneTapCallbackConsumption(ctx, start, proof, version)
}

func oneTapConsumptionFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	issuer, config, start, payload := oneTapIssuerFixture(t)
	// Native PrepareRequestKey correlates the start to its original command.
	start.CorrelationID = string(start.CommandID)
	payload.CorrelationID = start.CorrelationID
	return issuer, config, start, payload
}

func TestPrepareOneTapCallbackConsumptionPreservesOriginalIssuanceAndCustody(t *testing.T) {
	issuer, config, start, payload := oneTapConsumptionFixture(t)
	prepared, err := issuer.Prepare(context.Background(), start, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	original, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	want := original.Grants[0]
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	config.Crypto.Signer = resetNeverSigner{config.Crypto.Signer}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	for range 8 {
		calls.Go(func() {
			plan, err := prepareOneTapCallbackConsumption(t, rotated, context.Background(), start, proof, want.ReplayKeyVersion)
			if err != nil || plan != want {
				t.Error("original One Tap envelope, expiry or replay identity changed", err)
			}
		})
	}
	calls.Wait()
	other, err := prepareOneTapCallbackConsumption(t, rotated, context.Background(), start, proof, 3)
	if err != nil || other.ReplayKeyVersion != 3 || other.ReplayDigest == want.ReplayDigest || other.ProofFingerprint != want.ProofFingerprint {
		t.Fatal("another retained key impersonated original durable replay metadata", err)
	}
	retained, err := prepared.Plan()
	if err != nil || !reflect.DeepEqual(retained, original) {
		t.Fatal("preparation mutated original One Tap issuance", err)
	}
	if err := proof.Transfer(context.Background(), func(ctx context.Context, raw []byte) error {
		if sha256.Sum256(raw) != want.ProofFingerprint {
			t.Error("preparation changed original signed envelope bytes")
		}
		grant, err := capability.Verify(ctx, string(raw), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if err != nil {
			return err
		}
		expected := payload
		expected.ID = want.CapabilityID
		if !reflect.DeepEqual(grant.Payload(), expected) {
			t.Error("preparation changed original signed One Tap scope")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only preparation transferred proof custody", err)
	}
	if plan, err := prepareOneTapCallbackConsumption(t, rotated, context.Background(), start, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("transferred proof regained custody", err)
	}
}

func TestPrepareOneTapCallbackConsumptionRejectsForeignComposition(t *testing.T) {
	issuer, _, start, payload := oneTapConsumptionFixture(t)
	prepared, err := issuer.Prepare(context.Background(), start, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"OAuth start": func(b *identity.CommandBinding) {
			b.OperationID = "identity.oauth.signin-start"
			b.SchemaID = "identity.oauth.signin-start.rp-v1"
		},
		"SSO start": func(b *identity.CommandBinding) {
			b.OperationID = "identity.sso.signin-start"
			b.SchemaID = "identity.sso.signin-start.oidc-v1"
		},
		"foreign schema":         func(b *identity.CommandBinding) { b.SchemaID += "-foreign" },
		"foreign version":        func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"missing command":        func(b *identity.CommandBinding) { b.CommandID = "" },
		"missing tenant":         func(b *identity.CommandBinding) { b.TenantID = "" },
		"missing flow":           func(b *identity.CommandBinding) { b.AnonymousFlowID = "" },
		"foreign record":         func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"user override":          func(b *identity.CommandBinding) { b.UserID = "user" },
		"user actor":             func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
		"missing actor":          func(b *identity.CommandBinding) { b.ActorID = "" },
		"missing policy":         func(b *identity.CommandBinding) { b.PolicyID = "" },
		"missing policy version": func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
		"foreign correlation":    func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"link override":          func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := start
			mutate(&foreign)
			var invalid identity.InvalidInputError
			if plan, err := prepareOneTapCallbackConsumption(t, issuer, context.Background(), foreign, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign One Tap composition admitted or misclassified", err)
			}
		})
	}
	otherCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":                  func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow and record":         func(b *identity.CommandBinding) { b.AnonymousFlowID += "-foreign"; b.RecordID = b.AnonymousFlowID },
		"command and correlation": func(b *identity.CommandBinding) { b.CommandID = otherCommand; b.CorrelationID = string(otherCommand) },
	} {
		t.Run("foreign signed "+name, func(t *testing.T) {
			foreign := start
			mutate(&foreign)
			if plan, err := prepareOneTapCallbackConsumption(t, issuer, context.Background(), foreign, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign original One Tap signed scope admitted", err)
			}
		})
	}
	for _, version := range []uint32{0, 99} {
		var invalid identity.InvalidInputError
		if plan, err := prepareOneTapCallbackConsumption(t, issuer, context.Background(), start, proof, version); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("unknown replay key admitted", err)
		}
	}
	for _, call := range []struct {
		name   string
		issuer *Issuer
		ctx    context.Context
	}{{"nil issuer", nil, context.Background()}, {"zero issuer", &Issuer{}, context.Background()}, {"nil context", issuer, nil}} {
		t.Run(call.name, func(t *testing.T) {
			var invalid identity.InvalidInputError
			if plan, err := prepareOneTapCallbackConsumption(t, call.issuer, call.ctx, start, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("invalid One Tap verifier composition admitted", err)
			}
		})
	}
	if plan, err := prepareOneTapCallbackConsumption(t, issuer, context.Background(), start, capability.Proof{}, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("absent original proof admitted", err)
	}
}

func TestPrepareOneTapCallbackConsumptionRejectsForeignSignedUse(t *testing.T) {
	issuer, _, start, payload := oneTapConsumptionFixture(t)
	for name, mutate := range map[string]func(*capability.Payload){
		"OAuth purpose":      func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"SSO purpose":        func(p *capability.Payload) { p.Operation = "identity.sso.oidc-callback" },
		"subject":            func(p *capability.Payload) { p.Subject += "-foreign" },
		"tenant":             func(p *capability.Payload) { p.Tenant += "-foreign" },
		"resource":           func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":        func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"caveat":             func(p *capability.Payload) { p.Caveats = map[string]string{"foreign-policy": "required"} },
		"multiple uses":      func(p *capability.Payload) { p.MaxUses = 2 },
		"unlimited uses":     func(p *capability.Payload) { p.MaxUses = 0 },
		"bearer":             func(p *capability.Payload) { p.Subject = ""; p.Bearer = true },
		"foreign audience":   func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences": func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"changed not before": func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"extended lifetime":  func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := payload
			foreign.ID = "original-signed-onetap-grant"
			mutate(&foreign)
			proof, _, err := issuer.service.Issue(context.Background(), foreign)
			if err != nil {
				t.Fatal("foreign signed fixture failed", err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			if plan, err := prepareOneTapCallbackConsumption(t, issuer, context.Background(), start, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign signed One Tap use admitted", err)
			}
		})
	}
}

func TestPrepareOneTapCallbackConsumptionEnforcesExclusiveExpiryDespiteSkew(t *testing.T) {
	issuer, config, start, payload := oneTapConsumptionFixture(t)
	prepared, err := issuer.Prepare(context.Background(), start, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	original, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	observed := payload.ExpiresAt.Add(-time.Nanosecond)
	config.Crypto.Clock = func() time.Time { return observed }
	config.Crypto.Skew = time.Minute
	verifier, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, instant := range []time.Time{payload.ExpiresAt.Add(-time.Nanosecond), payload.ExpiresAt, payload.ExpiresAt.Add(time.Second)} {
		t.Run(instant.Sub(payload.ExpiresAt).String(), func(t *testing.T) {
			observed = instant
			if _, err := verifier.service.Verify(context.Background(), proof, oneTapCallbackPurpose, config.Audience); err != nil {
				t.Fatal("skew fixture did not reach strict expiry boundary", err)
			}
			plan, err := prepareOneTapCallbackConsumption(t, verifier, context.Background(), start, proof, 2)
			if instant.Before(payload.ExpiresAt) {
				if err != nil || plan != original.Grants[0] {
					t.Fatal("original One Tap lifetime shortened", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("verification skew extended signed expiry", err)
			}
		})
	}
}

func TestPrepareOneTapCallbackConsumptionClassifiesAuthorityAndCancellation(t *testing.T) {
	issuer, originalConfig, start, payload := oneTapConsumptionFixture(t)
	prepared, err := issuer.Prepare(context.Background(), start, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, mode := range []string{"revoked", "unavailable", "panic", "cancelled", "caller-deadline", "preparation-timeout", "zero-clock"} {
		t.Run(mode, func(t *testing.T) {
			config, ctx := originalConfig, context.Background()
			var expected error = identity.ForbiddenError{}
			switch mode {
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private One Tap diagnostics")
				})
			case "panic":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private One Tap diagnostics") })
			case "cancelled":
				expected = identity.CancelledError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "caller-deadline", "preparation-timeout":
				expected = identity.DeadlineExceededError{}
				if mode == "caller-deadline" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
					defer cancel()
				}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			}
			verifier, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "zero-clock" {
				expected = identity.UnavailableError{}
				verifier.clock = func() time.Time { return time.Time{} }
			}
			plan, err := prepareOneTapCallbackConsumption(t, verifier, ctx, start, proof, 2)
			if !errors.Is(err, expected) || plan != (identitypostgres.CapabilityPlan{}) || strings.Contains(err.Error(), "private One Tap diagnostics") {
				t.Fatal("One Tap authority failure admitted, leaked or misclassified", err)
			}
		})
	}
}
