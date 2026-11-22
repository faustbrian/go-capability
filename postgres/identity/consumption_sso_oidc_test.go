package identitycapability

import (
	"bytes"
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

type ssoOIDCSigninConsumptionPreparer interface {
	PrepareSSOOIDCSigninConsumption(context.Context, identity.CommandBinding, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareSSOOIDCSigninConsumption(t testing.TB, issuer *Issuer, ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(issuer).(ssoOIDCSigninConsumptionPreparer)
	if !ok {
		t.Fatal("original enterprise OIDC callback-state authentication is missing")
	}
	return preparer.PrepareSSOOIDCSigninConsumption(ctx, originalStart, proof, version)
}

func TestPrepareSSOOIDCSigninConsumptionPreservesOriginalGrant(t *testing.T) {
	issuer, config, originalStart, payload := ssoOIDCIssuerFixture(t)
	payload.Caveats = map[string]string{"rp.binding": strings.Repeat("a", 64)}
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original enterprise start grant could not be issued", err)
	}
	originalPlan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	want := originalPlan.Grants[0]
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	wrongKeyPlan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), originalStart, proof, 1)
	if err != nil || wrongKeyPlan.ReplayKeyVersion != 1 || wrongKeyPlan.ReplayDigest == want.ReplayDigest || wrongKeyPlan.ProofFingerprint != want.ProofFingerprint {
		t.Fatal("another retained key impersonated original durable replay metadata", err)
	}
	originalPayload, err := capability.CanonicalPayload(prepared.state.grants[0].Payload(), config.Crypto.Limits)
	if err != nil {
		t.Fatal(err)
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	for range 8 {
		calls.Go(func() {
			plan, err := prepareSSOOIDCSigninConsumption(t, rotated, context.Background(), originalStart, proof, want.ReplayKeyVersion)
			if err != nil || plan != want {
				t.Error("original enterprise envelope, replay identity or expiry changed", err)
			}
		})
	}
	calls.Wait()
	retainedPlan, err := prepared.Plan()
	if err != nil || !reflect.DeepEqual(retainedPlan, originalPlan) {
		t.Fatal("consumption preparation mutated original issuance", err)
	}
	if err := proof.Transfer(context.Background(), func(ctx context.Context, raw []byte) error {
		if sha256.Sum256(raw) != want.ProofFingerprint {
			t.Error("original signed envelope bytes changed")
		}
		grant, err := capability.Verify(ctx, string(raw), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if err != nil {
			return err
		}
		got, err := capability.CanonicalPayload(grant.Payload(), config.Crypto.Limits)
		if err != nil || !bytes.Equal(got, originalPayload) {
			t.Error("original signed payload or caveats changed", err)
		}
		return nil
	}); err != nil {
		t.Fatal("read-only preparation transferred original proof custody", err)
	}
	if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), originalStart, proof, want.ReplayKeyVersion); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("transferred enterprise proof regained custody", err)
	}
}

func TestPrepareSSOOIDCSigninConsumptionRejectsForeignOriginalStart(t *testing.T) {
	issuer, _, originalStart, payload := ssoOIDCIssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"social start": func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID = "identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1"
		},
		"foreign operation":      func(b *identity.CommandBinding) { b.OperationID = "identity.sso.saml-callback" },
		"foreign schema":         func(b *identity.CommandBinding) { b.SchemaID += "-foreign" },
		"foreign schema version": func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"zero command ID": func(b *identity.CommandBinding) {
			b.CommandID, b.RecordID = "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA"
		},
		"missing transaction":    func(b *identity.CommandBinding) { b.RecordID = "" },
		"foreign transaction":    func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"missing flow":           func(b *identity.CommandBinding) { b.AnonymousFlowID = "" },
		"user override":          func(b *identity.CommandBinding) { b.UserID = "user" },
		"user actor":             func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
		"missing actor":          func(b *identity.CommandBinding) { b.ActorID = "" },
		"missing policy":         func(b *identity.CommandBinding) { b.PolicyID = "" },
		"missing policy version": func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
		"missing correlation":    func(b *identity.CommandBinding) { b.CorrelationID = "" },
		"link mode":              func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := originalStart
			mutate(&foreign)
			var invalid identity.InvalidInputError
			if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), foreign, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign original start profile admitted or misclassified", err)
			}
		})
	}
	foreignCommandID, err := identity.ParseCommandID("AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal("foreign transaction fixture is not a canonical nonzero command", err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow":        func(b *identity.CommandBinding) { b.AnonymousFlowID += "-foreign" },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"transaction": func(b *identity.CommandBinding) {
			b.CommandID, b.RecordID = foreignCommandID, string(foreignCommandID)
		},
	} {
		t.Run("foreign signed "+name, func(t *testing.T) {
			foreign := originalStart
			mutate(&foreign)
			if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), foreign, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("valid but foreign original scope admitted", err)
			}
		})
	}
	for _, version := range []uint32{0, 9} {
		var invalid identity.InvalidInputError
		if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), originalStart, proof, version); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("unretained replay key admitted", err)
		}
	}
	for _, malformed := range []struct {
		issuer *Issuer
		ctx    context.Context
	}{{nil, context.Background()}, {issuer, nilContextForTest()}} {
		var invalid identity.InvalidInputError
		if plan, err := prepareSSOOIDCSigninConsumption(t, malformed.issuer, malformed.ctx, originalStart, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("invalid caller composition admitted", err)
		}
	}
	if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), originalStart, capability.Proof{}, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("zero enterprise proof admitted", err)
	}
}

func TestPrepareSSOOIDCSigninConsumptionRejectsSignedForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":                     func(p *capability.Payload) { p.Tenant += "-foreign" },
		"flow":                       func(p *capability.Payload) { p.Subject += "-foreign" },
		"transaction":                func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":                func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"missing correlation":        func(p *capability.Payload) { p.CorrelationID = "" },
		"social callback":            func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"SAML callback":              func(p *capability.Payload) { p.Operation = "identity.sso.saml-callback" },
		"final link grant":           func(p *capability.Payload) { p.Operation = "identity.account.link-token" },
		"multiple audiences":         func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"reusable":                   func(p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":              func(p *capability.Payload) { p.MaxUses = 2 },
		"bearer":                     func(p *capability.Payload) { p.Bearer, p.Subject = true, "" },
		"changed not-before":         func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"extended original lifetime": func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, _, originalStart, payload := ssoOIDCIssuerFixture(t)
			payload.ID = "signed-foreign-enterprise-proof"
			mutate(&payload)
			proof, _, err := issuer.service.Issue(context.Background(), payload)
			if err != nil {
				t.Fatal("foreign fixture could not be signed", err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), originalStart, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("signed foreign enterprise profile admitted or misclassified", err)
			}
		})
	}
}

func TestPrepareSSOOIDCSigninConsumptionSeparatesSocialAndEnterprise(t *testing.T) {
	issuer, _, enterpriseStart, enterprisePayload := ssoOIDCIssuerFixture(t)
	enterprise, err := issuer.Prepare(context.Background(), enterpriseStart, []capability.Payload{enterprisePayload})
	if err != nil {
		t.Fatal(err)
	}
	socialStart := oauthRPIssuerBinding(enterpriseStart, true)
	socialPayload := enterprisePayload
	socialPayload.Subject, socialPayload.Resource, socialPayload.Operation = socialStart.AnonymousFlowID, socialStart.RecordID, "identity.oauth.callback"
	social, err := issuer.Prepare(context.Background(), socialStart, []capability.Payload{socialPayload})
	if err != nil {
		t.Fatal(err)
	}
	enterpriseProof, socialProof := enterprise.state.proofs[0], social.state.proofs[0]
	t.Cleanup(func() {
		_ = enterpriseProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		_ = socialProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), enterpriseStart, socialProof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("original social proof entered enterprise preparation", err)
	}
	if plan, err := issuer.PrepareOAuthCallbackConsumption(context.Background(), socialStart, enterpriseProof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("original enterprise proof entered social preparation", err)
	}
}

func TestPrepareSSOOIDCSigninConsumptionRejectsCorruptedSignature(t *testing.T) {
	issuer, config, originalStart, payload := ssoOIDCIssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	var wire []byte
	if err := prepared.TransferForDelivery(context.Background(), 0, func(_ context.Context, raw []byte) error { wire = bytes.Clone(raw); return nil }); err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	signature := bytes.LastIndexByte(wire, '.') + 1
	if signature <= 0 || signature >= len(wire) {
		t.Fatal("unexpected original proof framing")
	}
	if wire[signature] == 'A' {
		wire[signature] = 'B'
	} else {
		wire[signature] = 'A'
	}
	corrupted, err := capability.ParseProof(string(wire), config.Crypto.Limits)
	if err != nil {
		t.Fatal("corrupted signature fixture was not parseable", err)
	}
	t.Cleanup(func() {
		_ = corrupted.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	if plan, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), originalStart, corrupted, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("unauthenticated enterprise proof produced a plan", err)
	}
}

func TestPrepareSSOOIDCSigninConsumptionRejectsExpiryDespiteVerificationSkew(t *testing.T) {
	issuer, config, originalStart, payload := ssoOIDCIssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := prepared.Plan()
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
			if _, err := verifier.service.Verify(context.Background(), proof, "identity.sso.oidc-callback", config.Audience); err != nil {
				t.Fatal("verification-skew fixture did not reach strict expiry boundary", err)
			}
			plan, err := prepareSSOOIDCSigninConsumption(t, verifier, context.Background(), originalStart, proof, 2)
			if instant.Before(payload.ExpiresAt) {
				if err != nil || plan != issuance.Grants[0] {
					t.Fatal("strict expiry shortened the original signed lifetime", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("verification skew extended original enterprise proof expiry", err)
			}
		})
	}
}

func TestPrepareSSOOIDCSigninConsumptionContainsFinalClockFailure(t *testing.T) {
	issuer, originalConfig, originalStart, payload := ssoOIDCIssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, mode := range []string{"panic", "zero", "cancellation-before-expiry-denial"} {
		t.Run(mode, func(t *testing.T) {
			config := originalConfig
			verified := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config.Crypto.Clock = func() time.Time {
				if verified {
					if mode == "panic" {
						panic("private enterprise clock diagnostics")
					}
					if mode == "zero" {
						return time.Time{}
					}
					cancel()
					return payload.ExpiresAt
				}
				return payload.IssuedAt
			}
			config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
				verified = true
				return false, nil
			})
			verifier, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			var expected error = identity.UnavailableError{}
			if mode == "cancellation-before-expiry-denial" {
				expected = identity.CancelledError{}
			}
			plan, err := prepareSSOOIDCSigninConsumption(t, verifier, ctx, originalStart, proof, 2)
			if !errors.Is(err, expected) || plan != (identitypostgres.CapabilityPlan{}) || strings.Contains(err.Error(), "private enterprise clock diagnostics") {
				t.Fatal("final clock failure was admitted, leaked or misclassified", err)
			}
		})
	}
}

func TestPrepareSSOOIDCSigninConsumptionRechecksConfiguredAuthority(t *testing.T) {
	issuer, originalConfig, originalStart, payload := ssoOIDCIssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, mode := range []string{"expired", "foreign-key", "foreign-issuer", "foreign-audience", "revoked", "unavailable", "panic", "cancelled", "cancelled-after-success", "deadline", "preparation-timeout"} {
		t.Run(mode, func(t *testing.T) {
			config, ctx := originalConfig, context.Background()
			var expected error = identity.ForbiddenError{}
			switch mode {
			case "expired":
				config.Crypto.Clock = func() time.Time { return payload.ExpiresAt }
			case "foreign-key":
				verifier, _ := capability.NewHMACSHA256Verifier([]byte("foreign-key-012345678901234567890123"))
				config.Crypto.Resolver, _ = capability.NewKeySet([]capability.Key{{Issuer: config.Crypto.Issuer, ID: "signing-v1", Verifier: verifier}})
			case "foreign-issuer":
				config.Crypto.Issuer = "https://foreign.example.test"
			case "foreign-audience":
				config.Audience = "foreign"
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private enterprise diagnostics")
				})
			case "panic":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					panic("private enterprise diagnostics")
				})
			case "cancelled", "cancelled-after-success":
				expected = identity.CancelledError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				if mode == "cancelled" {
					cancel()
				} else {
					config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { cancel(); return false, nil })
				}
			case "deadline", "preparation-timeout":
				expected = identity.DeadlineExceededError{}
				if mode == "preparation-timeout" {
					config.PreparationTimeout = time.Second
				} else {
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
			plan, err := prepareSSOOIDCSigninConsumption(t, verifier, ctx, originalStart, proof, 2)
			if !errors.Is(err, expected) || plan != (identitypostgres.CapabilityPlan{}) || strings.Contains(err.Error(), "private enterprise diagnostics") {
				t.Fatal("enterprise authority failure admitted, leaked or misclassified", err)
			}
		})
	}
}

func FuzzSSOOIDCSigninConsumptionOriginalScope(f *testing.F) {
	issuer, _, originalStart, payload := ssoOIDCIssuerFixture(f)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		f.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		f.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	f.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	f.Add(originalStart.OperationID, originalStart.SchemaID, string(originalStart.TenantID), originalStart.AnonymousFlowID, originalStart.CorrelationID, originalStart.RecordID)
	f.Add("identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1", "foreign", "foreign", "foreign", "foreign")
	f.Fuzz(func(t *testing.T, operation, schema, tenant, flow, correlation, record string) {
		for _, value := range []string{operation, schema, tenant, flow, correlation, record} {
			if len(value) > 256 {
				t.Skip()
			}
		}
		candidate := originalStart
		candidate.OperationID, candidate.SchemaID = operation, schema
		candidate.TenantID, candidate.AnonymousFlowID = identity.TenantID(tenant), flow
		candidate.CorrelationID, candidate.RecordID = correlation, record
		got, err := prepareSSOOIDCSigninConsumption(t, issuer, context.Background(), candidate, proof, 2)
		if candidate == originalStart {
			if err != nil || got != plan.Grants[0] {
				t.Fatal("original enterprise scope changed", err)
			}
		} else if err == nil || got != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("foreign enterprise scope produced a plan", err)
		}
	})
}
