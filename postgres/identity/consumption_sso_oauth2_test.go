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

type ssoOAuth2SigninConsumptionPreparer interface {
	PrepareSSOOAuth2SigninConsumption(context.Context, identity.CommandBinding, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareSSOOAuth2SigninConsumption(t testing.TB, issuer *Issuer, ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(issuer).(ssoOAuth2SigninConsumptionPreparer)
	if !ok {
		t.Fatal("original enterprise OAuth2 callback-state authentication is missing")
	}
	return preparer.PrepareSSOOAuth2SigninConsumption(ctx, originalStart, proof, version)
}

func TestPrepareSSOOAuth2SigninConsumptionPreservesOriginalGrantWithoutReissue(t *testing.T) {
	issuer, config, originalStart, payload := ssoOAuth2IssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original OAuth2 start grant could not be issued", err)
	}
	originalPlan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	want := originalPlan.Grants[0]
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
			plan, err := prepareSSOOAuth2SigninConsumption(t, rotated, context.Background(), originalStart, proof, want.ReplayKeyVersion)
			if err != nil || plan != want || plan.Purpose != "identity.sso.oauth-callback" || plan.MaxUses != 1 {
				t.Error("original OAuth2 envelope, one-use plan, replay identity or expiry changed", err)
			}
		})
	}
	calls.Wait()
	otherKey, err := prepareSSOOAuth2SigninConsumption(t, rotated, context.Background(), originalStart, proof, 3)
	if err != nil || otherKey.ReplayKeyVersion != 3 || otherKey.ReplayDigest == want.ReplayDigest || otherKey.ProofFingerprint != want.ProofFingerprint {
		t.Fatal("another retained key impersonated original durable replay metadata", err)
	}
	retainedPlan, err := prepared.Plan()
	if err != nil || !reflect.DeepEqual(retainedPlan, originalPlan) {
		t.Fatal("consumption preparation mutated original OAuth2 issuance", err)
	}
	if err := proof.Transfer(context.Background(), func(ctx context.Context, raw []byte) error {
		if sha256.Sum256(raw) != want.ProofFingerprint {
			t.Error("original OAuth2 signed envelope bytes changed")
		}
		grant, err := capability.Verify(ctx, string(raw), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if err != nil {
			return err
		}
		expected := payload
		expected.ID = want.CapabilityID
		if !reflect.DeepEqual(grant.Payload(), expected) || grant.Payload().Resource != string(originalStart.CommandID) || grant.Payload().MaxUses != 1 {
			t.Error("original OAuth2 payload, transaction resource or one-use policy changed")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only preparation transferred original proof custody", err)
	}
	if plan, err := prepareSSOOAuth2SigninConsumption(t, rotated, context.Background(), originalStart, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("transferred OAuth2 proof regained custody", err)
	}
}

func TestPrepareSSOOAuth2SigninConsumptionRejectsForeignStartAndScope(t *testing.T) {
	issuer, _, originalStart, payload := ssoOAuth2IssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"OIDC start":             func(b *identity.CommandBinding) { b.SchemaID = "identity.sso.signin-start.oidc-v1" },
		"OIDC member start":      func(b *identity.CommandBinding) { b.SchemaID = "identity.sso.signin-start.oidc-link-v1" },
		"foreign operation":      func(b *identity.CommandBinding) { b.OperationID = "identity.oauth.signin-start" },
		"foreign schema version": func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"zero command": func(b *identity.CommandBinding) {
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
			if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), foreign, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign OAuth2 start profile admitted or misclassified", err)
			}
		})
	}
	foreignCommand, err := identity.ParseCommandID("AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow":        func(b *identity.CommandBinding) { b.AnonymousFlowID += "-foreign" },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"command": func(b *identity.CommandBinding) {
			b.CommandID, b.RecordID = foreignCommand, string(foreignCommand)
		},
	} {
		t.Run("foreign signed "+name, func(t *testing.T) {
			foreign := originalStart
			mutate(&foreign)
			if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), foreign, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("valid but foreign original OAuth2 scope admitted", err)
			}
		})
	}
	for _, version := range []uint32{0, 9} {
		var invalid identity.InvalidInputError
		if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), originalStart, proof, version); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("unretained OAuth2 replay key admitted", err)
		}
	}
	for _, malformed := range []struct {
		issuer *Issuer
		ctx    context.Context
	}{{nil, context.Background()}, {issuer, nilContextForTest()}} {
		var invalid identity.InvalidInputError
		if plan, err := prepareSSOOAuth2SigninConsumption(t, malformed.issuer, malformed.ctx, originalStart, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("invalid OAuth2 caller composition admitted", err)
		}
	}
	if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), originalStart, capability.Proof{}, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("zero OAuth2 proof admitted", err)
	}
}

func TestPrepareSSOOAuth2SigninConsumptionRejectsSignedForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":                     func(p *capability.Payload) { p.Tenant += "-foreign" },
		"flow":                       func(p *capability.Payload) { p.Subject += "-foreign" },
		"transaction":                func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":                func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"missing correlation":        func(p *capability.Payload) { p.CorrelationID = "" },
		"multiple audiences":         func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"reusable":                   func(p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":              func(p *capability.Payload) { p.MaxUses = 2 },
		"bearer":                     func(p *capability.Payload) { p.Bearer, p.Subject = true, "" },
		"changed not-before":         func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"extended original lifetime": func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, _, originalStart, payload := ssoOAuth2IssuerFixture(t)
			payload.ID = "signed-foreign-enterprise-oauth2-proof"
			mutate(&payload)
			proof, _, err := issuer.service.Issue(context.Background(), payload)
			if err != nil {
				t.Fatal("foreign OAuth2 fixture could not be signed", err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), originalStart, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("signed foreign OAuth2 profile admitted or misclassified", err)
			}
		})
	}
}

func TestPrepareSSOOAuth2SigninConsumptionSeparatesOIDCAndSocial(t *testing.T) {
	issuer, _, oauthStart, oauthPayload := ssoOAuth2IssuerFixture(t)
	oauth, err := issuer.Prepare(context.Background(), oauthStart, []capability.Payload{oauthPayload})
	if err != nil {
		t.Fatal(err)
	}
	oauthProof := oauth.state.proofs[0]
	t.Cleanup(func() {
		_ = oauthProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	// Keep transaction and flow identical so only the signed protocol purpose differs.
	oidcStart, oidcPayload := oauthStart, oauthPayload
	oidcStart.SchemaID = "identity.sso.signin-start.oidc-v1"
	oidcPayload.Operation = "identity.sso.oidc-callback"
	for name, start := range map[string]identity.CommandBinding{"OIDC": oidcStart, "social": oauthRPIssuerBinding(oauthStart, true)} {
		t.Run(name, func(t *testing.T) {
			payload := oidcPayload
			if name == "social" {
				payload.Subject, payload.Resource, payload.Operation = start.AnonymousFlowID, start.RecordID, "identity.oauth.callback"
			}
			prepared, err := issuer.Prepare(context.Background(), start, []capability.Payload{payload})
			if err != nil {
				t.Fatal(err)
			}
			proof := prepared.state.proofs[0]
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), oauthStart, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign protocol proof entered enterprise OAuth2 preparation", err)
			}
			var plan identitypostgres.CapabilityPlan
			if name == "OIDC" {
				plan, err = issuer.PrepareSSOOIDCSigninConsumption(context.Background(), start, oauthProof, 2)
			} else {
				plan, err = issuer.PrepareOAuthCallbackConsumption(context.Background(), start, oauthProof, 2)
			}
			if !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("enterprise OAuth2 proof entered another protocol preparation", err)
			}
		})
	}
}

func TestPrepareSSOOAuth2SigninConsumptionRejectsExpiryDespiteVerificationSkew(t *testing.T) {
	issuer, config, originalStart, payload := ssoOAuth2IssuerFixture(t)
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
			if _, err := verifier.service.Verify(context.Background(), proof, "identity.sso.oauth-callback", config.Audience); err != nil {
				t.Fatal("verification-skew fixture did not reach strict expiry boundary", err)
			}
			plan, err := prepareSSOOAuth2SigninConsumption(t, verifier, context.Background(), originalStart, proof, 2)
			if instant.Before(payload.ExpiresAt) {
				if err != nil || plan != issuance.Grants[0] {
					t.Fatal("strict expiry shortened the original OAuth2 lifetime", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("verification skew extended original OAuth2 expiry", err)
			}
		})
	}
}

func TestPrepareSSOOAuth2SigninConsumptionRechecksAuthorityAndDeadline(t *testing.T) {
	issuer, originalConfig, originalStart, payload := ssoOAuth2IssuerFixture(t)
	prepared, err := issuer.Prepare(context.Background(), originalStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, mode := range []string{"foreign-audience", "revoked", "unavailable", "panic", "cancelled", "caller-deadline", "preparation-timeout"} {
		t.Run(mode, func(t *testing.T) {
			config, ctx := originalConfig, context.Background()
			var expected error = identity.ForbiddenError{}
			switch mode {
			case "foreign-audience":
				config.Audience = "foreign"
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private OAuth2 diagnostics")
				})
			case "panic":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private OAuth2 diagnostics") })
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
			plan, err := prepareSSOOAuth2SigninConsumption(t, verifier, ctx, originalStart, proof, 2)
			if !errors.Is(err, expected) || plan != (identitypostgres.CapabilityPlan{}) || strings.Contains(err.Error(), "private OAuth2 diagnostics") {
				t.Fatal("OAuth2 authority failure admitted, leaked or misclassified", err)
			}
		})
	}
}

func TestPrepareSSOOAuth2SigninConsumptionRejectsCorruptedSignature(t *testing.T) {
	issuer, config, originalStart, payload := ssoOAuth2IssuerFixture(t)
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
	if plan, err := prepareSSOOAuth2SigninConsumption(t, issuer, context.Background(), originalStart, corrupted, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("unauthenticated OAuth2 proof produced a plan", err)
	}
}
