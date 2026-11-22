package identitycapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type ssoOIDCExplicitLinkConsumptionPreparer interface {
	PrepareSSOOIDCExplicitLinkConsumption(context.Context, identity.CommandBinding, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareSSOOIDCExplicitLinkConsumption(t testing.TB, issuer *Issuer, ctx context.Context, originalStart identity.CommandBinding, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(issuer).(ssoOIDCExplicitLinkConsumptionPreparer)
	if !ok {
		t.Fatal("member-bound enterprise OIDC callback-state authentication is missing")
	}
	return preparer.PrepareSSOOIDCExplicitLinkConsumption(ctx, originalStart, proof, version)
}

func TestPrepareSSOOIDCExplicitLinkConsumptionPreservesOriginalGrant(t *testing.T) {
	i, config, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	if _, ok := any(i).(ssoOIDCExplicitLinkConsumptionPreparer); !ok {
		t.Fatal("member-bound enterprise OIDC callback-state authentication is missing")
	}
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("member consent issuance denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	got, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), b, proof, plan.Grants[0].ReplayKeyVersion)
	if err != nil || got != plan.Grants[0] {
		t.Fatal("member preparation changed original consent witness", err)
	}
	wrongKey, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), b, proof, 1)
	if err != nil || wrongKey.ReplayKeyVersion != 1 || wrongKey.ReplayDigest == got.ReplayDigest || wrongKey.ProofFingerprint != got.ProofFingerprint {
		t.Fatal("another retained key impersonated original durable replay witness", err)
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if retained, err := prepareSSOOIDCExplicitLinkConsumption(t, rotated, context.Background(), b, proof, 2); err != nil || retained != got {
		t.Fatal("replay-key rotation changed original member witness", err)
	}
	wantPayload, err := capability.CanonicalPayload(prepared.state.grants[0].Payload(), config.Crypto.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Transfer(context.Background(), func(ctx context.Context, raw []byte) error {
		if sha256.Sum256(raw) != got.ProofFingerprint {
			t.Error("member preparation changed signed envelope bytes")
		}
		grant, err := capability.Verify(ctx, string(raw), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if err != nil {
			return err
		}
		actual, err := capability.CanonicalPayload(grant.Payload(), config.Crypto.Limits)
		if err != nil || !bytes.Equal(actual, wantPayload) {
			t.Error("member preparation changed signed consent")
		}
		return nil
	}); err != nil {
		t.Fatal("member preparation transferred original custody", err)
	}
	if out, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), b, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("transferred member proof regained custody", err)
	}
}

func TestPrepareSSOOIDCExplicitLinkConsumptionRejectsForeignOriginalStart(t *testing.T) {
	i, _, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"anonymous schema": func(b *identity.CommandBinding) { b.SchemaID = "identity.sso.signin-start.oidc-v1" },
		"social operation": func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID = "identity.account.link-start", "identity.account.link-start.rp-v1"
		},
		"foreign version":     func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"foreign operation":   func(b *identity.CommandBinding) { b.OperationID += "-foreign" },
		"foreign actor":       func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
		"service actor":       func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		"API key actor":       func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectAPIKey },
		"anonymous flow":      func(b *identity.CommandBinding) { b.AnonymousFlowID = "foreign-flow" },
		"missing member":      func(b *identity.CommandBinding) { b.UserID = "" },
		"foreign record":      func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"missing policy":      func(b *identity.CommandBinding) { b.PolicyID = "" },
		"missing correlation": func(b *identity.CommandBinding) { b.CorrelationID = "" },
		"link mode":           func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			var invalid identity.InvalidInputError
			if out, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), foreign, proof, 2); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("invalid member origin admitted or misclassified", err)
			}
		})
	}
	otherCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"member":      func(b *identity.CommandBinding) { b.UserID += "-foreign"; b.ActorID = identity.ActorID(b.UserID) },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"transaction": func(b *identity.CommandBinding) { b.CommandID, b.RecordID = otherCommand, string(otherCommand) },
	} {
		t.Run("foreign signed "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if out, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), foreign, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("valid but foreign member origin admitted", err)
			}
		})
	}
}

func TestPrepareSSOOIDCExplicitLinkConsumptionSeparatesAnonymousMode(t *testing.T) {
	i, _, memberStart, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	member, err := i.Prepare(context.Background(), memberStart, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	_, _, anonymousStart, anonymousPayload := ssoOIDCIssuerFixture(t)
	anonymous, err := i.Prepare(context.Background(), anonymousStart, []capability.Payload{anonymousPayload})
	if err != nil {
		t.Fatal(err)
	}
	memberProof, anonymousProof := member.state.proofs[0], anonymous.state.proofs[0]
	t.Cleanup(func() {
		_ = memberProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		_ = anonymousProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	var invalid identity.InvalidInputError
	if out, err := i.PrepareSSOOIDCSigninConsumption(context.Background(), memberStart, memberProof, 2); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("anonymous API selected a member origin", err)
	}
	if out, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), anonymousStart, anonymousProof, 2); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("member API selected an anonymous origin", err)
	}
	if out, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), memberStart, anonymousProof, 2); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("member API authenticated anonymous state", err)
	}
	if out, err := i.PrepareSSOOIDCSigninConsumption(context.Background(), anonymousStart, memberProof, 2); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("anonymous API authenticated member state", err)
	}
}

func TestPrepareSSOOIDCExplicitLinkConsumptionRejectsSignedForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"member":             func(p *capability.Payload) { p.Subject += "-foreign" },
		"tenant":             func(p *capability.Payload) { p.Tenant += "-foreign" },
		"transaction":        func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":        func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"social callback":    func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"final link grant":   func(p *capability.Payload) { p.Operation = "identity.account.link-token" },
		"multiple audiences": func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":             func(p *capability.Payload) { p.Bearer, p.Subject = true, "" },
		"reusable":           func(p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":      func(p *capability.Payload) { p.MaxUses = 2 },
		"delayed not-before": func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"extended lifetime":  func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			i, _, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
			payload.ID = "signed-foreign-member-proof"
			mutate(&payload)
			proof, _, err := i.service.Issue(context.Background(), payload)
			if err != nil {
				t.Fatal("signed foreign fixture failed", err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			if out, err := prepareSSOOIDCExplicitLinkConsumption(t, i, context.Background(), b, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("signed foreign member proof admitted or misclassified", err)
			}
		})
	}
}

func TestPrepareSSOOIDCExplicitLinkConsumptionPreservesStrictExpiry(t *testing.T) {
	i, config, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	want, err := prepared.Plan()
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
	for _, instant := range []time.Time{observed, payload.ExpiresAt, payload.ExpiresAt.Add(time.Second)} {
		t.Run(instant.Sub(payload.ExpiresAt).String(), func(t *testing.T) {
			observed = instant
			if _, err := verifier.service.Verify(context.Background(), proof, "identity.sso.oidc-callback", config.Audience); err != nil {
				t.Fatal("verification skew fixture did not reach strict boundary", err)
			}
			out, err := prepareSSOOIDCExplicitLinkConsumption(t, verifier, context.Background(), b, proof, 2)
			if instant.Before(payload.ExpiresAt) {
				if err != nil || out != want.Grants[0] {
					t.Fatal("member preparation shortened or replaced original validity", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("verification skew renewed expired member consent", err)
			}
		})
	}
}
