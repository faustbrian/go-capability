package identitycapability

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func ssoOIDCIssuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	i, config, b, payload := issuerFixture(t)
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.sso.signin-start", "identity.sso.signin-start.oidc-v1", 1
	b.UserID, b.AnonymousFlowID = "", "enterprise-preauth-flow"
	b.ActorID, b.ActorKind = "enterprise-service", authorization.SubjectServiceAccount
	b.PolicyID, b.PolicyVersion = "enterprise-oidc-policy", 1
	b.CorrelationID, b.RecordID = "enterprise-original-correlation", string(b.CommandID)
	payload.Subject, payload.Resource = b.AnonymousFlowID, b.RecordID
	payload.Operation, payload.CorrelationID = "identity.sso.oidc-callback", b.CorrelationID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.ExpiresAt = payload.IssuedAt.Add(10 * time.Minute)
	return i, config, b, payload
}

func TestSSOOIDCIssuerPreservesOriginalCallbackGrant(t *testing.T) {
	i, config, b, payload := ssoOIDCIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("native enterprise callback-state preparation denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.RegistrationUserID != "" || plan.ResetRecipientUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" {
		t.Fatal("enterprise preauth flow became a user override", err)
	}
	metadata := plan.Grants[0]
	if metadata.Purpose != "identity.sso.oidc-callback" || metadata.MaxUses != 1 || metadata.ExpiresAt != payload.ExpiresAt || metadata.ReplayKeyVersion != config.CurrentReplayKeyVersion {
		t.Fatal("enterprise callback metadata changed")
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("native enterprise issuance declaration denied", err)
	}
	codec, _ := preparationFixture(t, i, config)
	disclosures := 0
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(ctx context.Context, _ uint16, token []byte) error {
		disclosures++
		grant, verifyErr := capability.Verify(ctx, string(token), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if verifyErr != nil || grant.EnvelopeDigest() != metadata.ProofFingerprint {
			t.Fatal("enterprise checkpoint lost original signed envelope", verifyErr)
		}
		want := payload
		want.ID = metadata.CapabilityID
		if !reflect.DeepEqual(grant.Payload(), want) {
			t.Fatal("enterprise checkpoint changed original signed callback payload")
		}
		return nil
	})
	if err != nil || disclosures != 1 {
		t.Fatal("enterprise checkpoint denied", err)
	}
	retained, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(context.Context, uint16, []byte) error {
		t.Fatal("retained checkpoint disclosed another bearer")
		return nil
	})
	if err != nil || !bytes.Equal(wire, retained) {
		t.Fatal("enterprise checkpoint replaced original custody", err)
	}
	codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b || restored.state.checkpointGeneration != 7 || restored.state.grants[0].EnvelopeDigest() != metadata.ProofFingerprint {
		t.Fatal("enterprise restoration lost original binding or generation", err)
	}
	restoredPlan, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(restoredPlan, plan) || !reflect.DeepEqual(restored.state.grants[0].Payload(), prepared.state.grants[0].Payload()) {
		t.Fatal("enterprise restoration replaced original metadata or validity", err)
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error {
		t.Fatal("restoration redisclosed enterprise bearer")
		return nil
	}) == nil {
		t.Fatal("restoration reopened enterprise bearer custody")
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow":        func(b *identity.CommandBinding) { b.AnonymousFlowID += "-foreign" },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"actor":       func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
	} {
		t.Run("restore foreign "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if _, err := codec.RestorePreparation(context.Background(), foreign, 7, plan, wire); err == nil {
				t.Fatal("enterprise checkpoint changed original scope")
			}
		})
	}
	if _, err := codec.RestorePreparation(context.Background(), b, 8, plan, wire); err == nil {
		t.Fatal("enterprise checkpoint changed original generation")
	}
	codec.clock = func() time.Time { return payload.ExpiresAt.Add(time.Second) }
	if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire); err == nil {
		t.Fatal("expired enterprise callback state renewed on restoration")
	}
}

func TestSSOOIDCIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, b, payload := ssoOIDCIssuerFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
		"social schema": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.SchemaID = "identity.oauth.signin-start.rp-v1"
		},
		"foreign schema":  func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaID += "-foreign" },
		"foreign version": func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
		"missing record":  func(b *identity.CommandBinding, _ *capability.Payload) { b.RecordID = "" },
		"foreign record": func(b *identity.CommandBinding, p *capability.Payload) {
			b.RecordID += "-foreign"
			p.Resource = b.RecordID
		},
		"missing actor":          func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorID = "" },
		"user actor":             func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectUser },
		"API key actor":          func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectAPIKey },
		"missing policy":         func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyID = "" },
		"missing policy version": func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyVersion = 0 },
		"missing correlation":    func(b *identity.CommandBinding, _ *capability.Payload) { b.CorrelationID = "" },
		"missing preauth flow":   func(b *identity.CommandBinding, _ *capability.Payload) { b.AnonymousFlowID = "" },
		"user subject": func(b *identity.CommandBinding, p *capability.Payload) {
			b.UserID, b.AnonymousFlowID, p.Subject = "user", "", "user"
		},
		"mixed subject":             func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID = "user" },
		"account link mode":         func(b *identity.CommandBinding, _ *capability.Payload) { b.LinkMode = identity.AccountLinkExplicit },
		"caller capability ID":      func(_ *identity.CommandBinding, p *capability.Payload) { p.ID = "caller-chosen" },
		"foreign subject":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Subject += "-foreign" },
		"foreign resource":          func(_ *identity.CommandBinding, p *capability.Payload) { p.Resource += "-foreign" },
		"foreign correlation":       func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID += "-foreign" },
		"missing correlation claim": func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID = "" },
		"social callback":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"SAML callback":             func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.sso.saml-callback" },
		"link grant":                func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.account.link-token" },
		"foreign tenant":            func(_ *identity.CommandBinding, p *capability.Payload) { p.Tenant += "-foreign" },
		"foreign audience":          func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences":        func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":                    func(_ *identity.CommandBinding, p *capability.Payload) { p.Bearer = true },
		"unlimited uses":            func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":             func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 2 },
		"missing issued time":       func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = time.Time{} },
		"fractional issued time":    func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Nanosecond) },
		"non UTC issued time": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.IssuedAt = p.IssuedAt.In(time.FixedZone("offset", 3600))
		},
		"non UTC not-before": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.NotBefore = p.NotBefore.In(time.FixedZone("offset", 3600))
		},
		"delayed validity": func(_ *identity.CommandBinding, p *capability.Payload) { p.NotBefore = p.NotBefore.Add(time.Second) },
		"fractional expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.Add(time.Nanosecond)
		},
		"non UTC expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.In(time.FixedZone("offset", 3600))
		},
		"extended lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second)
		},
		"zero lifetime": func(_ *identity.CommandBinding, p *capability.Payload) { p.ExpiresAt = p.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			foreign, input := b, payload
			mutate(&foreign, &input)
			if out, err := i.Prepare(context.Background(), foreign, []capability.Payload{input}); err == nil || out.state != nil {
				t.Fatal("enterprise issuance admitted a foreign callback-state profile")
			}
		})
	}
	if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload, payload}); err == nil || out.state != nil {
		t.Fatal("enterprise transaction acquired multiple callback-state grants")
	}
	for _, plan := range []identitypostgres.CapabilityIssuancePlan{
		{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"},
	} {
		if out, err := i.preparePlan(context.Background(), b, plan, []capability.Payload{payload}, false); err == nil || out.state != nil {
			t.Fatal("enterprise preauth flow admitted a user override")
		}
	}
}

func TestSSOOIDCIssuerRejectsForeignSignedScopeAndPlans(t *testing.T) {
	i, _, b, payload := ssoOIDCIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identitypostgres.CapabilityIssuancePlan){
		"social purpose":        func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.oauth.callback" },
		"multiple grants":       func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
		"registration override": func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = "user" },
		"reset override":        func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink override":    func(p *identitypostgres.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = "user" },
		"MFA override":          func(p *identitypostgres.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := plan
			foreign.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
			mutate(&foreign)
			if i.ValidateCapabilityIssuance(b, foreign) == nil {
				t.Fatal("enterprise declaration admitted a foreign issuance profile")
			}
		})
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":      func(p *capability.Payload) { p.Tenant += "-foreign" },
		"subject":     func(p *capability.Payload) { p.Subject += "-foreign" },
		"resource":    func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation": func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"purpose":     func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"lifetime":    func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(11 * time.Minute) },
	} {
		t.Run("signed foreign "+name, func(t *testing.T) {
			foreign := payload
			foreign.ID = plan.Grants[0].CapabilityID
			mutate(&foreign)
			proof, _, err := i.service.Issue(context.Background(), foreign)
			if err != nil {
				t.Fatal("foreign signed fixture failed", err)
			}
			grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(foreign.Operation), i.audience)
			if err != nil {
				t.Fatal("foreign signed fixture verification failed", err)
			}
			if _, err := i.grantSubjectPlan(b, b.AnonymousFlowID, grant, i.current); err == nil {
				t.Fatal("authenticated foreign enterprise scope admitted during restoration or persistence")
			}
		})
	}
	if _, err := i.PrepareOAuthCallbackConsumption(context.Background(), b, prepared.state.proofs[0], i.current); err == nil {
		t.Fatal("enterprise callback state entered social consumption")
	}
}
