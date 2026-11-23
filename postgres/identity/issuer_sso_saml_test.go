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

func ssoSAMLIssuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	i, config, b, payload := ssoOIDCIssuerFixture(t)
	b.OperationID, b.SchemaID = "identity.sso.saml-start", "identity.sso.saml-start.v1"
	b.PolicyID = "enterprise-saml-policy"
	payload.Operation = "identity.sso.saml-acs"
	payload.ExpiresAt = payload.IssuedAt.Add(5 * time.Minute)
	payload.Caveats = map[string]string{"rp.binding": "original-enterprise-saml-intent"}
	return i, config, b, payload
}

func TestSSOSAMLIssuerPreservesOriginalRelayStateGrant(t *testing.T) {
	i, config, b, payload := ssoSAMLIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("native SAML RelayState preparation denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.RegistrationUserID != "" || plan.ResetRecipientUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" {
		t.Fatal("SAML preauth flow became a user override", err)
	}
	metadata := plan.Grants[0]
	if metadata.Purpose != "identity.sso.saml-acs" || metadata.MaxUses != 1 || metadata.ExpiresAt != payload.ExpiresAt || metadata.ReplayKeyVersion != config.CurrentReplayKeyVersion {
		t.Fatal("SAML RelayState metadata changed")
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("native SAML issuance declaration denied", err)
	}
	codec, _ := preparationFixture(t, i, config)
	disclosures := 0
	var borrowed []byte
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(ctx context.Context, _ uint16, token []byte) error {
		disclosures++
		borrowed = token
		grant, verifyErr := capability.Verify(ctx, string(token), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if verifyErr != nil || grant.EnvelopeDigest() != metadata.ProofFingerprint {
			t.Fatal("SAML checkpoint lost original signed envelope", verifyErr)
		}
		want := payload
		want.ID = metadata.CapabilityID
		if !reflect.DeepEqual(grant.Payload(), want) {
			t.Fatal("SAML checkpoint changed original signed RelayState payload")
		}
		return nil
	})
	if err != nil || disclosures != 1 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("SAML checkpoint denied or retained borrowed proof", err)
	}
	retained, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(context.Context, uint16, []byte) error {
		t.Fatal("retained checkpoint disclosed another proof")
		return nil
	})
	if err != nil || !bytes.Equal(wire, retained) {
		t.Fatal("SAML checkpoint replaced original custody", err)
	}
	codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.binding != b || restored.state.checkpointGeneration != 7 || restored.state.grants[0].EnvelopeDigest() != metadata.ProofFingerprint {
		t.Fatal("SAML restoration lost original binding or generation", err)
	}
	restoredPlan, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(restoredPlan, plan) || !reflect.DeepEqual(restored.state.grants[0].Payload(), prepared.state.grants[0].Payload()) {
		t.Fatal("SAML restoration replaced original metadata or validity", err)
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error {
		t.Fatal("restoration redisclosed SAML proof")
		return nil
	}) == nil {
		t.Fatal("restoration reopened SAML proof custody")
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow":        func(b *identity.CommandBinding) { b.AnonymousFlowID += "-foreign" },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"actor":       func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
		"record":      func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"policy":      func(b *identity.CommandBinding) { b.PolicyVersion++ },
		"operation":   func(b *identity.CommandBinding) { b.OperationID = "identity.sso.signin-start" },
		"schema":      func(b *identity.CommandBinding) { b.SchemaID = "identity.sso.signin-start.oidc-v1" },
	} {
		t.Run("restore foreign "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if _, err := codec.RestorePreparation(context.Background(), foreign, 7, plan, wire); err == nil {
				t.Fatal("SAML checkpoint changed original scope")
			}
		})
	}
	if _, err := codec.RestorePreparation(context.Background(), b, 8, plan, wire); err == nil {
		t.Fatal("SAML checkpoint changed original generation")
	}
	foreignWire := append([]byte(nil), wire...)
	foreignWire[len(foreignWire)-1] ^= 1
	if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, foreignWire); err == nil {
		t.Fatal("SAML checkpoint admitted substituted ciphertext")
	}
	codec.clock = func() time.Time { return payload.ExpiresAt }
	if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire); err == nil {
		t.Fatal("expired SAML RelayState renewed on restoration")
	}
}

func TestSSOSAMLIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, b, payload := ssoSAMLIssuerFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
		"OIDC schema": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.SchemaID = "identity.sso.signin-start.oidc-v1"
		},
		"OAuth2 schema": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.SchemaID = "identity.sso.signin-start.oauth2-v1"
		},
		"social schema": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.SchemaID = "identity.oauth.signin-start.rp-v1"
		},
		"signin-start operation": func(b *identity.CommandBinding, _ *capability.Payload) { b.OperationID = "identity.sso.signin-start" },
		"foreign schema":         func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaID += "-foreign" },
		"foreign version":        func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
		"missing record":         func(b *identity.CommandBinding, _ *capability.Payload) { b.RecordID = "" },
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
		"OIDC callback":             func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.sso.oidc-callback" },
		"OAuth2 callback":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.sso.oauth-callback" },
		"social callback":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.oauth.callback" },
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
			p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second)
		},
		"OIDC lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.IssuedAt.Add(10 * time.Minute)
		},
		"zero lifetime": func(_ *identity.CommandBinding, p *capability.Payload) { p.ExpiresAt = p.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			foreign, input := b, payload
			mutate(&foreign, &input)
			if out, err := i.Prepare(context.Background(), foreign, []capability.Payload{input}); err == nil || out.state != nil {
				t.Fatal("SAML issuance admitted a foreign RelayState profile")
			}
		})
	}
	if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload, payload}); err == nil || out.state != nil {
		t.Fatal("SAML transaction acquired multiple RelayState grants")
	}
	for _, plan := range []identitypostgres.CapabilityIssuancePlan{
		{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"},
	} {
		if out, err := i.preparePlan(context.Background(), b, plan, []capability.Payload{payload}, false); err == nil || out.state != nil {
			t.Fatal("SAML preauth flow admitted a user override")
		}
	}
}

func TestSSOSAMLIssuerRejectsForeignSignedScopeAndPreparedCustody(t *testing.T) {
	i, config, b, payload := ssoSAMLIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identitypostgres.CapabilityIssuancePlan){
		"OIDC purpose":          func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.sso.oidc-callback" },
		"OAuth2 purpose":        func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.sso.oauth-callback" },
		"social purpose":        func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.oauth.callback" },
		"multiple grants":       func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
		"registration override": func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = "user" },
		"reset override":        func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink override":    func(p *identitypostgres.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = "user" },
		"MFA override":          func(p *identitypostgres.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
		"missing fingerprint":   func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].ProofFingerprint = [32]byte{} },
		"unknown replay key":    func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].ReplayKeyVersion = 99 },
		"reusable":              func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].MaxUses = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := plan
			foreign.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
			mutate(&foreign)
			if i.ValidateCapabilityIssuance(b, foreign) == nil {
				t.Fatal("SAML declaration admitted a foreign issuance profile")
			}
			if _, err := codec.RestorePreparation(context.Background(), b, 7, foreign, wire); err == nil {
				t.Fatal("SAML checkpoint admitted substituted metadata")
			}
		})
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":         func(p *capability.Payload) { p.Tenant += "-foreign" },
		"subject":        func(p *capability.Payload) { p.Subject += "-foreign" },
		"resource":       func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":    func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"OIDC purpose":   func(p *capability.Payload) { p.Operation = "identity.sso.oidc-callback" },
		"OAuth2 purpose": func(p *capability.Payload) { p.Operation = "identity.sso.oauth-callback" },
		"social purpose": func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"lifetime":       func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
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
				t.Fatal("authenticated foreign SAML scope admitted during restoration or persistence")
			}
		})
	}
	for name, mutate := range map[string]func(*identitypostgres.CapabilityPlan){
		"capability ID":       func(p *identitypostgres.CapabilityPlan) { p.CapabilityID += "-foreign" },
		"fingerprint":         func(p *identitypostgres.CapabilityPlan) { p.ProofFingerprint[0] ^= 1 },
		"replay digest":       func(p *identitypostgres.CapabilityPlan) { p.ReplayDigest[0] ^= 1 },
		"retained replay key": func(p *identitypostgres.CapabilityPlan) { p.ReplayKeyVersion = 1 },
		"expiry":              func(p *identitypostgres.CapabilityPlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
	} {
		t.Run("restore substituted "+name, func(t *testing.T) {
			foreign := plan
			foreign.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
			mutate(&foreign.Grants[0])
			if err := i.ValidateCapabilityIssuance(b, foreign); err != nil {
				t.Fatal("substituted metadata fixture is not structurally valid", err)
			}
			if _, err := codec.RestorePreparation(context.Background(), b, 7, foreign, wire); err == nil {
				t.Fatal("SAML checkpoint authenticated substituted original custody")
			}
		})
	}
	foreignIssuer, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	foreignCodec, _ := preparationFixture(t, foreignIssuer, config)
	if _, err := foreignCodec.CheckpointPreparation(context.Background(), prepared, 7, nil); err == nil {
		t.Fatal("another issuer acquired original prepared SAML custody")
	}
}
