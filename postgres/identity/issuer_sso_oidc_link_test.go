package identitycapability

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func ssoOIDCExplicitLinkIssuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	i, config, b, payload := ssoOIDCIssuerFixture(t)
	b.SchemaID = "identity.sso.signin-start.oidc-link-v1"
	b.UserID, b.AnonymousFlowID = "enterprise-member", ""
	b.ActorID, b.ActorKind = identity.ActorID(b.UserID), authorization.SubjectUser
	payload.Subject = string(b.UserID)
	payload.Caveats = map[string]string{"rp.binding": "original-member-consent"}
	return i, config, b, payload
}

func TestSSOOIDCExplicitLinkIssuerPreservesMemberConsent(t *testing.T) {
	i, config, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("valid member-bound enterprise consent denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		t.Fatal("member callback-state plan missing", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("member callback-state declaration denied", err)
	}
	metadata := plan.Grants[0]
	if metadata.ExpiresAt != payload.ExpiresAt || metadata.MaxUses != 1 || metadata.ReplayKeyVersion != config.CurrentReplayKeyVersion {
		t.Fatal("member callback-state witness changed")
	}
	want := payload
	want.ID = metadata.CapabilityID
	if !reflect.DeepEqual(prepared.state.grants[0].Payload(), want) {
		t.Fatal("member subject or signed consent changed")
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(context.Context, uint16, []byte) error { return nil })
	if err != nil {
		t.Fatal("member checkpoint denied", err)
	}
	codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil {
		t.Fatal("member checkpoint restoration denied", err)
	}
	restoredPlan, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(restoredPlan, plan) || !reflect.DeepEqual(restored.state.grants[0].Payload(), want) {
		t.Fatal("restoration changed original member consent or replay/expiry witness", err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"member":      func(b *identity.CommandBinding) { b.UserID += "-foreign"; b.ActorID = identity.ActorID(b.UserID) },
		"actor":       func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"policy":      func(b *identity.CommandBinding) { b.PolicyVersion++ },
	} {
		t.Run("restore foreign "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if _, err := codec.RestorePreparation(context.Background(), foreign, 7, plan, wire); err == nil {
				t.Fatal("member checkpoint admitted another original binding")
			}
		})
	}
	if _, err := codec.RestorePreparation(context.Background(), b, 8, plan, wire); err == nil {
		t.Fatal("member checkpoint changed original generation")
	}
	codec.clock = func() time.Time { return payload.ExpiresAt }
	if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire); err == nil {
		t.Fatal("member checkpoint renewed original expiry")
	}
}

func TestSSOOIDCExplicitLinkIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
		"anonymous schema": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.SchemaID = "identity.sso.signin-start.oidc-v1"
		},
		"social schema": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.SchemaID = "identity.account.link-start.rp-v1"
		},
		"foreign version": func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
		"missing member":  func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID = "" },
		"anonymous flow":  func(b *identity.CommandBinding, _ *capability.Payload) { b.AnonymousFlowID = "preauth" },
		"service actor": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"API key actor":  func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectAPIKey },
		"foreign actor":  func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorID += "-foreign" },
		"missing record": func(b *identity.CommandBinding, _ *capability.Payload) { b.RecordID = "" },
		"foreign record": func(b *identity.CommandBinding, p *capability.Payload) {
			b.RecordID += "-foreign"
			p.Resource = b.RecordID
		},
		"link mode":           func(b *identity.CommandBinding, _ *capability.Payload) { b.LinkMode = identity.AccountLinkExplicit },
		"foreign subject":     func(_ *identity.CommandBinding, p *capability.Payload) { p.Subject += "-foreign" },
		"foreign tenant":      func(_ *identity.CommandBinding, p *capability.Payload) { p.Tenant += "-foreign" },
		"foreign resource":    func(_ *identity.CommandBinding, p *capability.Payload) { p.Resource += "-foreign" },
		"foreign correlation": func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID += "-foreign" },
		"final link grant":    func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.account.link-token" },
		"social callback":     func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"foreign audience":    func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences":  func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":              func(_ *identity.CommandBinding, p *capability.Payload) { p.Bearer = true },
		"reusable":            func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":       func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 2 },
		"extended lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			foreign, input := b, payload
			mutate(&foreign, &input)
			if out, err := i.Prepare(context.Background(), foreign, []capability.Payload{input}); err == nil || out.state != nil {
				t.Fatal("member issuance admitted a foreign profile")
			}
		})
	}
	if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload, payload}); err == nil || out.state != nil {
		t.Fatal("member initiation acquired multiple callback-state grants")
	}
	for _, override := range []identitypostgres.CapabilityIssuancePlan{
		{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"},
	} {
		if out, err := i.preparePlan(context.Background(), b, override, []capability.Payload{payload}, false); err == nil || out.state != nil {
			t.Fatal("member issuance admitted a subject override")
		}
	}
}
