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

func oneTapIssuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	i, config, b, payload := issuerFixture(t)
	flow, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.oauth.onetap-start", "oauth-onetap-start-v1", 1
	b.UserID, b.AnonymousFlowID, b.RecordID = "", string(flow), string(flow)
	b.ActorID, b.ActorKind = "onetap-service", authorization.SubjectServiceAccount
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "onetap-policy", 1, "original-onetap-correlation"
	payload.Subject, payload.Resource = b.AnonymousFlowID, b.RecordID
	payload.Operation, payload.CorrelationID = "identity.oauth.onetap-callback", b.CorrelationID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.ExpiresAt = payload.IssuedAt.Add(5 * time.Minute)
	return i, config, b, payload
}

func TestOneTapIssuerPreservesOriginalCallbackGrant(t *testing.T) {
	i, config, b, payload := oneTapIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("native One Tap start callback preparation denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.RegistrationUserID != "" || plan.ResetRecipientUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" {
		t.Fatal("One Tap flow became a user override", err)
	}
	metadata := plan.Grants[0]
	if metadata.Purpose != "identity.oauth.onetap-callback" || metadata.MaxUses != 1 || metadata.ExpiresAt != payload.ExpiresAt || metadata.ReplayKeyVersion != config.CurrentReplayKeyVersion {
		t.Fatal("One Tap callback metadata changed")
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("native One Tap issuance declaration denied", err)
	}
	codec, _ := preparationFixture(t, i, config)
	disclosures := 0
	var borrowed []byte
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(ctx context.Context, _ uint16, token []byte) error {
		disclosures++
		borrowed = token
		grant, verifyErr := capability.Verify(ctx, string(token), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if verifyErr != nil || grant.EnvelopeDigest() != metadata.ProofFingerprint {
			t.Fatal("checkpoint lost original signed One Tap envelope", verifyErr)
		}
		want := payload
		want.ID = metadata.CapabilityID
		if !reflect.DeepEqual(grant.Payload(), want) {
			t.Fatal("checkpoint changed original signed One Tap scope")
		}
		return nil
	})
	if err != nil || disclosures != 1 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("One Tap checkpoint denied or retained borrowed plaintext", err)
	}
	retained, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(context.Context, uint16, []byte) error {
		t.Fatal("checkpoint redisclosed original proof")
		return nil
	})
	if err != nil || !bytes.Equal(wire, retained) {
		t.Fatal("checkpoint replaced original custody", err)
	}
	codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil {
		t.Fatal("original One Tap checkpoint restoration denied", err)
	}
	restoredPlan, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(restoredPlan, plan) || restored.state.binding != b || restored.state.checkpointGeneration != 7 {
		t.Fatal("restoration replaced original One Tap binding or metadata", err)
	}
	grants, err := restored.Grants()
	if err != nil || len(grants) != 1 || grants[0].EnvelopeDigest() != metadata.ProofFingerprint || !reflect.DeepEqual(grants[0].Payload(), prepared.state.grants[0].Payload()) {
		t.Fatal("restoration replaced original signed One Tap grant", err)
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error {
		t.Fatal("restoration redisclosed One Tap proof")
		return nil
	}) == nil {
		t.Fatal("restoration reopened proof custody")
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant":      func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow":        func(b *identity.CommandBinding) { b.AnonymousFlowID += "-foreign"; b.RecordID = b.AnonymousFlowID },
		"correlation": func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"actor":       func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
	} {
		t.Run("restore foreign "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if _, err := codec.RestorePreparation(context.Background(), foreign, 7, plan, wire); err == nil {
				t.Fatal("checkpoint changed original One Tap scope")
			}
		})
	}
	if _, err := codec.RestorePreparation(context.Background(), b, 8, plan, wire); err == nil {
		t.Fatal("checkpoint changed original generation")
	}
	codec.clock = func() time.Time { return payload.ExpiresAt }
	if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire); err == nil {
		t.Fatal("expired One Tap callback renewed on restoration")
	}
}

func TestOneTapIssuerRejectsForeignProfiles(t *testing.T) {
	i, _, b, payload := oneTapIssuerFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
		"foreign schema":  func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaID += "-foreign" },
		"foreign version": func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
		"missing command": func(b *identity.CommandBinding, _ *capability.Payload) { b.CommandID = "" },
		"missing tenant":  func(b *identity.CommandBinding, _ *capability.Payload) { b.TenantID = "" },
		"missing flow":    func(b *identity.CommandBinding, _ *capability.Payload) { b.AnonymousFlowID = "" },
		"foreign record": func(b *identity.CommandBinding, p *capability.Payload) {
			b.RecordID = "other-flow"
			p.Resource = b.RecordID
		},
		"user subject": func(b *identity.CommandBinding, p *capability.Payload) {
			b.UserID, b.AnonymousFlowID, p.Subject = "user", "", "user"
		},
		"mixed subject":              func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID = "user" },
		"missing actor":              func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorID = "" },
		"user actor":                 func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectUser },
		"API key actor":              func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectAPIKey },
		"missing policy":             func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyID = "" },
		"missing policy version":     func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyVersion = 0 },
		"missing correlation":        func(b *identity.CommandBinding, _ *capability.Payload) { b.CorrelationID = "" },
		"link mode":                  func(b *identity.CommandBinding, _ *capability.Payload) { b.LinkMode = identity.AccountLinkExplicit },
		"caller capability ID":       func(_ *identity.CommandBinding, p *capability.Payload) { p.ID = "caller-chosen" },
		"foreign subject":            func(_ *identity.CommandBinding, p *capability.Payload) { p.Subject += "-foreign" },
		"foreign tenant":             func(_ *identity.CommandBinding, p *capability.Payload) { p.Tenant += "-foreign" },
		"foreign resource":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Resource += "-foreign" },
		"foreign correlation":        func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID += "-foreign" },
		"missing signed correlation": func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID = "" },
		"RP callback":                func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"SSO callback":               func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.sso.oidc-callback" },
		"final link grant":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.account.link-token" },
		"foreign audience":           func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences":         func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":                     func(_ *identity.CommandBinding, p *capability.Payload) { p.Bearer = true },
		"unlimited uses":             func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":              func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 2 },
		"missing issued time":        func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = time.Time{} },
		"fractional issued time":     func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Nanosecond) },
		"non UTC issued time": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.IssuedAt = p.IssuedAt.In(time.FixedZone("offset", 3600))
		},
		"non UTC not-before": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.NotBefore = p.NotBefore.In(time.FixedZone("offset", 3600))
		},
		"changed not-before": func(_ *identity.CommandBinding, p *capability.Payload) { p.NotBefore = p.NotBefore.Add(-time.Second) },
		"fractional expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.Add(time.Nanosecond)
		},
		"non UTC expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.In(time.FixedZone("offset", 3600))
		},
		"extended lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second)
		},
		"zero lifetime": func(_ *identity.CommandBinding, p *capability.Payload) { p.ExpiresAt = p.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			foreign, input := b, payload
			mutate(&foreign, &input)
			if out, err := i.Prepare(context.Background(), foreign, []capability.Payload{input}); err == nil || out.state != nil {
				t.Fatal("One Tap issuance admitted foreign profile")
			}
		})
	}
	for _, inputs := range [][]capability.Payload{nil, {payload, payload}} {
		if out, err := i.Prepare(context.Background(), b, inputs); err == nil || out.state != nil {
			t.Fatal("One Tap issuance did not require exactly one callback grant")
		}
	}
	for _, plan := range []identitypostgres.CapabilityIssuancePlan{
		{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"},
	} {
		if out, err := i.preparePlan(context.Background(), b, plan, []capability.Payload{payload}, false); err == nil || out.state != nil {
			t.Fatal("One Tap flow admitted user override")
		}
	}
}

func TestOneTapIssuerRejectsForeignSignedScopeAndPlans(t *testing.T) {
	i, _, b, payload := oneTapIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identitypostgres.CapabilityIssuancePlan){
		"foreign purpose":       func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.oauth.callback" },
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
				t.Fatal("One Tap declaration admitted foreign profile")
			}
		})
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":      func(p *capability.Payload) { p.Tenant += "-foreign" },
		"subject":     func(p *capability.Payload) { p.Subject += "-foreign" },
		"resource":    func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation": func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"purpose":     func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"not-before":  func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"lifetime":    func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
	} {
		t.Run("signed foreign "+name, func(t *testing.T) {
			foreign := payload
			foreign.ID = plan.Grants[0].CapabilityID
			mutate(&foreign)
			proof, _, err := i.service.Issue(context.Background(), foreign)
			if err != nil {
				t.Fatal("foreign signed fixture failed", err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(foreign.Operation), i.audience)
			if err != nil {
				t.Fatal("foreign signed fixture verification failed", err)
			}
			if _, err := i.grantSubjectPlan(b, b.AnonymousFlowID, grant, i.current); err == nil {
				t.Fatal("authenticated foreign One Tap scope admitted during restoration or persistence")
			}
		})
	}
}

func TestOneTapIssuerRejectsPurposeBorrowing(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	b.OperationID = "identity.user.create"
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	plan.Grants[0].Purpose = "identity.oauth.onetap-callback"
	if i.ValidateCapabilityIssuance(b, plan) == nil {
		t.Fatal("unrelated operation borrowed One Tap purpose in retained declaration")
	}
	payload.Operation = "identity.oauth.onetap-callback"
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil || out.state != nil {
		t.Fatal("unrelated operation borrowed One Tap callback issuance")
	}
	payload.ID = "foreign-original-grant"
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	grant, err := i.service.Verify(context.Background(), proof, "identity.oauth.onetap-callback", i.audience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.grantSubjectPlan(b, string(b.UserID), grant, i.current); err == nil {
		t.Fatal("unrelated signed purpose admitted during restoration or persistence")
	}
}
