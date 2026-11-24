package identitycapability

import (
	"context"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func samlLogoutRelayIssuanceFixture(t *testing.T) (*Issuer, IssuerConfig, identity.CommandBinding, kernel.CapabilityIssuancePlan) {
	t.Helper()
	i, config, binding, payload := samlLogoutRelayFixture(t)
	prepared, err := i.Prepare(context.Background(), binding, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original logout RelayState issuance preparation failed", err)
	}
	t.Cleanup(func() {
		_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
	})
	plan, err := prepared.Plan()
	if err != nil || i.ValidateCapabilityIssuance(binding, plan) != nil {
		t.Fatal("original logout RelayState issuance plan invalid", err)
	}
	return i, config, binding, plan
}

// Selection alone proves no durable outcome. Native recovery supplies the
// sealed RecoveryWork and checks absence or contradictions under its fence.
func TestSAMLLogoutRelayIssuanceAbsenceProfilePreservesOriginal(t *testing.T) {
	i, config, binding, plan := samlLogoutRelayIssuanceFixture(t)
	want := plan
	want.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	if !i.samlLogoutRelayAbsenceProfile(binding, plan) {
		t.Fatal("exact original logout RelayState cannot select fenced absence proof")
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys[3] = [32]byte{3}
	rotated, err := NewIssuer(config)
	if err != nil || !rotated.samlLogoutRelayAbsenceProfile(binding, plan) || !reflect.DeepEqual(plan, want) {
		t.Fatal("rotation replaced original logout RelayState issuance identity", err)
	}
	delete(config.RetainedReplayKeys, plan.Grants[0].ReplayKeyVersion)
	retired, err := NewIssuer(config)
	if err != nil || retired.samlLogoutRelayAbsenceProfile(binding, plan) {
		t.Fatal("retired original replay key selected logout RelayState absence proof", err)
	}
	var absent *Issuer
	if absent.samlLogoutRelayAbsenceProfile(binding, plan) {
		t.Fatal("absent issuer selected logout RelayState recovery")
	}
}

func TestSAMLLogoutRelayIssuanceAbsenceProfileRejectsBroaderScope(t *testing.T) {
	i, _, binding, original := samlLogoutRelayIssuanceFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *kernel.CapabilityIssuancePlan){
		"local logout operation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID = "identity.sso.saml-logout-start"
		},
		"settlement operation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID = "identity.sso.saml-logout-relay-settle"
		},
		"foreign schema": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaID += "-foreign" },
		"schema version": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaVersion++ },
		"foreign record": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.RecordID += "-foreign" },
		"missing user":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.UserID = "" },
		"foreign actor":  func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.ActorID += "-foreign" },
		"service actor": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"API key actor": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.ActorKind = authorization.SubjectAPIKey
		},
		"anonymous flow":              func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.AnonymousFlowID = "preauth" },
		"missing tenant":              func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.TenantID = "" },
		"malformed command":           func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.CommandID = "not-a-command" },
		"missing local correlation":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.CorrelationID = "" },
		"malformed local correlation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.CorrelationID = "not-a-command" },
		"zero local correlation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.CorrelationID = "AAAAAAAAAAAAAAAAAAAAAA"
		},
		"issue is local correlation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.CorrelationID = string(b.CommandID)
		},
		"missing policy":         func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.PolicyID = "" },
		"missing policy version": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.PolicyVersion = 0 },
		"link mode": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.LinkMode = identity.AccountLinkExplicit
		},
		"signup override": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.RegistrationUserID = "user" },
		"reset override":  func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink override": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.MagicLinkRecipientUserID = "user"
		},
		"MFA override": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
		"no grant":     func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants = nil },
		"multiple grants": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants = append(p.Grants, p.Grants[0])
		},
		"ACS purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.sso.saml-acs"
		},
		"IdP confirmation purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.sso.saml-idp-init"
		},
		"local logout purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.sso.saml-logout-start"
		},
		"foreign contributor":   func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Contributor.Owner = "foreign" },
		"missing capability ID": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].CapabilityID = "" },
		"missing replay digest": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ReplayDigest = [32]byte{}
		},
		"foreign replay key": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].ReplayKeyVersion = 99 },
		"multiple uses":      func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].MaxUses = 2 },
		"missing envelope": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ProofFingerprint = [32]byte{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, plan := binding, original
			plan.Grants = append([]kernel.CapabilityPlan(nil), original.Grants...)
			mutate(&b, &plan)
			if i.samlLogoutRelayAbsenceProfile(b, plan) {
				t.Fatal("foreign or broader issuance borrowed logout RelayState absence proof")
			}
		})
	}
}

func TestSAMLLogoutRelayIssuanceAbsenceProfileKeepsSiblingProfilesIsolated(t *testing.T) {
	for name, fixture := range map[string]func(testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload){
		"ordinary":        issuerFixture,
		"SAML SP start":   ssoSAMLIssuerFixture,
		"OIDC start":      ssoOIDCIssuerFixture,
		"OIDC link start": ssoOIDCExplicitLinkIssuerFixture,
		"OAuth2 start":    ssoOAuth2IssuerFixture,
	} {
		t.Run(name, func(t *testing.T) {
			i, _, binding, payload := fixture(t)
			prepared, err := i.Prepare(context.Background(), binding, []capability.Payload{payload})
			if err != nil {
				t.Fatal("sibling issuance fixture failed", err)
			}
			t.Cleanup(func() {
				_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
			})
			plan, err := prepared.Plan()
			if err != nil || i.samlLogoutRelayAbsenceProfile(binding, plan) {
				t.Fatal("sibling issuance borrowed logout RelayState recovery", err)
			}
		})
	}
	i, _, binding, plan := samlIDPArrivalIssuanceFixture(t)
	if i.samlLogoutRelayAbsenceProfile(binding, plan) || !i.samlIDPArrivalAbsenceProfile(binding, plan) {
		t.Fatal("logout RelayState changed IdP arrival recovery selection")
	}
	i, _, binding, plan = anonymousUpgradeIssuanceFixture(t)
	if i.samlLogoutRelayAbsenceProfile(binding, plan) || !i.anonymousUpgradeAbsenceProfile(binding, plan) {
		t.Fatal("logout RelayState changed anonymous upgrade recovery selection")
	}
	i, _, binding, plan = organizationInvitationIssuanceFixture(t)
	if i.samlLogoutRelayAbsenceProfile(binding, plan) || !i.organizationInvitationAbsenceProfile(binding, plan) {
		t.Fatal("logout RelayState changed organization invitation recovery selection")
	}
}
