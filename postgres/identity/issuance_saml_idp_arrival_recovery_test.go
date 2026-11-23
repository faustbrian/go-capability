package identitycapability

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func samlIDPArrivalIssuanceFixture(t *testing.T) (*Issuer, IssuerConfig, identity.CommandBinding, kernel.CapabilityIssuancePlan) {
	t.Helper()
	i, config, binding, payload := issuerFixture(t)
	binding.ActorID, binding.ActorKind = "saml-arrival-service", authorization.SubjectServiceAccount
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = "identity.sso.saml-idp-prepare", "sso-enterprise-saml-idp-prepare-v1", 1
	binding.RecordID = string(binding.CommandID)
	binding.PolicyID, binding.PolicyVersion = "enterprise-saml-policy", 1
	binding.CorrelationID = "original-saml-idp-arrival"
	payload.Operation, payload.Resource = "identity.sso.saml-idp-init", binding.RecordID
	payload.CorrelationID = binding.CorrelationID
	prepared, err := i.Prepare(context.Background(), binding, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original SAML IdP arrival issuance preparation failed", err)
	}
	t.Cleanup(func() {
		_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
	})
	plan, err := prepared.Plan()
	if err != nil || i.ValidateCapabilityIssuance(binding, plan) != nil {
		t.Fatal("original SAML IdP arrival issuance plan invalid", err)
	}
	return i, config, binding, plan
}

// These cases select the existing fenced absence proof, not a command outcome.
// Native SSO recovery must exercise its sealed RecoveryWork against PostgreSQL;
// metadata alone cannot establish either durable absence or grant authority.
func TestSAMLIDPArrivalIssuanceAbsenceProfilePreservesOriginal(t *testing.T) {
	i, config, binding, plan := samlIDPArrivalIssuanceFixture(t)
	want := plan
	want.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	if !i.samlIDPArrivalAbsenceProfile(binding, plan) {
		t.Fatal("exact original SAML IdP arrival cannot select fenced absence proof")
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys[3] = [32]byte{3}
	rotated, err := NewIssuer(config)
	if err != nil || !rotated.samlIDPArrivalAbsenceProfile(binding, plan) || !reflect.DeepEqual(plan, want) {
		t.Fatal("rotation replaced original SAML IdP arrival issuance identity", err)
	}
	expired := plan
	expired.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	expired.Grants[0].ExpiresAt = time.Unix(1, 0).UTC()
	if !i.samlIDPArrivalAbsenceProfile(binding, expired) || expired.Grants[0].ExpiresAt != time.Unix(1, 0).UTC() {
		t.Fatal("historical expiry was renewed or mistaken for absence evidence")
	}
	delete(config.RetainedReplayKeys, plan.Grants[0].ReplayKeyVersion)
	retired, err := NewIssuer(config)
	if err != nil || retired.samlIDPArrivalAbsenceProfile(binding, plan) {
		t.Fatal("retired original replay key selected absence proof", err)
	}
	var absent *Issuer
	if absent.samlIDPArrivalAbsenceProfile(binding, plan) {
		t.Fatal("absent issuer selected recovery")
	}
}

func TestSAMLIDPArrivalIssuanceAbsenceProfileRejectsBroaderScope(t *testing.T) {
	i, _, binding, original := samlIDPArrivalIssuanceFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *kernel.CapabilityIssuancePlan){
		"ordinary-operation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID = "identity.profile.update"
		},
		"confirmation-operation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID = "identity.sso.saml-idp-init"
		},
		"SP-start-operation": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID = "identity.sso.saml-start"
		},
		"foreign-schema":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaID += "-foreign" },
		"schema-version":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaVersion++ },
		"missing-record":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.RecordID = "" },
		"different-record": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.RecordID += "-foreign" },
		"missing-actor":    func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.ActorID = "" },
		"user-actor": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.ActorKind = authorization.SubjectUser
		},
		"API-key-actor": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.ActorKind = authorization.SubjectAPIKey
		},
		"missing-user": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.UserID = "" },
		"anonymous-subject": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.UserID, b.AnonymousFlowID = "", "preauth-flow"
		},
		"mixed-subject":  func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.AnonymousFlowID = "preauth-flow" },
		"missing-tenant": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.TenantID = "" },
		"malformed-command": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.CommandID, b.RecordID = "invalid", "invalid"
		},
		"zero-command": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.CommandID, b.RecordID = "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA"
		},
		"missing-policy":         func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.PolicyID = "" },
		"missing-policy-version": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.PolicyVersion = 0 },
		"missing-correlation":    func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.CorrelationID = "" },
		"link-mode": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.LinkMode = identity.AccountLinkExplicit
		},
		"signup-override": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.RegistrationUserID = "new-user" },
		"reset-override":  func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink-override": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.MagicLinkRecipientUserID = "user"
		},
		"MFA-override": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
		"no-grant":     func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants = nil },
		"multiple-grants": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants = append(p.Grants, p.Grants[0])
		},
		"foreign-purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.identifier.verify"
		},
		"SP-ACS-purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.sso.saml-acs"
		},
		"foreign-owner": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Contributor.Owner = "foreign" },
		"foreign-contract": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Contributor.ContractID = "foreign"
		},
		"foreign-version":       func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Contributor.Version++ },
		"missing-capability-ID": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].CapabilityID = "" },
		"missing-replay-digest": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ReplayDigest = [32]byte{}
		},
		"foreign-replay-key": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].ReplayKeyVersion = 99 },
		"multi-use":          func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].MaxUses = 2 },
		"no-envelope": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ProofFingerprint = [32]byte{}
		},
		"no-expiry": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ExpiresAt = time.Time{}
		},
		"fractional-expiry": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ExpiresAt = p.Grants[0].ExpiresAt.Add(time.Nanosecond)
		},
		"foreign-expiry-zone": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ExpiresAt = p.Grants[0].ExpiresAt.In(time.FixedZone("foreign", 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, plan := binding, original
			plan.Grants = append([]kernel.CapabilityPlan(nil), original.Grants...)
			mutate(&b, &plan)
			if i.samlIDPArrivalAbsenceProfile(b, plan) {
				t.Fatal("foreign or broader issuance borrowed SAML IdP arrival absence proof")
			}
		})
	}
}

func TestSAMLIDPArrivalIssuanceAbsenceProfileKeepsSiblingProfilesIsolated(t *testing.T) {
	for name, fixture := range map[string]func(testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload){
		"ordinary":        issuerFixture,
		"SAML-SP-start":   ssoSAMLIssuerFixture,
		"OIDC-start":      ssoOIDCIssuerFixture,
		"OIDC-link-start": ssoOIDCExplicitLinkIssuerFixture,
		"OAuth2-start":    ssoOAuth2IssuerFixture,
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
			if err != nil || i.samlIDPArrivalAbsenceProfile(binding, plan) {
				t.Fatal("sibling issuance borrowed SAML IdP arrival recovery", err)
			}
		})
	}
	i, _, binding, plan := anonymousUpgradeIssuanceFixture(t)
	if i.samlIDPArrivalAbsenceProfile(binding, plan) || !i.anonymousUpgradeAbsenceProfile(binding, plan) {
		t.Fatal("SAML IdP arrival changed anonymous upgrade recovery selection")
	}
	i, _, binding, plan = organizationInvitationIssuanceFixture(t)
	if i.samlIDPArrivalAbsenceProfile(binding, plan) || !i.organizationInvitationAbsenceProfile(binding, plan) {
		t.Fatal("SAML IdP arrival changed organization invitation recovery selection")
	}
}
