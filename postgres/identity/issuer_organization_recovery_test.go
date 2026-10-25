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

func organizationInvitationIssuanceFixture(t *testing.T) (*Issuer, IssuerConfig, identity.CommandBinding, kernel.CapabilityIssuancePlan) {
	t.Helper()
	i, config, binding, payload := issuerFixture(t)
	binding.ActorID, binding.ActorKind = "inviting-owner", authorization.SubjectUser
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = "identity.organization.invitation-send", "organization-invitation-send", 1
	binding.RecordID, binding.PolicyID, binding.PolicyVersion = "invitation", "organization-policy", 9
	binding.CorrelationID = "original-invitation-recovery"
	payload.Operation, payload.Resource = "identity.organization.invitation.accept", binding.RecordID
	payload.Caveats = map[string]string{"organization.id": "organization", "organization.invitation-version": "1", "organization.role": "member", "organization.recipient-identifier": "verified-email", "organization.recipient-identifier-version": "1"}
	prepared, err := i.Prepare(context.Background(), binding, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original invitation issuance preparation failed", err)
	}
	t.Cleanup(func() {
		_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
	})
	plan, err := prepared.Plan()
	if err != nil || i.ValidateCapabilityIssuance(binding, plan) != nil {
		t.Fatal("original invitation issuance plan invalid", err)
	}
	return i, config, binding, plan
}

// These cases constrain profile selection, not durable absence. The actual
// native organization consumer exercises expired-lease recovery after a real
// deferred COMMIT rollback; no fabricated RecoveryWork is used here.
func TestOrganizationInvitationIssuanceAbsenceProfilePreservesOriginal(t *testing.T) {
	i, config, binding, plan := organizationInvitationIssuanceFixture(t)
	want := plan
	want.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	if !i.organizationInvitationAbsenceProfile(binding, plan) {
		t.Fatal("exact original invitation cannot select fenced absence proof")
	}
	// The inviter and recipient are deliberately different users; recovery must
	// preserve both roles, not relabel the original command as self-service.
	if string(binding.ActorID) == string(binding.UserID) {
		t.Fatal("fixture lost distinct original inviter and recipient")
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys[3] = [32]byte{3}
	rotated, err := NewIssuer(config)
	if err != nil || !rotated.organizationInvitationAbsenceProfile(binding, plan) || !reflect.DeepEqual(plan, want) {
		t.Fatal("rotation replaced original invocation or proof custody", err)
	}
	expired := plan
	expired.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	expired.Grants[0].ExpiresAt = time.Unix(1, 0).UTC()
	if !i.organizationInvitationAbsenceProfile(binding, expired) || expired.Grants[0].ExpiresAt != time.Unix(1, 0).UTC() {
		t.Fatal("historical expiry was renewed or mistaken for outcome evidence")
	}
	delete(config.RetainedReplayKeys, plan.Grants[0].ReplayKeyVersion)
	retired, err := NewIssuer(config)
	if err != nil || retired.organizationInvitationAbsenceProfile(binding, plan) {
		t.Fatal("retired original replay key selected absence proof", err)
	}
}

func TestOrganizationInvitationIssuanceAbsenceProfileRejectsBroaderScope(t *testing.T) {
	i, _, binding, original := organizationInvitationIssuanceFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *kernel.CapabilityIssuancePlan){
		"ordinary": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID, b.SchemaID = "identity.profile.update", "profile-update"
		},
		"resend": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID, b.SchemaID = "identity.organization.invitation.resend", "organization-invitation-resend"
		},
		"accept": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID, b.SchemaID = "identity.organization.invitation.accept", "organization-invitation-accept"
		},
		"schema":         func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaID = "foreign" },
		"schema-version": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaVersion++ },
		"no-record":      func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.RecordID = "" },
		"no-actor":       func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.ActorID = "" },
		"service-actor": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"no-recipient": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.UserID = "" },
		"anonymous":    func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.AnonymousFlowID = "foreign-flow" },
		"no-tenant":    func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.TenantID = "" },
		"bad-command":  func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.CommandID = "invalid" },
		"bad-policy":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.PolicyVersion = 0 },
		"signup":       func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.RegistrationUserID = "new-user" },
		"reset":        func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.MagicLinkRecipientUserID = "user"
		},
		"mfa":      func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
		"no-grant": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants = nil },
		"two-grants": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants = append(p.Grants, p.Grants[0])
		},
		"foreign-purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.identifier.verify"
		},
		"foreign-owner": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Contributor.Owner = "foreign" },
		"foreign-key":   func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].ReplayKeyVersion = 99 },
		"multi-use":     func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].MaxUses = 2 },
		"no-envelope": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ProofFingerprint = [32]byte{}
		},
		"no-expiry": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ExpiresAt = time.Time{}
		},
		"fractional-expiry": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ExpiresAt = p.Grants[0].ExpiresAt.Add(time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, plan := binding, original
			plan.Grants = append([]kernel.CapabilityPlan(nil), original.Grants...)
			mutate(&b, &plan)
			if i.organizationInvitationAbsenceProfile(b, plan) {
				t.Fatal("broader or foreign invocation borrowed invitation absence proof")
			}
		})
	}
	for _, selected := range []bool{false, true} {
		i, _, b, payload := issuerFixture(t)
		var prepared PreparedIssuance
		var err error
		if selected {
			b = registrationIssuerBinding(b)
			payload.Subject = "registered-user"
			prepared, err = i.PrepareRegistration(context.Background(), b, "registered-user", []capability.Payload{payload})
		} else {
			prepared, err = i.Prepare(context.Background(), b, []capability.Payload{payload})
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
		})
		plan, err := prepared.Plan()
		if err != nil || i.organizationInvitationAbsenceProfile(b, plan) {
			t.Fatal("ordinary or signup issuance borrowed invitation recovery", err)
		}
	}
}
