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

func anonymousUpgradeIssuanceFixture(t *testing.T) (*Issuer, IssuerConfig, identity.CommandBinding, kernel.CapabilityIssuancePlan) {
	t.Helper()
	i, config, binding, payload, _ := anonymousUpgradeFixture(t)
	binding.RecordID, binding.SchemaID = "", "identity.anonymous.upgrade.prepare.native-v1"
	payload.ID = ""
	prepared, err := i.Prepare(context.Background(), binding, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original anonymous-upgrade issuance preparation", err)
	}
	t.Cleanup(func() {
		_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
	})
	plan, err := prepared.Plan()
	if err != nil || i.ValidateCapabilityIssuance(binding, plan) != nil {
		t.Fatal("original anonymous-upgrade plan invalid", err)
	}
	return i, config, binding, plan
}

// The primary native PostgreSQL consumer proves this profile's actual unknown-
// commit recovery. These cases bound selection of the existing absence query;
// they do not fabricate RecoveryWork or claim durable absence from metadata.
func TestAnonymousUpgradeIssuanceAbsenceProfilePreservesOriginalCustody(t *testing.T) {
	i, config, binding, plan := anonymousUpgradeIssuanceFixture(t)
	want := plan
	want.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	if !i.anonymousUpgradeAbsenceProfile(binding, plan) {
		t.Fatal("exact native anonymous-upgrade issuance cannot select absence proof")
	}
	config.CurrentReplayKeyVersion, config.RetainedReplayKeys = 3, map[uint32][32]byte{1: {1}, 2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if !rotated.anonymousUpgradeAbsenceProfile(binding, plan) || !reflect.DeepEqual(plan, want) {
		t.Fatal("rotation replaced original issuance identity or scope")
	}
	// Recovery reads historical provenance, not live bearer authority: elapsed
	// original expiry must not erase either the existing row or absence evidence.
	expired := plan
	expired.Grants = append([]kernel.CapabilityPlan(nil), plan.Grants...)
	expired.Grants[0].ExpiresAt = time.Unix(1, 0).UTC()
	if !i.anonymousUpgradeAbsenceProfile(binding, expired) || expired.Grants[0].ExpiresAt != time.Unix(1, 0).UTC() {
		t.Fatal("historical expiry was renewed or made unrecoverable")
	}
	delete(config.RetainedReplayKeys, plan.Grants[0].ReplayKeyVersion)
	retired, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if retired.anonymousUpgradeAbsenceProfile(binding, plan) {
		t.Fatal("retired original replay key selected absence proof")
	}
}

func TestAnonymousUpgradeIssuanceAbsenceProfileRejectsBroaderRecovery(t *testing.T) {
	i, _, binding, original := anonymousUpgradeIssuanceFixture(t)
	for name, mutate := range map[string]func(*identity.CommandBinding, *kernel.CapabilityIssuancePlan){
		"ordinary": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.OperationID, b.SchemaID = "identity.profile.update", "profile-update"
		},
		"consumption-schema": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.SchemaID = "identity.anonymous.upgrade.native-v1"
		},
		"schema-version": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.SchemaVersion = 2 },
		"guest-record":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.RecordID = "guest-user" },
		"foreign-actor":  func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.ActorID = "other-user" },
		"service-actor": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"anonymous-flow": func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) {
			b.UserID, b.AnonymousFlowID = "", "anonymous-flow"
		},
		"invalid-tenant":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.TenantID = "" },
		"invalid-command":  func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.CommandID = "invalid" },
		"invalid-policy":   func(b *identity.CommandBinding, _ *kernel.CapabilityIssuancePlan) { b.PolicyVersion = 0 },
		"signup-selection": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.RegistrationUserID = "new-user" },
		"reset-selection":  func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink-selection": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.MagicLinkRecipientUserID = "user"
		},
		"mfa-selection": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
		"no-grant":      func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants = nil },
		"multiple-grants": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants = append(p.Grants, p.Grants[0])
			p.Grants[1].CapabilityID += "-other"
			p.Grants[1].ReplayDigest[0]++
		},
		"foreign-purpose": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].Purpose = "identity.identifier.verify"
		},
		"foreign-contributor": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Contributor.Owner = "other" },
		"foreign-replay-key":  func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].ReplayKeyVersion = 99 },
		"multi-use":           func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) { p.Grants[0].MaxUses = 2 },
		"no-envelope": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
			p.Grants[0].ProofFingerprint = [32]byte{}
		},
		"zero-expiry": func(_ *identity.CommandBinding, p *kernel.CapabilityIssuancePlan) {
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
			if i.anonymousUpgradeAbsenceProfile(b, plan) {
				t.Fatal("foreign or broader issuance selected native absence proof")
			}
		})
	}
}

func TestAnonymousUpgradeIssuanceAbsenceProfileDoesNotBroadenOrdinaryOrSignup(t *testing.T) {
	for _, signup := range []bool{false, true} {
		i, _, binding, payload := issuerFixture(t)
		var prepared PreparedIssuance
		var err error
		if signup {
			binding = registrationIssuerBinding(binding)
			payload.Subject = "registered-user"
			prepared, err = i.PrepareRegistration(context.Background(), binding, "registered-user", []capability.Payload{payload})
		} else {
			prepared, err = i.Prepare(context.Background(), binding, []capability.Payload{payload})
		}
		if err != nil {
			t.Fatal("existing issuance fixture rejected", err)
		}
		t.Cleanup(func() {
			_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
		})
		plan, err := prepared.Plan()
		if err != nil || i.ValidateCapabilityIssuance(binding, plan) != nil {
			t.Fatal("existing issuance profile invalid", err)
		}
		if i.anonymousUpgradeAbsenceProfile(binding, plan) {
			t.Fatal("ordinary/signup issuance borrowed native absence recovery")
		}
	}
}
