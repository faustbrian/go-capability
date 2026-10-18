package identitycapability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func invitationConsumptionFixture(t *testing.T) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload, OrganizationInvitationScope) {
	t.Helper()
	i, config, b, p := issuerFixture(t)
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.organization.invitation.accept", "organization-invitation-accept", 1
	b.RecordID, b.ActorID, b.ActorKind = "invitation", identity.ActorID(b.UserID), authorization.SubjectUser
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "organization", 1, string(b.CommandID)
	scope := OrganizationInvitationScope{OrganizationID: "organization", InvitationVersion: 1, Role: "member", RecipientIdentifierID: "email", RecipientIdentifierVersion: 7}
	p.ID, p.Resource, p.Operation = "invitation-proof", b.RecordID, b.OperationID
	p.IssuedAt, p.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	p.Caveats = map[string]string{
		"organization.id":                           scope.OrganizationID,
		"organization.invitation-version":           strconv.FormatUint(scope.InvitationVersion, 10),
		"organization.role":                         scope.Role,
		"organization.recipient-identifier":         string(scope.RecipientIdentifierID),
		"organization.recipient-identifier-version": strconv.FormatUint(scope.RecipientIdentifierVersion, 10),
	}
	return i, config, b, p, scope
}

func TestPrepareOrganizationInvitationConsumptionConservesOriginalProof(t *testing.T) {
	i, config, b, payload, scope := invitationConsumptionFixture(t)
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
	grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(b.OperationID), config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := i.PrepareOrganizationInvitationConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope)
	expected, expectedErr := i.grantPlan(b, b.UserID, grant, 1)
	if err != nil || expectedErr != nil || plan != expected || plan.Purpose != capability.Purpose(b.OperationID) || plan.ProofFingerprint != grant.EnvelopeDigest() {
		t.Fatal("invitation preparation changed original signed/replay identity", err)
	}
	config.CurrentReplayKeyVersion, config.RetainedReplayKeys = 3, map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	again, err := rotated.PrepareOrganizationInvitationConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope)
	if err != nil || again != plan {
		t.Fatal("key rotation renewed invitation identity", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := i.PrepareOrganizationInvitationConsumption(ctx, b, proof, grant.EnvelopeDigest(), 1, scope); !errors.Is(err, context.Canceled) || got != (kernel.CapabilityPlan{}) {
		t.Fatal("cancelled preparation returned usable metadata", err)
	}
}

func TestPrepareOrganizationInvitationConsumptionRejectsSignedForeignScope(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"organization":         func(p *capability.Payload) { p.Caveats["organization.id"] = "other" },
		"version":              func(p *capability.Payload) { p.Caveats["organization.invitation-version"] = "2" },
		"role":                 func(p *capability.Payload) { p.Caveats["organization.role"] = "owner" },
		"identifier":           func(p *capability.Payload) { p.Caveats["organization.recipient-identifier"] = "other-email" },
		"identifier-version":   func(p *capability.Payload) { p.Caveats["organization.recipient-identifier-version"] = "8" },
		"tenant":               func(p *capability.Payload) { p.Tenant = "other" },
		"recipient":            func(p *capability.Payload) { p.Subject = "other" },
		"invitation":           func(p *capability.Payload) { p.Resource = "other" },
		"purpose":              func(p *capability.Payload) { p.Operation = "identity.identifier.verify" },
		"missing":              func(p *capability.Payload) { delete(p.Caveats, "organization.role") },
		"extra":                func(p *capability.Payload) { p.Caveats["organization.unclassified"] = "value" },
		"noncanonical-version": func(p *capability.Payload) { p.Caveats["organization.invitation-version"] = "01" },
	} {
		t.Run(name, func(t *testing.T) {
			i, config, b, payload, scope := invitationConsumptionFixture(t)
			mutate(&payload)
			proof, _, err := i.service.Issue(context.Background(), payload)
			if err != nil {
				t.Fatal("signed hostile fixture invalid", err)
			}
			defer func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
			grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience)
			if err != nil {
				t.Fatal("signed hostile fixture unverifiable", err)
			}
			got, err := i.PrepareOrganizationInvitationConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || got != (kernel.CapabilityPlan{}) {
				t.Fatal("signed foreign scope accepted", err)
			}
		})
	}
}

func TestPrepareOrganizationInvitationConsumptionRejectsForeignInvocationAndMetadata(t *testing.T) {
	i, config, b, payload, original := invitationConsumptionFixture(t)
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
	grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding, *OrganizationInvitationScope, *[32]byte, *uint32){
		"operation": func(b *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			b.OperationID = "identity.organization.member.add"
		},
		"schema": func(b *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			b.SchemaID = "other"
		},
		"actor": func(b *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			b.ActorID = "other"
		},
		"anonymous": func(b *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			b.AnonymousFlowID = "other"
		},
		"tenant": func(b *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			b.TenantID = "other"
		},
		"record": func(b *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			b.RecordID = "other"
		},
		"empty-scope": func(_ *identity.CommandBinding, s *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			*s = OrganizationInvitationScope{}
		},
		"scope-organization": func(_ *identity.CommandBinding, s *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			s.OrganizationID = "other"
		},
		"scope-role": func(_ *identity.CommandBinding, s *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			s.Role = "owner"
		},
		"scope-version": func(_ *identity.CommandBinding, s *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			s.InvitationVersion++
		},
		"scope-identifier-version": func(_ *identity.CommandBinding, s *OrganizationInvitationScope, _ *[32]byte, _ *uint32) {
			s.RecipientIdentifierVersion++
		},
		"envelope": func(_ *identity.CommandBinding, _ *OrganizationInvitationScope, e *[32]byte, _ *uint32) {
			*e = [32]byte{1}
		},
		"missing-envelope": func(_ *identity.CommandBinding, _ *OrganizationInvitationScope, e *[32]byte, _ *uint32) {
			*e = [32]byte{}
		},
		"missing-key": func(_ *identity.CommandBinding, _ *OrganizationInvitationScope, _ *[32]byte, k *uint32) { *k = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			binding, scope, envelope, key := b, original, grant.EnvelopeDigest(), uint32(1)
			mutate(&binding, &scope, &envelope, &key)
			if got, err := i.PrepareOrganizationInvitationConsumption(context.Background(), binding, proof, envelope, key, scope); err == nil || got != (kernel.CapabilityPlan{}) {
				t.Fatal("foreign invocation returned a plan")
			}
		})
	}
	if _, err := json.Marshal(original); err == nil {
		t.Fatal("scope serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", original), original.OrganizationID) {
		t.Fatal("scope diagnostic leaked identifiers")
	}
}

func TestPrepareOrganizationInvitationConsumptionAllowsConcurrentReadOnlyCustody(t *testing.T) {
	i, config, b, payload, scope := invitationConsumptionFixture(t)
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
	grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	want, err := i.grantPlan(b, b.UserID, grant, 1)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got, err := i.PrepareOrganizationInvitationConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope); err != nil || got != want {
				t.Error("concurrent read changed proof identity", err)
			}
		})
	}
	wg.Wait()
}
