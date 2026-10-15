package identitycapability

import (
	"encoding/hex"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func managedScopePayload() capability.Payload {
	return capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"managed-email"}, Subject: "user", Tenant: "tenant", Resource: "email-id", Operation: "identity.identifier.verify", MaxUses: 1, Caveats: map[string]string{"email.profile": "management-v1", "email.confirm_operation": "identity.email.verification-confirm", "email.intent": strings.Repeat("a", 64), "email.binding_key_version": "1"}}
}

func TestManagedSupersessionSelectsConsumptionFenceWithoutSignupAlias(t *testing.T) {
	p := managedScopePayload()
	scope, err := ManagedEmailScopeFromPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	digest := scope.Digest()
	p.Caveats["email.supersession"] = hex.EncodeToString(digest[:])
	if !emailConsumptionProfile(p, "management-v1") || emailConsumptionProfile(p, "registration-v1") {
		t.Fatal("selected management family changed signed consumption ownership")
	}
	b := kernel.CapabilityReservationBinding{Command: identity.CommandBinding{OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.managed-v1", SchemaVersion: 1}, Plan: kernel.CapabilityPlan{Purpose: "identity.identifier.verify"}}
	const sql = "SELECT state FROM public.capability_identity_one_use WHERE tenant_id=$1 FOR UPDATE"
	if got := activeCapabilitySQL(sql, b); !strings.HasSuffix(got, " AND superseded_by_command_id IS NULL FOR UPDATE") {
		t.Fatal("managed consumption does not deny superseded predecessors")
	}
	b.Command.SchemaID = "identity.email.verification-confirm.native-v1"
	if got := activeCapabilitySQL(sql, b); got != sql {
		t.Fatal("signup acquired management-only schema/fence requirements")
	}
}

func TestManagedEmailSupersessionScopeStableAcrossFreshRequests(t *testing.T) {
	p := managedScopePayload()
	original, err := ManagedEmailScopeFromPayload(p)
	if err != nil || original.Digest() == ([32]byte{}) {
		t.Fatal("managed mailbox has no stable supersession scope", err)
	}
	p.ID, p.CorrelationID = "fresh-grant", "fresh-command"
	p.IssuedAt, p.ExpiresAt = time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	p.Caveats["email.intent"], p.Caveats["email.binding_key_version"] = strings.Repeat("b", 64), "2"
	digest := original.Digest()
	p.Caveats["email.supersession"] = hex.EncodeToString(digest[:])
	current, err := ManagedEmailScopeFromPayload(p)
	if err != nil || current.Digest() != original.Digest() {
		t.Fatal("fresh request/key rotation escaped the original mailbox family", err)
	}
	for _, mutate := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Issuer = "https://other.example.test" },
		func(p *capability.Payload) { p.Audiences[0] = "another" },
		func(p *capability.Payload) { p.Tenant = "another" },
		func(p *capability.Payload) { p.Subject = "another" },
		func(p *capability.Payload) { p.Resource = "another" },
		func(p *capability.Payload) { p.Caveats["email.confirm_operation"] = "identity.email.change-confirm" },
	} {
		foreign := managedScopePayload()
		foreign.Audiences = append([]string(nil), foreign.Audiences...)
		foreign.Caveats = maps.Clone(foreign.Caveats)
		mutate(&foreign)
		got, err := ManagedEmailScopeFromPayload(foreign)
		if err != nil || got.Digest() == original.Digest() {
			t.Fatal("foreign issuer/recipient/purpose shared the verification family", err)
		}
	}
	for _, mutate := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Caveats["email.profile"] = "registration-v1" },
		func(p *capability.Payload) { p.Operation = "identity.magic-link.consume" },
		func(p *capability.Payload) { p.MaxUses = 2 },
		func(p *capability.Payload) { p.Resource = "" },
		func(p *capability.Payload) { p.Caveats["email.supersession"] = strings.Repeat("f", 64) },
		func(p *capability.Payload) { p.Caveats["email.supersession"] = strings.Repeat("A", 64) },
		func(p *capability.Payload) { p.Caveats["extra"] = "foreign" },
	} {
		foreign := managedScopePayload()
		mutate(&foreign)
		if got, err := ManagedEmailScopeFromPayload(foreign); err == nil || got.Digest() != ([32]byte{}) {
			t.Fatal("unsupported profile or forged family admitted")
		}
	}
}
