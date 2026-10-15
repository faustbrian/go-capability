package identitycapability

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestParticipantRequiresCoordinatorAuthority(t *testing.T) {
	p := NewParticipant()
	if p.Descriptor() != (identitypostgres.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}) {
		t.Fatal("wrong ownership")
	}
	var invalid identity.InvalidInputError
	for _, err := range []error{
		p.ReserveCapability(context.Background(), identitypostgres.CapabilityReservationWork{}),
		p.RebindCapability(context.Background(), identitypostgres.CapabilityReservationWork{}),
		p.ReleaseCapability(context.Background(), identitypostgres.CapabilityReleaseWork{}),
		p.ApplyCapability(context.Background(), identitypostgres.CapabilityApplyWork{}),
		p.FinalizeCapability(context.Background(), identitypostgres.CapabilityFinalizeWork{}),
		(*Participant)(nil).ReserveCapability(context.Background(), identitypostgres.CapabilityReservationWork{}),
		(&Participant{}).ReserveCapability(context.Background(), identitypostgres.CapabilityReservationWork{}),
		p.ReserveCapability(nil, identitypostgres.CapabilityReservationWork{}),
	} {
		if !errors.As(err, &invalid) {
			t.Fatalf("authority not rejected: %T", err)
		}
	}
	status, err := p.RecoverParticipant(context.Background(), identitypostgres.RecoveryWork{})
	if status != identitypostgres.RecoveryUnknown || !errors.As(err, &invalid) {
		t.Fatal("fabricated recovery evidence")
	}
}

func TestExecutionParticipantAndCurrentGeneration(t *testing.T) {
	var _ identitypostgres.CapabilityExecutionContributor = NewParticipant()
	b := identitypostgres.CapabilityReservationBinding{Generation: 7, Plan: identitypostgres.CapabilityPlan{ExpiresAt: time.Now().UTC()}}
	for _, terminal := range []bool{false, true} {
		calls := 0
		err := executeConsumption(context.Background(), b, terminal, func(_ context.Context, _ string, args ...any) (int64, error) {
			calls++
			if args[10] != "7" {
				t.Fatal("execution used previous generation")
			}
			return 1, nil
		})
		if err != nil || calls != 2 {
			t.Fatal("lock and transition missing", err)
		}
	}
}
