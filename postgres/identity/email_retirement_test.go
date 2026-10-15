package identitycapability

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestEmailRetirementConservesReservedNoncommitEvidence(t *testing.T) {
	for _, state := range []string{"reserved", "revoked"} {
		if classifyConsumptionRecovery(state, 0) != kernel.RecoveryNotCommitted {
			t.Fatal("unused original reservation lost negative recovery evidence", state)
		}
	}
	for _, state := range []string{"issued", "released", "expired", "missing"} {
		if classifyConsumptionRecovery(state, 0) != kernel.RecoveryUnknown {
			t.Fatal("terminal state invented exact reservation evidence", state)
		}
	}
	for _, state := range []string{"reserved", "finalized"} {
		if classifyConsumptionRecovery(state, 1) != kernel.RecoveryCommitted {
			t.Fatal("committed original use lost evidence", state)
		}
	}
	if classifyConsumptionRecovery("revoked", 1) != kernel.RecoveryUnknown {
		t.Fatal("impossible revoked/use combination became authority")
	}
}

func TestVerificationTargetRetentionIsExplicitAndOriginal(t *testing.T) {
	_, config, _, payload := issuerFixture(t)
	unselected, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := unselected.verificationTarget(payload); err != nil || id != "" {
		t.Fatal("unselected issuer acquired a new migration contract", err)
	}
	config.RetainEmailVerificationTargets = true
	selected, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := selected.verificationTarget(payload); err != nil || string(id) != payload.Resource {
		t.Fatal("selected issuer did not retain its authenticated resource", err)
	}
	payload.Resource = ""
	if _, err := selected.verificationTarget(payload); err == nil {
		t.Fatal("targetless verification could evade exact retirement")
	}
	payload.Operation = "identity.password.reset-complete"
	if id, err := selected.verificationTarget(payload); err != nil || id != "" {
		t.Fatal("unrelated capability gained identifier semantics", err)
	}
}

func TestEmailRetirementRequiresClassifiedBoundedScope(t *testing.T) {
	b := identity.CommandBinding{TenantID: "tenant", UserID: "user", RecordID: "address"}
	calls := 0
	err := retireEmailVerificationGrants(context.Background(), b, func(context.Context, string, ...any) (int64, error) {
		calls++
		return 0, nil // active original grants have no authenticated target
	})
	var denied identity.ForbiddenError
	if !errors.As(err, &denied) || calls != 1 {
		t.Fatal("unclassified original grants were ignored or partially retired", err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := retireEmailVerificationGrants(canceled, b, func(context.Context, string, ...any) (int64, error) {
		t.Fatal("canceled retirement performed SQL")
		return 0, nil
	}); !errors.As(err, new(identity.CancelledError)) {
		t.Fatal("retirement lost cancellation", err)
	}
}

func TestEmailRetirementRejectsUnpreparedWork(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := RetireEmailVerificationGrants(ctx, kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unprepared Work gained target retirement")
		}
	}
}
