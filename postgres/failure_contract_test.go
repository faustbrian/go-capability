package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

// PG-MIGRATION-FAILURES: the helper returns the first failure and never
// finalizes the caller's transaction, including at the final SQL stage.
func TestMigrationFailuresLeaveTransactionCallerOwned(t *testing.T) {
	for stage := 1; stage <= 7; stage++ {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			failure := errors.New("migration stage failed")
			state := &stubSQLState{execRows: 1, execErr: failure, execFailAt: stage}
			db := openStubDatabase(t, state)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if err := MigrateLegacyConsumption(context.Background(), tx, "ordinary-issuer"); !errors.Is(err, failure) {
				t.Fatalf("migration failure = %v", err)
			}
			if len(state.executions) != stage || state.commits != 0 || state.rollbacks != 0 {
				t.Fatal("migration continued or finalized caller transaction after failure")
			}
			if err := tx.Rollback(); err != nil || state.rollbacks != 1 {
				t.Fatal("caller could not roll back failed migration")
			}
		})
	}
}

func TestCanceledMigrationDoesNotExecuteSQL(t *testing.T) {
	state := &stubSQLState{execRows: 1}
	db := openStubDatabase(t, state)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := MigrateLegacyConsumption(ctx, tx, "ordinary-issuer"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled migration = %v", err)
	}
	if len(state.executions) != 0 || state.commits != 0 || state.rollbacks != 0 {
		t.Fatal("canceled migration executed SQL or finalized caller transaction")
	}
	if err := tx.Rollback(); err != nil || state.rollbacks != 1 {
		t.Fatal("caller rollback failed")
	}
}

// PG-CLOCK-FAILURE: failed authoritative database time cannot admit a use.
func TestPublicConsumeRejectsDatabaseClockFailure(t *testing.T) {
	failure := errors.New("database clock unavailable")
	state := &stubSQLState{queryErr: failure, execRows: 1}
	db := openStubDatabase(t, state)
	store, err := NewConsumptionStore(db)
	if err != nil {
		t.Fatal(err)
	}
	request := capability.Consumption{Issuer: "ordinary-issuer", CapabilityID: "ordinary-capability", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}
	result, err := store.Consume(context.Background(), request)
	if !errors.Is(err, failure) || result != (capability.ConsumptionResult{}) {
		t.Fatalf("Consume(clock failure) = %#v, %v", result, err)
	}
	if state.query != "SELECT CURRENT_TIMESTAMP" || len(state.executions) != 0 || state.commits != 0 || state.rollbacks != 1 {
		t.Fatal("clock failure wrote or committed quota, or leaked transaction")
	}
	state.queryErr = nil
	result, err = store.Consume(context.Background(), request)
	if err != nil || result.Use != 1 || result.Remaining != 1 || state.commits != 1 {
		t.Fatalf("Consume(recovered clock) = %#v, %v", result, err)
	}
}
