package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func TestMigrationRejectsMissingArguments(t *testing.T) {
	if err := MigrateLegacyConsumption(context.Background(), nil, "ordinary-issuer"); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("nil transaction: %v", err)
	}
	state := &stubSQLState{execRows: 1}
	db := openStubDatabase(t, state)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var nilContext context.Context
	if err := MigrateLegacyConsumption(nilContext, tx, "ordinary-issuer"); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("nil context: %v", err)
	}
	if len(state.executions) != 0 || state.commits != 0 || state.rollbacks != 0 {
		t.Fatal("invalid migration executed SQL or finalized caller transaction")
	}
	if err := tx.Rollback(); err != nil || state.rollbacks != 1 {
		t.Fatal("caller could not roll back rejected migration")
	}
}

func TestMigrationIssuerAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		issuer string
		valid  bool
	}{
		{"ascii255", strings.Repeat("a", 255), true},
		{"utf8bytes256", strings.Repeat("é", 128), true},
		{"utf8bytes257", strings.Repeat("é", 128) + "a", false},
		{"empty", "", false},
		{"invalidUTF8", string([]byte{0xff}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &stubSQLState{execRows: 1}
			db := openStubDatabase(t, state)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			err = MigrateLegacyConsumption(context.Background(), tx, test.issuer)
			if state.commits != 0 || state.rollbacks != 0 {
				t.Fatal("migration finalized caller transaction")
			}
			if !test.valid {
				if !errors.Is(err, capability.ErrInvalidConfiguration) || len(state.executions) != 0 {
					t.Fatalf("rejected issuer: error=%v, statements=%d", err, len(state.executions))
				}
				if err := tx.Rollback(); err != nil || state.rollbacks != 1 {
					t.Fatal("caller rollback failed")
				}
				return
			}
			if err != nil || len(state.executions) != 7 {
				t.Fatalf("accepted issuer: error=%v, statements=%d", err, len(state.executions))
			}
			backfill := state.executions[2]
			if backfill.query != "UPDATE capability_consumptions SET issuer = $1" || len(backfill.arguments) != 1 || backfill.arguments[0].Value != test.issuer {
				t.Fatal("migration did not bind exact issuer")
			}
			if err := tx.Commit(); err != nil || state.commits != 1 {
				t.Fatal("caller commit failed")
			}
		})
	}
}

func TestPublicConsumeIssuerAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		issuer string
		valid  bool
	}{
		{"ascii255", strings.Repeat("a", 255), true},
		{"utf8bytes256", strings.Repeat("é", 128), true},
		{"utf8bytes257", strings.Repeat("é", 128) + "a", false},
		{"empty", "", false},
		{"invalidUTF8", string([]byte{0xff}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &stubSQLState{execRows: 1}
			if !test.valid {
				// A database failure must never replace input rejection.
				state.beginErr = errors.New("unexpected database access")
			}
			db := openStubDatabase(t, state)
			store, err := NewConsumptionStore(db)
			if err != nil {
				t.Fatal(err)
			}
			request := capability.Consumption{Issuer: test.issuer, CapabilityID: "ordinary-capability", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}
			result, err := store.Consume(context.Background(), request)
			if !test.valid {
				if !errors.Is(err, capability.ErrInvalidConfiguration) || result != (capability.ConsumptionResult{}) {
					t.Fatalf("rejected issuer: result=%#v, error=%v", result, err)
				}
				if state.query != "" || len(state.executions) != 0 || state.commits != 0 || state.rollbacks != 0 {
					t.Fatal("rejected issuer reached database work")
				}
				return
			}
			if err != nil || result.Use != 1 || result.Remaining != 1 || state.commits != 1 || state.rollbacks != 0 {
				t.Fatalf("accepted issuer: result=%#v, error=%v", result, err)
			}
			if len(state.queryArgs) != 2 || state.queryArgs[0].Value != test.issuer || state.queryArgs[1].Value != request.CapabilityID {
				t.Fatal("load did not bind exact issuer and capability")
			}
			if len(state.executions) != 1 || len(state.executions[0].arguments) != 4 || state.executions[0].arguments[0].Value != test.issuer || state.executions[0].arguments[1].Value != request.CapabilityID {
				t.Fatal("insert did not bind exact issuer and capability")
			}
		})
	}
}
