//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/golib/pkg/capability"
	capabilitypostgres "github.com/faustbrian/golib/pkg/capability/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresConsumptionSurvivesClientRecreation(t *testing.T) {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		t.Fatal("POSTGRES_URL is required")
	}
	first := openPostgres(t, dsn)
	schema, err := os.ReadFile("migrations/001_capability_consumptions.sql")
	if err != nil {
		t.Fatalf("ReadFile(migration) error = %v", err)
	}
	if _, err := first.ExecContext(t.Context(), string(schema)); err != nil {
		t.Fatalf("install migration error = %v", err)
	}
	id := "integration-" + time.Now().UTC().Format("20060102150405.000000000")
	t.Cleanup(func() {
		database, openErr := sql.Open("pgx", dsn)
		if openErr != nil {
			t.Errorf("cleanup sql.Open() error = %v", openErr)
			return
		}
		defer database.Close()
		if _, cleanupErr := database.ExecContext(context.Background(),
			"DROP TABLE capability_consumptions",
		); cleanupErr != nil {
			t.Errorf("cleanup error = %v", cleanupErr)
		}
	})
	store, err := capabilitypostgres.NewConsumptionStore(first)
	if err != nil {
		t.Fatalf("NewConsumptionStore() error = %v", err)
	}
	request := capability.Consumption{CapabilityID: id, MaxUses: 1, ExpiresAt: time.Now().Add(time.Minute).UTC()}
	if result, err := store.Consume(t.Context(), request); err != nil || result.Use != 1 {
		t.Fatalf("Consume(first) = %#v, %v", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first client) error = %v", err)
	}

	second := openPostgres(t, dsn)
	defer second.Close()
	store, err = capabilitypostgres.NewConsumptionStore(second)
	if err != nil {
		t.Fatalf("NewConsumptionStore(recreated) error = %v", err)
	}
	if _, err := store.Consume(t.Context(), request); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatalf("Consume(after client recreation) error = %v", err)
	}
}

func openPostgres(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if err := database.PingContext(t.Context()); err != nil {
		_ = database.Close()
		t.Fatalf("PingContext() error = %v", err)
	}
	return database
}
