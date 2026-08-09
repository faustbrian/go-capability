//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
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

func TestPostgresConsumptionSurvivesCallerProcessExit(t *testing.T) {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		t.Fatal("POSTGRES_URL is required")
	}
	if os.Getenv("CAPABILITY_POSTGRES_PROCESS_CHILD") == "1" {
		database := openPostgres(t, dsn)
		store, err := capabilitypostgres.NewConsumptionStore(database)
		if err != nil {
			t.Fatalf("NewConsumptionStore(child) error = %v", err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, os.Getenv("CAPABILITY_PROCESS_EXPIRY"))
		if err != nil {
			t.Fatalf("Parse(child expiry) error = %v", err)
		}
		request := capability.Consumption{CapabilityID: os.Getenv("CAPABILITY_PROCESS_ID"), MaxUses: 1, ExpiresAt: expiresAt}
		if result, err := store.Consume(t.Context(), request); err != nil || result.Use != 1 {
			t.Fatalf("Consume(child) = %#v, %v", result, err)
		}
		os.Exit(23)
	}

	database := openPostgres(t, dsn)
	defer database.Close()
	schema, err := os.ReadFile("migrations/001_capability_consumptions.sql")
	if err != nil {
		t.Fatalf("ReadFile(migration) error = %v", err)
	}
	if _, err := database.ExecContext(t.Context(), string(schema)); err != nil {
		t.Fatalf("install migration error = %v", err)
	}
	id := "process-" + time.Now().UTC().Format("20060102150405.000000000")
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)
	t.Cleanup(func() {
		cleanup, openErr := sql.Open("pgx", dsn)
		if openErr != nil {
			t.Errorf("cleanup sql.Open() error = %v", openErr)
			return
		}
		defer cleanup.Close()
		if _, cleanupErr := cleanup.ExecContext(context.Background(), "DROP TABLE capability_consumptions"); cleanupErr != nil {
			t.Errorf("cleanup error = %v", cleanupErr)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable() error = %v", err)
	}
	childContext, cancelChild := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelChild()
	command := exec.CommandContext(childContext, executable,
		"-test.run=^TestPostgresConsumptionSurvivesCallerProcessExit$", "-test.timeout=10s")
	command.Env = append(os.Environ(), "CAPABILITY_POSTGRES_PROCESS_CHILD=1", "CAPABILITY_PROCESS_ID="+id, "CAPABILITY_PROCESS_EXPIRY="+expiresAt.Format(time.RFC3339Nano))
	if err := command.Run(); err == nil {
		t.Fatal("child process exited successfully")
	} else if childContext.Err() != nil {
		t.Fatalf("child process context = %v", childContext.Err())
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
		t.Fatalf("child process exit = %v", err)
	}
	store, err := capabilitypostgres.NewConsumptionStore(database)
	if err != nil {
		t.Fatalf("NewConsumptionStore(parent) error = %v", err)
	}
	request := capability.Consumption{CapabilityID: id, MaxUses: 1, ExpiresAt: expiresAt}
	if _, err := store.Consume(t.Context(), request); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatalf("Consume(after process exit) error = %v", err)
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
