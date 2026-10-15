//go:build integration

package identitycapability

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-postgres/postgrestest"
	"github.com/jackc/pgx/v5"
)

// IdentityTestPostgresConfig shares the owned fixture with external-package tests.
// It is available only in the test variant, not the public library API.
func IdentityTestPostgresConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv("IDENTITY_CAPABILITY_TEST_DSN")
	if dsn == "" {
		version := os.Getenv("CAPABILITY_POSTGRES_VERSION")
		if version == "" {
			version = "18"
		}
		matrix, err := os.ReadFile("testdata/postgres-images.tsv")
		if err != nil {
			t.Fatal("PostgreSQL image matrix unavailable")
		}
		var image string
		for _, line := range strings.Split(string(matrix), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == version && strings.Contains(fields[1], "@sha256:") {
				image = fields[1]
			}
		}
		if image == "" {
			t.Fatal("selected PostgreSQL image is not pinned")
		}
		ctx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		fixture, err := postgrestest.Start(ctx, postgrestest.Config{Image: image, Database: "identity_test", CleanupTimeout: 2 * time.Minute})
		if err != nil {
			t.Fatal("disposable PostgreSQL fixture unavailable")
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := fixture.Close(cleanup); err != nil {
				t.Error("owned PostgreSQL fixture cleanup failed")
			}
		})
		dsn = fixture.DSN()
	}
	config, err := parseIdentityTestPostgresConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func parseIdentityTestPostgresConfig(dsn string) (*pgx.ConnConfig, error) {
	config, err := pgx.ParseConfig(dsn)
	loopback := func(host string) bool { return host == "127.0.0.1" || host == "localhost" || host == "::1" }
	if dsn == "" || err != nil || !loopback(config.Host) || config.Database != "identity_test" {
		return nil, errors.New("explicit disposable loopback identity_test cluster required")
	}
	// Every fallback may execute the same administrative DDL after primary failure.
	for _, fallback := range config.Fallbacks {
		if !loopback(fallback.Host) {
			return nil, errors.New("every disposable PostgreSQL fallback must be loopback")
		}
	}
	return config, nil
}

func TestIdentityTestPostgresConfig(t *testing.T) {
	for _, test := range []struct {
		name  string
		dsn   string
		valid bool
	}{
		{"ipv4", "host=127.0.0.1 dbname=identity_test", true},
		{"localhost", "host=localhost dbname=identity_test", true},
		{"ipv6", "host=::1 dbname=identity_test", true},
		{"loopback fallbacks", "host=127.0.0.1,localhost,::1 dbname=identity_test", true},
		{"remote primary", "host=remote.invalid dbname=identity_test", false},
		{"remote fallback", "host=127.0.0.1,remote.invalid dbname=identity_test", false},
		{"remote final fallback", "host=127.0.0.1,localhost,remote.invalid dbname=identity_test", false},
		{"socket fallback", "host=127.0.0.1,/tmp dbname=identity_test", false},
		{"other database", "host=127.0.0.1 dbname=other", false},
		{"empty", "", false},
		{"malformed", "host='", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := parseIdentityTestPostgresConfig(test.dsn)
			if (err == nil) != test.valid {
				t.Fatalf("connection configuration accepted = %t, want %t", err == nil, test.valid)
			}
			if !test.valid && config != nil {
				t.Fatal("rejected configuration remains connectable")
			}
		})
	}
}
