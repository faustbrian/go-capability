//go:build integration

package identitycapability

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func TestOAuthProxyOriginGrantRetirementIntegration(t *testing.T) {
	conn := oauthProxyRetirementDatabase(t)
	ctx := t.Context()
	for _, purpose := range []string{"identity.oauth.proxy-forward", "identity.oauth.callback"} {
		t.Run(purpose, func(t *testing.T) {
			for _, state := range []string{"issued", "reserved", "revoked", "finalized", "released", "expired"} {
				t.Run(state, func(t *testing.T) {
					tx := oauthProxyRetirementTransaction(t, conn)
					scope, grant := oauthProxyRetirementSeed(t, tx, purpose, state, "target")
					before := oauthProxyRetirementSnapshot(t, tx, scope, grant)
					if err := retireOAuthProxyOriginGrant(ctx, scope, grant, oauthProxyRetirementQuery(tx)); err != nil {
						t.Fatal("exact native original grant could not settle retirement", err)
					}
					after := oauthProxyRetirementSnapshot(t, tx, scope, grant)
					want := state
					if state == "issued" || state == "reserved" {
						want = "revoked"
					}
					if after.state != want || after.metadata != before.metadata {
						t.Fatal("retirement changed original issuance, reservation, use or expiry metadata")
					}
					if err := retireOAuthProxyOriginGrant(ctx, scope, grant, oauthProxyRetirementQuery(tx)); err != nil {
						t.Fatal("exact retirement retry was not idempotent", err)
					}
					if again := oauthProxyRetirementSnapshot(t, tx, scope, grant); again != after {
						t.Fatal("retirement retry changed retained terminal provenance")
					}
				})
			}
			t.Run("neighbors remain unchanged", func(t *testing.T) {
				tx := oauthProxyRetirementTransaction(t, conn)
				scope, grant := oauthProxyRetirementSeed(t, tx, purpose, "reserved", "target")
				type neighbor struct {
					scope  kernel.OAuthProxyOriginRetirementScope
					grant  kernel.CapabilityPlan
					before oauthProxyRetirementRow
				}
				var neighbors []neighbor
				for _, dimension := range []string{"origin", "flow", "purpose", "locator"} {
					otherPurpose := purpose
					if dimension == "purpose" {
						otherPurpose = "identity.oauth.callback"
						if purpose == otherPurpose {
							otherPurpose = "identity.oauth.proxy-forward"
						}
					}
					otherScope, otherGrant := oauthProxyRetirementSeed(t, tx, otherPurpose, "reserved", dimension)
					if dimension == "origin" {
						if _, err := tx.Exec(ctx, `UPDATE public.capability_identity_one_use SET origin_command_id='BQUFBQUFBQUFBQUFBQUFBQ' WHERE capability_id=$1 AND purpose=$2`, otherGrant.CapabilityID, otherPurpose); err != nil {
							t.Fatal(err)
						}
					}
					if dimension == "flow" {
						if _, err := tx.Exec(ctx, `UPDATE public.capability_identity_one_use SET subject_id='BgYGBgYGBgYGBgYGBgYGBg' WHERE capability_id=$1 AND purpose=$2`, otherGrant.CapabilityID, otherPurpose); err != nil {
							t.Fatal(err)
						}
					}
					neighbors = append(neighbors, neighbor{otherScope, otherGrant, oauthProxyRetirementSnapshot(t, tx, otherScope, otherGrant)})
				}
				if err := retireOAuthProxyOriginGrant(ctx, scope, grant, oauthProxyRetirementQuery(tx)); err != nil {
					t.Fatal("retire the exact original among nearby grants", err)
				}
				for _, other := range neighbors {
					if after := oauthProxyRetirementSnapshot(t, tx, other.scope, other.grant); after != other.before {
						t.Fatal("retirement changed a neighboring origin, flow, purpose or locator")
					}
				}
			})
			for _, mismatch := range []string{"tenant", "origin", "flow", "purpose", "replay-version", "replay-digest", "capability", "proof", "expiry", "maximum"} {
				t.Run("deny mismatched "+mismatch, func(t *testing.T) {
					tx := oauthProxyRetirementTransaction(t, conn)
					scope, grant := oauthProxyRetirementSeed(t, tx, purpose, "reserved", "target")
					before := oauthProxyRetirementSnapshot(t, tx, scope, grant)
					changedScope, changedGrant := scope, grant
					switch mismatch {
					case "tenant":
						changedScope.TenantID = "tenant-b"
					case "origin":
						changedScope.OriginCommandID = "BQUFBQUFBQUFBQUFBQUFBQ"
					case "flow":
						changedScope.FlowID = "BgYGBgYGBgYGBgYGBgYGBg"
					case "purpose":
						changedScope.GrantPurpose, changedGrant.Purpose = "identity.identifier.verify", "identity.identifier.verify"
					case "replay-version":
						changedGrant.ReplayKeyVersion++
					case "replay-digest":
						changedGrant.ReplayDigest[0] ^= 1
					case "capability":
						changedGrant.CapabilityID = "another-capability"
					case "proof":
						changedGrant.ProofFingerprint[0] ^= 1
					case "expiry":
						changedGrant.ExpiresAt = changedGrant.ExpiresAt.Add(time.Microsecond)
					case "maximum":
						changedGrant.MaxUses = 2
					}
					if err := retireOAuthProxyOriginGrant(ctx, changedScope, changedGrant, oauthProxyRetirementQuery(tx)); err == nil {
						t.Fatal("missing or mismatched original grant was acknowledged")
					}
					if after := oauthProxyRetirementSnapshot(t, tx, scope, grant); after != before {
						t.Fatal("mismatch changed retained original custody")
					}
				})
			}
		})
	}
	t.Run("committed retirement replay and rollback", func(t *testing.T) {
		tx := oauthProxyRetirementTransaction(t, conn)
		scope, grant := oauthProxyRetirementSeed(t, tx, "identity.oauth.proxy-forward", "reserved", "durable")
		before := oauthProxyRetirementSnapshot(t, tx, scope, grant)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		attempt := oauthProxyRetirementTransaction(t, conn)
		if err := retireOAuthProxyOriginGrant(ctx, scope, grant, oauthProxyRetirementQuery(attempt)); err != nil {
			t.Fatal(err)
		}
		if got := oauthProxyRetirementSnapshot(t, attempt, scope, grant); got.state != "revoked" || got.metadata != before.metadata {
			t.Fatal("retirement was not provisional in the caller's transaction")
		}
		if err := attempt.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		committed := oauthProxyRetirementTransaction(t, conn)
		if got := oauthProxyRetirementSnapshot(t, committed, scope, grant); got != before {
			t.Fatal("caller rollback failed to restore the original reserved grant")
		}
		if err := retireOAuthProxyOriginGrant(ctx, scope, grant, oauthProxyRetirementQuery(committed)); err != nil {
			t.Fatal(err)
		}
		if err := committed.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		replay := oauthProxyRetirementTransaction(t, conn)
		if err := retireOAuthProxyOriginGrant(ctx, scope, grant, oauthProxyRetirementQuery(replay)); err != nil {
			t.Fatal("new transaction could not acknowledge the exact committed retirement", err)
		}
		if got := oauthProxyRetirementSnapshot(t, replay, scope, grant); got.state != "revoked" || got.metadata != before.metadata {
			t.Fatal("committed replay lost original reservation evidence")
		}
	})
}

type oauthProxyRetirementRow struct{ state, metadata string }

func oauthProxyRetirementSnapshot(t *testing.T, tx pgx.Tx, scope kernel.OAuthProxyOriginRetirementScope, grant kernel.CapabilityPlan) oauthProxyRetirementRow {
	t.Helper()
	var row oauthProxyRetirementRow
	if err := tx.QueryRow(t.Context(), `SELECT state,(to_jsonb(c)-'state')::text FROM public.capability_identity_one_use c
 WHERE tenant_id=$1 AND purpose=$2 AND replay_key_version=$3 AND replay_digest=$4`,
		string(scope.TenantID), grant.Purpose, grant.ReplayKeyVersion, grant.ReplayDigest[:]).Scan(&row.state, &row.metadata); err != nil {
		t.Fatal("read exact original grant state and all retained metadata", err)
	}
	return row
}

func oauthProxyRetirementQuery(tx pgx.Tx) func(context.Context, string, ...any) (string, error) {
	return func(ctx context.Context, sql string, args ...any) (string, error) {
		var result string
		err := tx.QueryRow(ctx, sql, args...).Scan(&result)
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return result, err
	}
}

// Synthetic records obey the actual native issuance and consumption migrations;
// the fixture supplies no second grant engine or fabricated coordinator Work.
func oauthProxyRetirementSeed(t *testing.T, tx pgx.Tx, purpose, state, label string) (kernel.OAuthProxyOriginRetirementScope, kernel.CapabilityPlan) {
	t.Helper()
	scope := kernel.OAuthProxyOriginRetirementScope{
		TenantID: "tenant-a", OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", FlowID: "AgICAgICAgICAgICAgICAg",
		GrantPurpose: purpose, SourceCommandID: "AwMDAwMDAwMDAwMDAwMDAw", SourceVersion: 7,
	}
	var issued, expiry time.Time
	if err := tx.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())-interval '2 hours',
 date_trunc('second',clock_timestamp())+interval '1 hour'`).Scan(&issued, &expiry); err != nil {
		t.Fatal(err)
	}
	if state == "expired" {
		expiry = issued.Add(time.Hour)
	}
	grant := kernel.CapabilityPlan{Purpose: capability.Purpose(purpose), ReplayKeyVersion: 3, ReplayDigest: sha256.Sum256([]byte(purpose + label)),
		CapabilityID: label, ProofFingerprint: [32]byte{2}, ExpiresAt: expiry, MaxUses: 1}
	var command, fingerprint, generation any
	if state != "issued" {
		command, fingerprint, generation = "BAQEBAQEBAQEBAQEBAQEBA", []byte(strings.Repeat("c", 32)), "9"
	}
	uses := 0
	if state == "finalized" {
		uses = 1
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO public.capability_identity_one_use(
 tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,state,uses,
 command_id,command_fingerprint,generation,origin_command_id,origin_fingerprint,origin_generation,subject_id,
 signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12::numeric,$13,$14,5,$15,$16,$16,'fixture-key',$14,$16)`,
		string(scope.TenantID), purpose, grant.ReplayKeyVersion, grant.ReplayDigest[:], grant.CapabilityID, grant.ProofFingerprint[:], expiry,
		state, uses, command, fingerprint, generation, string(scope.OriginCommandID), []byte(strings.Repeat("o", 32)), string(scope.FlowID), issued)
	if err != nil {
		t.Fatal("seed the exact native original grant record", err)
	}
	return scope, grant
}

func oauthProxyRetirementTransaction(t *testing.T, conn *pgx.Conn) pgx.Tx {
	t.Helper()
	tx, err := conn.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	})
	return tx
}

func oauthProxyRetirementDatabase(t *testing.T) *pgx.Conn {
	t.Helper()
	config := IdentityTestPostgresConfig(t)
	admin, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := admin.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "proxy_retirement_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP DATABASE "+quoted); err != nil {
			t.Error("drop exact fixture-owned retirement database", err)
		}
	})
	config.Database = name
	conn, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	for _, migration := range []string{"001_identity_one_use.sql", "002_original_issuance.sql"} {
		contents, err := fs.ReadFile(Migrations(), migration)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(t.Context(), strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
			t.Fatal("install actual native grant migration", migration, err)
		}
	}
	return conn
}
