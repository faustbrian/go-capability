//go:build integration

package identitycapability

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These tests exercise the exact private SQL operation delegated to by both
// production phase methods. They do not mint sealed coordinator handles or
// claim successful public domain composition while Begin remains closed.
func TestNativeConsumptionIntegration(t *testing.T) {
	config := IdentityTestPostgresConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("admin cleanup")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "capability_execution_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup")
		}
	}()
	config.Database = name
	connect := func(t *testing.T) *pgx.Conn {
		t.Helper()
		conn, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if conn.Close(cleanup) != nil {
				t.Error("connection cleanup")
			}
		})
		return conn
	}
	// The installer closes before DROP DATABASE even if a child assertion fails.
	installer, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if installer.Close(cleanup) != nil {
			t.Error("installer cleanup")
		}
	}()
	contents, err := fs.ReadFile(Migrations(), "001_identity_one_use.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
		t.Fatal(err)
	}
	seed := func(t *testing.T, state string, uses int32, lifetime time.Duration) identitypostgres.CapabilityReservationBinding {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		var expiry time.Time
		if err := installer.QueryRow(ctx, `SELECT clock_timestamp()+$1::bigint*interval '1 microsecond'`, int64(lifetime/time.Microsecond)).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		b := identitypostgres.CapabilityReservationBinding{Command: identity.CommandBinding{CommandID: id, TenantID: "tenant-a"}, Plan: identitypostgres.CapabilityPlan{CapabilityID: string(id), Purpose: "identity.identifier.attach", ReplayKeyVersion: 1, ReplayDigest: [32]byte{1}, ProofFingerprint: [32]byte{2}, ExpiresAt: expiry, MaxUses: 1}, Fingerprint: [32]byte{3}, Generation: 7}
		// Digests are synthetic seed metadata, not a production proof issuer.
		b.Plan.ReplayDigest = [32]byte{}
		copy(b.Plan.ReplayDigest[:], string(id))
		args := append(inputArgs(b), string(id), b.Fingerprint[:], "7", state, uses)
		if state == "issued" {
			args[8], args[9], args[10] = nil, nil, nil
		}
		if _, err := installer.Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,command_id,command_fingerprint,generation,state,uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::numeric,$12,$13)`, args...); err != nil {
			t.Fatal(err)
		}
		return b
	}
	begin := func(t *testing.T, conn *pgx.Conn) pgx.Tx {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		})
		return tx
	}
	executor := func(tx pgx.Tx) func(context.Context, string, ...any) (int64, error) {
		return func(c context.Context, sql string, args ...any) (int64, error) {
			tag, err := tx.Exec(c, sql, args...)
			return tag.RowsAffected(), err
		}
	}
	read := func(t *testing.T, b identitypostgres.CapabilityReservationBinding, state string, uses int32) {
		t.Helper()
		var gotState string
		var generation *string
		var gotUses int32
		var expiry time.Time
		if err := installer.QueryRow(ctx, `SELECT state,uses,generation::text,expires_at FROM public.capability_identity_one_use WHERE capability_id=$1`, b.Plan.CapabilityID).Scan(&gotState, &gotUses, &generation, &expiry); err != nil || gotState != state || gotUses != uses || generation == nil && state != "issued" && state != "revoked" || generation != nil && *generation != strconv.FormatUint(b.Generation, 10) || !expiry.Equal(b.Plan.ExpiresAt) {
			t.Fatal("persisted state/binding changed", err)
		}
	}
	t.Run("magic-link supersession preserves recovery and rolls back", func(t *testing.T) {
		for _, migration := range []string{"002_original_issuance.sql", "003_magiclink_supersession.sql"} {
			contents, err := fs.ReadFile(Migrations(), migration)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := installer.Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
				t.Fatal(err)
			}
		}
		scope, err := MagicLinkScopeFromPayload(supersessionPayload())
		if err != nil {
			t.Fatal(err)
		}
		magicSeed := func(state string, uses int32, scoped bool) identitypostgres.CapabilityReservationBinding {
			b := seed(t, state, uses, time.Hour)
			b.Plan.Purpose = "identity.magic-link.consume"
			var digest any
			if scoped {
				digest = scope.digest[:]
			}
			_, err := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET purpose=$2,origin_command_id=$1,origin_fingerprint=$3,origin_generation=7,subject_id='user',signed_issued_at=date_trunc('second',clock_timestamp()),signed_not_before=date_trunc('second',clock_timestamp()),signing_key_id='key',payload_digest=$3,created_at=clock_timestamp(),supersession_scope=$4 WHERE capability_id=$1`, b.Plan.CapabilityID, string(b.Plan.Purpose), b.Fingerprint[:], digest)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		old := magicSeed("reserved", 0, true)
		issued := magicSeed("issued", 0, true)
		consumed := magicSeed("finalized", 1, true)
		legacy := magicSeed("reserved", 0, false)
		foreign := magicSeed("reserved", 0, true)
		otherScope := scope.digest
		otherScope[0]++
		if _, err := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET supersession_scope=$2 WHERE capability_id=$1`, foreign.Plan.CapabilityID, otherScope[:]); err != nil {
			t.Fatal(err)
		}
		latest := magicSeed("issued", 0, false)
		check := func(b identitypostgres.CapabilityReservationBinding, superseded bool) {
			var marked bool
			if err := installer.QueryRow(ctx, `SELECT superseded_by_command_id IS NOT NULL FROM public.capability_identity_one_use WHERE capability_id=$1`, b.Plan.CapabilityID).Scan(&marked); err != nil || marked != superseded {
				t.Fatal("supersession marker", err)
			}
		}
		for _, commit := range []bool{false, true} {
			tx := begin(t, connect(t))
			if err := persistMagicLinkSupersession(ctx, "tenant-a", string(latest.Command.CommandID), latest.Plan.CapabilityID, scope, executor(tx)); err != nil {
				t.Fatal(err)
			}
			if commit {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
			check(old, commit)
			check(issued, commit)
			check(consumed, false)
			check(legacy, false)
			check(foreign, false)
			check(latest, false)
		}
		read(t, old, "reserved", 0)
		tx := begin(t, connect(t))
		var conflict identity.ConflictError
		if err := executeConsumption(ctx, old, false, executor(tx)); !errors.As(err, &conflict) {
			t.Fatal("superseded reservation consumed", err)
		}
		var state string
		var uses int32
		if err := tx.QueryRow(ctx, statusSQL, append(inputArgs(old), string(old.Command.CommandID), old.Fingerprint[:], "7")...).Scan(&state, &uses); err != nil || state != "reserved" || uses != 0 {
			t.Fatal("supersession destroyed negative recovery", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		// Recovery remains entitled to terminal-release the unchanged unused
		// reservation; supersession is not an invented committed outcome.
		tx = begin(t, connect(t))
		tag, err := tx.Exec(ctx, releaseSQL, append(inputArgs(old), string(old.Command.CommandID), old.Fingerprint[:], "7", "8")...)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("superseded reservation could not release", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		old.Generation = 8
		read(t, old, "released", 0)
		check(old, true)

		// A consume that already holds the common scope fence wins. Resend
		// waits instead of holding account/browser locks or changing its use.
		winning := magicSeed("reserved", 0, true)
		replacement := magicSeed("issued", 0, false)
		consumeTx := begin(t, connect(t))
		if err := executeConsumption(ctx, winning, false, executor(consumeTx)); err != nil {
			t.Fatal(err)
		}
		resendTx := begin(t, connect(t))
		if _, err := resendTx.Exec(ctx, `SET LOCAL statement_timeout='100ms'`); err != nil {
			t.Fatal(err)
		}
		err = persistMagicLinkSupersession(ctx, "tenant-a", string(replacement.Command.CommandID), replacement.Plan.CapabilityID, scope, executor(resendTx))
		var timeout *pgconn.PgError
		if !errors.As(err, &timeout) || timeout.Code != "57014" {
			t.Fatal("resend did not wait on held consuming scope fence", err)
		}
		if err := resendTx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := executeConsumption(ctx, winning, true, executor(consumeTx)); err != nil {
			t.Fatal(err)
		}
		if err := consumeTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		resendTx = begin(t, connect(t))
		if err := persistMagicLinkSupersession(ctx, "tenant-a", string(replacement.Command.CommandID), replacement.Plan.CapabilityID, scope, executor(resendTx)); err != nil {
			t.Fatal(err)
		}
		if err := resendTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		read(t, winning, "finalized", 1)
		check(winning, false)
		t.Run("managed mailbox preserves recovery and rollback", func(t *testing.T) {
			managed, err := ManagedEmailScopeFromPayload(managedScopePayload())
			if err != nil {
				t.Fatal(err)
			}
			// Installed migration 003 is intentionally narrower. Prove the forward
			// extension is necessary before applying it to this populated table.
			legacy := seed(t, "issued", 0, time.Hour)
			_, err = installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET purpose='identity.identifier.verify',origin_command_id=$1,origin_fingerprint=$2,origin_generation=7,subject_id='user',signed_issued_at=date_trunc('second',clock_timestamp()),signed_not_before=date_trunc('second',clock_timestamp()),signing_key_id='key',payload_digest=$2,created_at=clock_timestamp(),supersession_scope=$3 WHERE capability_id=$1`, legacy.Plan.CapabilityID, legacy.Fingerprint[:], managed.digest[:])
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23514" {
				t.Fatal("old installed history did not expose its closed purpose boundary")
			}
			contents, err := fs.ReadFile(Migrations(), "004_managed_email_supersession.sql")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := installer.Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
				t.Fatal("populated managed supersession upgrade", err)
			}
			managedSeed := func(state string, uses int32, scoped bool) identitypostgres.CapabilityReservationBinding {
				b := seed(t, state, uses, time.Hour)
				b.Plan.Purpose = "identity.identifier.verify"
				b.Command.OperationID, b.Command.SchemaID, b.Command.SchemaVersion = "identity.email.verification-confirm", "identity.email.verification-confirm.managed-v1", 1
				var digest any
				if scoped {
					digest = managed.digest[:]
				}
				if _, err := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET purpose=$2,origin_command_id=$1,origin_fingerprint=$3,origin_generation=7,subject_id='user',signed_issued_at=date_trunc('second',clock_timestamp()),signed_not_before=date_trunc('second',clock_timestamp()),signing_key_id='key',payload_digest=$3,created_at=clock_timestamp(),supersession_scope=$4 WHERE capability_id=$1`, b.Plan.CapabilityID, string(b.Plan.Purpose), b.Fingerprint[:], digest); err != nil {
					t.Fatal(err)
				}
				return b
			}
			old := managedSeed("reserved", 0, true)
			issued := managedSeed("issued", 0, true)
			consumed := managedSeed("finalized", 1, true)
			unselected := managedSeed("reserved", 0, false)
			foreign := managedSeed("reserved", 0, true)
			other := managed.digest
			other[0]++
			if _, err := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET supersession_scope=$2 WHERE capability_id=$1`, foreign.Plan.CapabilityID, other[:]); err != nil {
				t.Fatal(err)
			}
			latest := managedSeed("issued", 0, false)
			for _, commit := range []bool{false, true} {
				tx := begin(t, connect(t))
				if err := persistManagedEmailSupersession(ctx, "tenant-a", string(latest.Command.CommandID), latest.Plan.CapabilityID, managed, executor(tx)); err != nil {
					t.Fatal(err)
				}
				if commit {
					err = tx.Commit(ctx)
				} else {
					err = tx.Rollback(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				check(old, commit)
				check(issued, commit)
				check(consumed, false)
				check(unselected, false)
				check(foreign, false)
				check(latest, false)
			}
			tx := begin(t, connect(t))
			var conflict identity.ConflictError
			if err := executeConsumption(ctx, old, false, executor(tx)); !errors.As(err, &conflict) {
				t.Fatal("superseded managed reservation consumed", err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			read(t, old, "reserved", 0)
			t.Run("exact email retirement conserves originals", func(t *testing.T) {
				contents, err := fs.ReadFile(Migrations(), "005_verification_target.sql")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := installer.Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
					t.Fatal("populated verification-target upgrade", err)
				}
				// A forward migration cannot invent targets for old grants. Retained
				// supersession/origin/recovery rows must be byte-for-byte unaffected.
				read(t, old, "reserved", 0)
				check(old, true)
				emailSeed := func(state string, uses int32, tenant, user, target, purpose string) identitypostgres.CapabilityReservationBinding {
					b := seed(t, state, uses, time.Hour)
					var resource any
					if target != "" {
						resource = target
					}
					_, e := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET tenant_id=$2,purpose=$3,origin_command_id=$1,origin_fingerprint=$4,origin_generation=7,subject_id=$5,signed_issued_at=date_trunc('second',clock_timestamp()),signed_not_before=date_trunc('second',clock_timestamp()),signing_key_id='key',payload_digest=$4,created_at=clock_timestamp(),verification_identifier_id=$6 WHERE capability_id=$1`, b.Plan.CapabilityID, tenant, purpose, b.Fingerprint[:], user, resource)
					if e != nil {
						t.Fatal(e)
					}
					b.Command.TenantID, b.Command.UserID, b.Plan.Purpose = identity.TenantID(tenant), identity.UserID(user), capability.Purpose(purpose)
					return b
				}
				const tenant, user, target = "retirement-tenant", "retirement-user", "removed-address"
				issued := emailSeed("issued", 0, tenant, user, target, "identity.identifier.verify")
				reserved := emailSeed("reserved", 0, tenant, user, target, "identity.identifier.verify")
				used := emailSeed("finalized", 1, tenant, user, target, "identity.identifier.verify")
				other := emailSeed("reserved", 0, tenant, user, "remaining-address", "identity.identifier.verify")
				foreignUser := emailSeed("reserved", 0, tenant, "other-user", target, "identity.identifier.verify")
				foreignTenant := emailSeed("reserved", 0, "other-tenant", user, target, "identity.identifier.verify")
				reset := emailSeed("reserved", 0, tenant, user, "", "identity.password.reset-complete")
				legacy := emailSeed("reserved", 0, tenant, user, "", "identity.identifier.verify")
				originless := seed(t, "issued", 0, time.Hour)
				if _, e := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET tenant_id=$2,purpose='identity.identifier.verify' WHERE capability_id=$1`, originless.Plan.CapabilityID, tenant); e != nil {
					t.Fatal(e)
				}
				binding := identity.CommandBinding{TenantID: tenant, UserID: user, RecordID: target}
				tx := begin(t, connect(t))
				var forbidden identity.ForbiddenError
				if e := retireEmailVerificationGrants(ctx, binding, executor(tx)); !errors.As(e, &forbidden) {
					t.Fatal("unclassified active original was ignored", e)
				}
				if e := tx.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
				read(t, issued, "issued", 0)
				read(t, reserved, "reserved", 0)
				// Expired/terminal historical input is not usable authority. Its
				// original target and replay history still must not be rewritten.
				if _, e := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET state='expired' WHERE capability_id=$1`, legacy.Plan.CapabilityID); e != nil {
					t.Fatal(e)
				}
				tx = begin(t, connect(t))
				if e := retireEmailVerificationGrants(ctx, binding, executor(tx)); !errors.As(e, &forbidden) {
					t.Fatal("originless legacy grant was silently attributed to another subject", e)
				}
				if e := tx.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
				if _, e := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET state='expired' WHERE capability_id=$1`, originless.Plan.CapabilityID); e != nil {
					t.Fatal(e)
				}
				for _, commit := range []bool{false, true} {
					tx = begin(t, connect(t))
					if e := retireEmailVerificationGrants(ctx, binding, executor(tx)); e != nil {
						t.Fatal(e)
					}
					if commit {
						err = tx.Commit(ctx)
					} else {
						err = tx.Rollback(ctx)
					}
					if err != nil {
						t.Fatal(err)
					}
					if commit {
						read(t, issued, "revoked", 0)
						read(t, reserved, "revoked", 0)
					} else {
						read(t, issued, "issued", 0)
						read(t, reserved, "reserved", 0)
					}
					read(t, used, "finalized", 1)
					for _, b := range []identitypostgres.CapabilityReservationBinding{other, foreignUser, foreignTenant, reset} {
						read(t, b, "reserved", 0)
					}
					read(t, legacy, "expired", 0)
				}
				tx = begin(t, connect(t))
				var conflict identity.ConflictError
				if e := executeConsumption(ctx, reserved, false, executor(tx)); !errors.As(e, &conflict) {
					t.Fatal("retired reservation consumed", e)
				}
				if e := tx.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
				// Exact original reservation/fingerprint/generation still proves no
				// protected use committed, and only unanimous recovery can release.
				reserved.PreviousGeneration = reserved.Generation
				var state string
				var uses int32
				if e := installer.QueryRow(ctx, statusSQL, boundArgs(reserved)...).Scan(&state, &uses); e != nil || classifyConsumptionRecovery(state, uses) != identitypostgres.RecoveryNotCommitted {
					t.Fatal("retirement erased original recovery linkage", e)
				}
				tag, e := installer.Exec(ctx, releaseSQL, append(boundArgs(reserved), "8")...)
				if e != nil || tag.RowsAffected() != 1 {
					t.Fatal("retired exact negative could not terminal-reconcile", e)
				}
				reserved.Generation = 8
				read(t, reserved, "revoked", 0)
				var originals int
				if e := installer.QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE capability_id=$1 AND origin_command_id=$1 AND origin_generation=7 AND origin_fingerprint=$2 AND payload_digest=$2 AND verification_identifier_id=$3`, reserved.Plan.CapabilityID, reserved.Fingerprint[:], target).Scan(&originals); e != nil || originals != 1 {
					t.Fatal("retirement/reconciliation rewrote origin or target", e)
				}
			})
		})
	})
	t.Run("apply finalize commit and duplicate denial", func(t *testing.T) {
		b := seed(t, "reserved", 0, time.Hour)
		tx := begin(t, connect(t))
		if err := executeConsumption(ctx, b, false, executor(tx)); err != nil {
			t.Fatal(err)
		}
		read(t, b, "reserved", 0)
		var uses int32
		if err := tx.QueryRow(ctx, `SELECT uses FROM public.capability_identity_one_use WHERE capability_id=$1`, b.Plan.CapabilityID).Scan(&uses); err != nil || uses != 1 {
			t.Fatal("provisional use absent", err)
		}
		var conflict identity.ConflictError
		if err := executeConsumption(ctx, b, false, executor(tx)); !errors.As(err, &conflict) {
			t.Fatal("duplicate use", err)
		}
		if err := executeConsumption(ctx, b, true, executor(tx)); err != nil {
			t.Fatal(err)
		}
		read(t, b, "reserved", 0)
		if err := executeConsumption(ctx, b, true, executor(tx)); !errors.As(err, &conflict) {
			t.Fatal("duplicate finalization", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		read(t, b, "finalized", 1)
	})
	t.Run("apply and finalize rollback conserve unused reservation", func(t *testing.T) {
		for _, finalize := range []bool{false, true} {
			b := seed(t, "reserved", 0, time.Hour)
			tx := begin(t, connect(t))
			if err := executeConsumption(ctx, b, false, executor(tx)); err != nil {
				t.Fatal(err)
			}
			if finalize {
				if err := executeConsumption(ctx, b, true, executor(tx)); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			read(t, b, "reserved", 0)
		}
	})
	t.Run("finalize requires a consumed reservation", func(t *testing.T) {
		b := seed(t, "reserved", 0, time.Hour)
		tx := begin(t, connect(t))
		var conflict identity.ConflictError
		if err := executeConsumption(ctx, b, true, executor(tx)); !errors.As(err, &conflict) {
			t.Fatal("unused finalized", err)
		}
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		read(t, b, "reserved", 0)
	})
	t.Run("every frozen binding facet rejects substitution", func(t *testing.T) {
		for _, change := range []func(*identitypostgres.CapabilityReservationBinding){
			func(b *identitypostgres.CapabilityReservationBinding) { b.Command.TenantID = "other" },
			func(b *identitypostgres.CapabilityReservationBinding) { b.Plan.Purpose = "other" },
			func(b *identitypostgres.CapabilityReservationBinding) { b.Plan.ReplayKeyVersion++ },
			func(b *identitypostgres.CapabilityReservationBinding) { b.Plan.ReplayDigest[0]++ },
			func(b *identitypostgres.CapabilityReservationBinding) { b.Plan.CapabilityID += "x" },
			func(b *identitypostgres.CapabilityReservationBinding) { b.Plan.ProofFingerprint[0]++ },
			func(b *identitypostgres.CapabilityReservationBinding) {
				b.Plan.ExpiresAt = b.Plan.ExpiresAt.Add(time.Second)
			},
			func(b *identitypostgres.CapabilityReservationBinding) { b.Plan.MaxUses++ },
			func(b *identitypostgres.CapabilityReservationBinding) {
				b.Command.CommandID, _ = identity.NewCommandID()
			},
			func(b *identitypostgres.CapabilityReservationBinding) { b.Fingerprint[0]++ },
			func(b *identitypostgres.CapabilityReservationBinding) { b.Generation++ },
		} {
			for _, finalize := range []bool{false, true} {
				uses := int32(0)
				if finalize {
					uses = 1
				}
				b := seed(t, "reserved", uses, time.Hour)
				changed := b
				change(&changed)
				tx := begin(t, connect(t))
				var conflict identity.ConflictError
				if err := executeConsumption(ctx, changed, finalize, executor(tx)); !errors.As(err, &conflict) {
					t.Fatal("frozen input bypass", err)
				}
				if tx.Rollback(ctx) != nil {
					t.Fatal("rollback")
				}
				read(t, b, "reserved", uses)
			}
		}
	})
	t.Run("terminal state and expiry never reactivate", func(t *testing.T) {
		for _, state := range []string{"finalized", "released", "expired", "revoked"} {
			uses := int32(0)
			if state == "finalized" {
				uses = 1
			}
			b := seed(t, state, uses, time.Hour)
			for _, finalize := range []bool{false, true} {
				tx := begin(t, connect(t))
				var conflict identity.ConflictError
				if err := executeConsumption(ctx, b, finalize, executor(tx)); !errors.As(err, &conflict) {
					t.Fatal("terminal reactivation", err)
				}
				if tx.Rollback(ctx) != nil {
					t.Fatal("rollback")
				}
				read(t, b, state, uses)
			}
		}
		b := seed(t, "reserved", 0, -time.Second)
		tx := begin(t, connect(t))
		var conflict identity.ConflictError
		if err := executeConsumption(ctx, b, false, executor(tx)); !errors.As(err, &conflict) {
			t.Fatal("expired use", err)
		}
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		read(t, b, "reserved", 0)
	})
	wait := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			var ready bool
			if err := installer.QueryRow(ctx, sql, args...).Scan(&ready); err != nil {
				t.Fatal("database barrier", err)
			}
			if ready {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("database barrier deadline")
			case <-ticker.C:
			}
		}
	}
	t.Run("row lock wait cannot carry expiry forward", func(t *testing.T) {
		b := seed(t, "reserved", 0, 2*time.Second)
		blocker := begin(t, connect(t))
		if _, err := blocker.Exec(ctx, `SELECT 1 FROM public.capability_identity_one_use WHERE capability_id=$1 FOR UPDATE`, b.Plan.CapabilityID); err != nil {
			t.Fatal(err)
		}
		conn := connect(t)
		worker := begin(t, conn)
		call, stop := context.WithCancel(ctx)
		var group sync.WaitGroup
		done := make(chan error, 1)
		group.Go(func() { done <- executeConsumption(call, b, false, executor(worker)) })
		defer func() { stop(); group.Wait() }()
		wait(t, `SELECT cardinality(pg_blocking_pids($1))>0`, conn.PgConn().PID())
		wait(t, `SELECT clock_timestamp()>=$1`, b.Plan.ExpiresAt)
		if blocker.Commit(ctx) != nil {
			t.Fatal("blocker commit")
		}
		var conflict identity.ConflictError
		if err := <-done; !errors.As(err, &conflict) {
			t.Fatal("expiry survived lock wait", err)
		}
		if worker.Rollback(ctx) != nil {
			t.Fatal("worker rollback")
		}
		read(t, b, "reserved", 0)
	})
	t.Run("expiry between apply and finalize rolls back use", func(t *testing.T) {
		b := seed(t, "reserved", 0, 500*time.Millisecond)
		tx := begin(t, connect(t))
		if err := executeConsumption(ctx, b, false, executor(tx)); err != nil {
			t.Fatal(err)
		}
		wait(t, `SELECT clock_timestamp()>=$1`, b.Plan.ExpiresAt)
		var conflict identity.ConflictError
		if err := executeConsumption(ctx, b, true, executor(tx)); !errors.As(err, &conflict) {
			t.Fatal("late finalization", err)
		}
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		read(t, b, "reserved", 0)
	})
	t.Run("issued and missing input cannot be consumed", func(t *testing.T) {
		for _, missing := range []bool{false, true} {
			b := seed(t, "reserved", 0, time.Hour)
			sql := `UPDATE public.capability_identity_one_use SET state='issued',command_id=NULL,command_fingerprint=NULL,generation=NULL WHERE capability_id=$1`
			if missing {
				sql = `DELETE FROM public.capability_identity_one_use WHERE capability_id=$1`
			}
			if _, err := installer.Exec(ctx, sql, b.Plan.CapabilityID); err != nil {
				t.Fatal(err)
			}
			tx := begin(t, connect(t))
			for _, finalize := range []bool{false, true} {
				var conflict identity.ConflictError
				if err := executeConsumption(ctx, b, finalize, executor(tx)); !errors.As(err, &conflict) {
					t.Fatal("unreserved input mutated", err)
				}
			}
			if tx.Rollback(ctx) != nil {
				t.Fatal("rollback")
			}
			var unchanged bool
			if missing {
				err = installer.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE capability_id=$1)`, b.Plan.CapabilityID).Scan(&unchanged)
			} else {
				err = installer.QueryRow(ctx, `SELECT state='issued' AND uses=0 AND command_id IS NULL AND command_fingerprint IS NULL AND generation IS NULL FROM public.capability_identity_one_use WHERE capability_id=$1`, b.Plan.CapabilityID).Scan(&unchanged)
			}
			if err != nil || !unchanged {
				t.Fatal("unreserved input prefix", err)
			}
		}
	})
	t.Run("full width current generation is conserved", func(t *testing.T) {
		b := seed(t, "reserved", 0, time.Hour)
		b.Generation = math.MaxUint64
		if _, err := installer.Exec(ctx, `UPDATE public.capability_identity_one_use SET generation=$2::numeric WHERE capability_id=$1`, b.Plan.CapabilityID, strconv.FormatUint(b.Generation, 10)); err != nil {
			t.Fatal(err)
		}
		tx := begin(t, connect(t))
		if executeConsumption(ctx, b, false, executor(tx)) != nil || executeConsumption(ctx, b, true, executor(tx)) != nil || tx.Commit(ctx) != nil {
			t.Fatal("full-width generation lost")
		}
		read(t, b, "finalized", 1)
	})
	t.Run("concurrent use admits one commit and honors winner rollback", func(t *testing.T) {
		for _, commit := range []bool{false, true} {
			b := seed(t, "reserved", 0, time.Hour)
			first := begin(t, connect(t))
			if err := executeConsumption(ctx, b, false, executor(first)); err != nil {
				t.Fatal(err)
			}
			conn := connect(t)
			second := begin(t, conn)
			call, stop := context.WithCancel(ctx)
			var group sync.WaitGroup
			done := make(chan error, 1)
			group.Go(func() { done <- executeConsumption(call, b, false, executor(second)) })
			defer func() { stop(); group.Wait() }()
			wait(t, `SELECT cardinality(pg_blocking_pids($1))>0`, conn.PgConn().PID())
			if commit {
				if executeConsumption(ctx, b, true, executor(first)) != nil || first.Commit(ctx) != nil {
					t.Fatal("first finalization")
				}
			} else if first.Rollback(ctx) != nil {
				t.Fatal("first rollback")
			}
			err := <-done
			if commit {
				var conflict identity.ConflictError
				if !errors.As(err, &conflict) || second.Rollback(ctx) != nil {
					t.Fatal("second committed use", err)
				}
			} else if err != nil || executeConsumption(ctx, b, true, executor(second)) != nil || second.Commit(ctx) != nil {
				t.Fatal("rollback prevented valid successor", err)
			}
			read(t, b, "finalized", 1)
		}
	})
}
