//go:build integration

package identitycapability_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	legacycapability "github.com/faustbrian/go-capability/v2/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpostgres "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type testPolicy struct{}

func (testPolicy) Decide(ctx context.Context, _ authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

func TestPublicCoordinatorComposition(t *testing.T) {
	config := identitycapability.IdentityTestPostgresConfig(t)
	dsn := config.ConnString()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable cluster unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_capability_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	rolesOwned := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup failed")
		}
		if rolesOwned {
			if _, err := admin.Exec(cleanup, "DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
				t.Error("role cleanup failed")
			}
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	legacySQL, err := os.ReadFile("testdata/legacy_consumptions.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(legacySQL)); err != nil {
		t.Fatal("legacy install failed", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := legacycapability.MigrateLegacyConsumption(ctx, tx, "https://identity.example.test"); err != nil {
		t.Fatal("explicit legacy issuer migration", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	legacy, err := legacycapability.NewConsumptionStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Consume(ctx, capability.Consumption{Issuer: "https://identity.example.test", CapabilityID: "legacy-consumed", MaxUses: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal("legacy seed consumption failed", err)
	}
	backend, err := migrationpostgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(identitypostgres.MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("identity install failed", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	install, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer install.Rollback(ctx)
	if _, err := install.Exec(ctx, auditpostgres.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	for _, source := range []fs.FS{auditpostgres.Migrations(), outboxpostgres.Migrations(), identityoutbox.Migrations(), identitycapability.Migrations()} {
		entries, err := fs.ReadDir(source, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			contents, err := fs.ReadFile(source, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := install.Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
				t.Fatal("owned install failed", entry.Name(), err)
			}
		}
	}
	if err := install.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rolesOwned = true
	deliveryRunner, err := migrations.NewRunner(deliverypostgres.MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deliveryRunner.Up(ctx); err != nil {
		t.Fatal("delivery install", err)
	}
	registrationSource := identitypostgres.PasswordRegistrationMigrationSource{Base: identitypostgres.CredentialMigrationSource{Base: identitypostgres.IdentifierMutationMigrationSource{Base: deliverypostgres.MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14}, Version: 15}, Version: 16}, Version: 17}
	registrationRunner, err := migrations.NewRunner(registrationSource, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registrationRunner.Up(ctx); err != nil {
		t.Fatal("registration history install", err)
	}
	statusRunner, err := migrations.NewRunner(identitypostgres.StatusMigrationSource{Base: registrationSource, Version: 18}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statusRunner.Up(ctx); err != nil {
		t.Fatal("current recipient authority install", err)
	}
	preparationRunner, err := migrations.NewRunner(identitypostgres.AdmissionPreparationMigrationSource{Base: identitypostgres.PreparationMigrationSource{Base: identitypostgres.StatusMigrationSource{Base: registrationSource, Version: 18}, Version: 19}, Version: 20}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparationRunner.Up(ctx); err != nil {
		t.Fatal("original preparation install", err)
	}
	var legacyUses int32
	if err := db.QueryRowContext(ctx, `SELECT uses FROM public.capability_consumptions WHERE capability_id='legacy-consumed'`).Scan(&legacyUses); err != nil || legacyUses != 1 {
		t.Fatal("additive adapter changed legacy data", err)
	}
	repo, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	p := identitycapability.NewParticipant()
	t.Run("MFA continuation issuance", func(t *testing.T) { testMFAIssuance(t, ctx, pool, repo, auditing, lifecycle) })
	t.Run("reset recipient issuance", func(t *testing.T) { testResetRecipientIssuance(t, ctx, pool, repo, auditing, lifecycle) })
	t.Run("magic-link recipient issuance", func(t *testing.T) { testMagicLinkRecipientIssuance(t, ctx, pool, repo, auditing, lifecycle) })
	t.Run("registration issuance", func(t *testing.T) { testRegistrationIssuance(t, ctx, pool, repo, auditing, lifecycle, dsn, name) })
	t.Run("original issuance", func(t *testing.T) { testOriginalIssuance(t, ctx, pool, repo, auditing, lifecycle) })
	t.Run("original issuance earlier not before", func(t *testing.T) { testOriginalIssuance(t, ctx, pool, repo, auditing, lifecycle) })
	t.Run("original issuance long signing key", func(t *testing.T) { testOriginalIssuance(t, ctx, pool, repo, auditing, lifecycle) })
	t.Run("original issuance encrypted delivery", func(t *testing.T) {
		testOriginalIssuance(t, ctx, pool, repo, auditing, lifecycle, newIssuanceDeliveryFixture(t))
	})
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, auditing, lifecycle, p})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authorization.NewDecisionService(testPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: policy}})
	if err != nil {
		t.Fatal(err)
	}

	prepare := func() (identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		commandID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		b := identity.CommandBinding{CommandID: commandID, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: "identity.identifier.attach", RecordID: string(commandID), PolicyID: "test-policy", PolicyVersion: 1, SchemaID: "identity-identifier", SchemaVersion: 1, CorrelationID: "test-correlation"}
		s := identity.IdentifierCommand{Binding: b, Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: identity.IdentifierID(b.RecordID), Action: identity.IdentifierAttach, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1}, SessionID: "session-a", SessionVersion: 1}
		now := time.Now().UTC().Truncate(time.Second)
		payload, err := identity.BuildIdentifierProofPayload(identity.IdentifierProofSpec{Command: s, Issuer: "https://identity.example.test", Audience: "backend", ID: string(commandID), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(4 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		key := []byte("12345678901234567890123456789012")
		signer, err := capability.NewHMACSHA256Signer("fixture", key)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := capability.NewHMACSHA256Verifier(key)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "fixture", Verifier: verifier}})
		if err != nil {
			t.Fatal(err)
		}
		token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		s.Proof, err = capability.Verify(ctx, token, keys, capability.VerifyOptions{Issuer: "https://identity.example.test", Now: now, Limits: capability.DefaultLimits()})
		if err != nil {
			t.Fatal(err)
		}
		command, err := identity.NewIdentifierCommand(s)
		if err != nil {
			t.Fatal(err)
		}
		builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
		if err != nil {
			t.Fatal(err)
		}
		record, err := builder.Build(audit.RecordInput{Action: "identity.identifier.add", OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "identifier", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "standard", "aggregate.type": "identifier", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"}})
		if err != nil {
			t.Fatal(err)
		}
		redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
		if err != nil {
			t.Fatal(err)
		}
		record, err = redactor.Redact(ctx, record)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := identitypostgres.AuditBindingDigest(b, record)
		if err != nil {
			t.Fatal(err)
		}
		// Fixture issuance is explicit seed data, not a production issuer, session
		// authority or risk orchestration. Runtime phases below are all production.
		plan, err := c.PrepareCommandPlan(b, command, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Audits: []identitypostgres.AuditPlan{{EventType: "identity.identifier.add", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identifier.added.v1", AfterVersion: 1}, Capability: &identitypostgres.CapabilityPlan{CapabilityID: payload.ID, Purpose: capability.Purpose(b.OperationID), ReplayKeyVersion: 1, ReplayDigest: sha256.Sum256([]byte("fixture-replay:" + string(commandID))), ProofFingerprint: sha256.Sum256([]byte(token)), ExpiresAt: payload.ExpiresAt, MaxUses: 1}})
		if err != nil {
			t.Fatal(err)
		}
		cp := plan.Capability
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,1)`, string(b.TenantID), string(cp.Purpose), cp.ReplayKeyVersion, cp.ReplayDigest[:], cp.CapabilityID, cp.ProofFingerprint[:], cp.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		return b, command, plan
	}
	for _, scenario := range []string{"release", "wrong-proof", "wrong-digest", "wrong-key", "wrong-expiry", "terminal", "missing", "takeover", "concurrent-replay", "recovery-conflict", "recovery-committed", "recovery-missing", "takeover-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			b, command, plan := prepare()
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			switch scenario {
			case "wrong-proof":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET proof_fingerprint=$2 WHERE capability_id=$1`, plan.Capability.CapabilityID, make([]byte, 32))
			case "wrong-digest":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET replay_digest=$2 WHERE capability_id=$1`, plan.Capability.CapabilityID, make([]byte, 32))
			case "wrong-key":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET replay_key_version=2 WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "wrong-expiry":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET expires_at=expires_at+interval '1 second' WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "terminal":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state='revoked' WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "missing":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM public.capability_identity_one_use WHERE capability_id=$1`, plan.Capability.CapabilityID)
			}
			if err != nil {
				t.Fatal(err)
			}
			reservation, result, err := c.ReserveCommand(ctx, b, command, plan)
			if scenario != "release" && scenario != "takeover" && scenario != "concurrent-replay" && !strings.HasPrefix(scenario, "recovery-") && scenario != "takeover-conflict" {
				if err == nil {
					t.Fatal("invalid input reserved")
				}
				var claims int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, key).Scan(&claims); err != nil || claims != 0 {
					t.Fatal("reservation failure left claim prefix", err)
				}
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("production reserve failed", err)
			}
			if _, err := c.Begin(ctx, reservation); err == nil {
				t.Fatal("incomplete proof workflow activated")
			}
			if scenario == "concurrent-replay" {
				var group sync.WaitGroup
				failures := make(chan error, 6)
				for range 6 {
					group.Go(func() {
						_, got, e := c.ReserveCommand(ctx, b, command, plan)
						if e != nil || got.Outcome != identity.CommitOutcomeInProgress {
							failures <- errors.New("concurrent replay changed reservation")
						}
					})
				}
				group.Wait()
				close(failures)
				for failure := range failures {
					t.Error(failure)
				}
			}
			expire := func() {
				t.Helper()
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
					t.Fatal(err)
				}
			}
			generation := "2"
			if scenario == "takeover" {
				expire()
				if _, _, err := c.ReserveCommand(ctx, b, command, plan); err != nil {
					t.Fatal("production takeover failed", err)
				}
				generation = "3"
			}
			switch scenario {
			case "recovery-conflict":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET proof_fingerprint=$2 WHERE capability_id=$1`, plan.Capability.CapabilityID, make([]byte, 32))
			case "recovery-committed":
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state='finalized',uses=1 WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "recovery-missing":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM public.capability_identity_one_use WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "takeover-conflict":
				expire()
				_, err = pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET generation=9 WHERE capability_id=$1`, plan.Capability.CapabilityID)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := c.ReserveCommand(ctx, b, command, plan); err == nil {
					t.Fatal("wrong predecessor transferred")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			expire()
			query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			got, err := c.RecoverCommand(ctx, query, caller)
			var unavailable identity.UnavailableError
			if strings.HasPrefix(scenario, "recovery-") || scenario == "takeover-conflict" {
				if got.Outcome != identity.CommitOutcomeInProgress || !errors.As(err, &unavailable) {
					t.Fatal("uncertain participant terminalized", got.Outcome, err)
				}
				var j string
				var audits int
				if err := pool.Raw().QueryRow(ctx, `SELECT generation::text,(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1) FROM identity.commands WHERE command_id=$1`, key).Scan(&j, &audits); err != nil || j != "1" || audits != 0 {
					t.Fatal("uncertain recovery left prefix", err)
				}
				return
			}
			if got.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &unavailable) {
				t.Fatal("production recovery failed", got.Outcome, err)
			}
			var state, actualGeneration string
			var audits, outbox int
			if err := pool.Raw().QueryRow(ctx, `SELECT state,generation::text,(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$2) FROM public.capability_identity_one_use WHERE capability_id=$1`, plan.Capability.CapabilityID, key).Scan(&state, &actualGeneration, &audits, &outbox); err != nil {
				t.Fatal(err)
			}
			if state != "released" || actualGeneration != generation || audits != 1 || outbox != 0 {
				t.Fatal("release/audit/receipt not atomic", state, actualGeneration, audits, outbox)
			}
			again, _ := c.RecoverCommand(ctx, query, caller)
			if again.Outcome != got.Outcome || again.Binding != got.Binding {
				t.Fatal("terminal receipt changed")
			}
			replay, receipt, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil || receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("aborted replay changed original receipt", err)
			}
			if _, err := c.Begin(ctx, replay); err == nil {
				t.Fatal("terminal replay supplied execution authority")
			}
		})
	}
}
