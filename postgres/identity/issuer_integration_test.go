//go:build integration

package identitycapability_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This exercises the native original producer and real audit/outbox through
// public coordinator custody. No issued row is seeded for the production path.
func testOriginalIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, encrypted ...*issuanceDeliveryFixture) {
	now := time.Now().UTC().Truncate(time.Second)
	key := []byte("0123456789abcdef0123456789abcdef")
	signingID := "signing-v1"
	if strings.Contains(t.Name(), "long_signing_key") {
		signingID = strings.Repeat("k", 256)
	}
	signer, err := capability.NewHMACSHA256Signer(signingID, key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: signingID, Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	contributors := []identitypostgres.Contributor{repo, auditing, lifecycle, issuer}
	var sending *issuanceDeliveryFixture
	if len(encrypted) != 0 {
		sending = encrypted[0]
		contributors = append(contributors, sending.contributor)
	}
	registry, err := identitypostgres.NewContributorRegistry(contributors)
	if err != nil {
		t.Fatal(err)
	}
	c, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "reset-origin", "missing", "wrong-envelope", "wrong-replay", "late-failure", "multi-grant", "missing-delivery"} {
		if sending != nil && mode == "reset-origin" {
			continue
		}
		if sending == nil && mode == "missing-delivery" {
			continue
		}
		if sending != nil && mode == "multi-grant" {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			uid, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: identity.UserID(uid), ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.user.create", PolicyID: "test-policy", PolicyVersion: 1, SchemaID: "identity-user", SchemaVersion: 1, CorrelationID: "test-correlation"}
			cmd, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive})
			if err != nil {
				t.Fatal(err)
			}
			payload := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: "identifier", Operation: "identity.identifier.verify", ExpiresAt: now.Add(5 * time.Minute), MaxUses: 1}
			if mode == "reset-origin" {
				payload.Operation, payload.Resource, payload.CorrelationID = "identity.password.reset-complete", "identity.password/credential", string(id)
				payload.IssuedAt, payload.NotBefore = now, now
				payload.Caveats = map[string]string{"password.recovery-path": "emailed_password_reset", "password.credential-version": "1", "password.credential-authority-version": "2", "password.user-authority-version": "3", "password.identifier": "identifier", "password.identifier-version": "4", "password.binding-key-version": "1", "password.callback": strings.Repeat("a", 64)}
			}
			if strings.Contains(t.Name(), "earlier_not_before") {
				payload.IssuedAt = now
				payload.NotBefore = now.Add(-time.Second)
			}
			inputs := []capability.Payload{payload}
			if mode == "multi-grant" {
				inputs = append(inputs, payload)
			}
			prepared, err := issuer.Prepare(ctx, b, inputs)
			if err != nil {
				t.Fatal(err)
			}
			issue, err := prepared.Plan()
			if err != nil {
				t.Fatal(err)
			}
			var resetProof capability.Proof
			var resetWire [32]byte
			if mode == "reset-origin" {
				if err := prepared.TransferForDelivery(ctx, 0, func(_ context.Context, raw []byte) error {
					resetWire = sha256.Sum256(raw)
					var e error
					resetProof, e = capability.ParseProof(string(raw), capability.DefaultLimits())
					return e
				}); err != nil {
					t.Fatal("synthetic delivered reset custody", err)
				}
				defer resetProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
				assertIssuanceOriginDenied(t, issuer, ctx, pool, resetProof, "identity.password.reset-complete", false)
				assertIssuanceOriginDenied(t, issuer, ctx, pool, resetProof, "identity.password.reset-complete", true)
			}
			var sealed deliverypostgres.PreparedDelivery
			var deliveryPlan *identitypostgres.DeliveryPlan
			if sending != nil {
				sealed = sending.prepare(t, ctx, b, prepared, len(inputs), payload.ExpiresAt)
				p, err := sealed.Plan()
				if err != nil {
					t.Fatal(err)
				}
				deliveryPlan = &p
			}
			if mode == "wrong-envelope" {
				issue.Grants[0].ProofFingerprint = [32]byte{9}
			}
			if mode == "wrong-replay" {
				issue.Grants[0].ReplayDigest = [32]byte{9}
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
			if err != nil {
				t.Fatal(err)
			}
			recordInput := audit.RecordInput{Action: "identity.user.create", OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "standard", "aggregate.type": "user", "aggregate.id": string(b.UserID), "aggregate.before_version": "0", "aggregate.after_version": "1"}}
			redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
			if err != nil {
				t.Fatal(err)
			}
			build := func() audit.Record {
				record, e := builder.Build(recordInput)
				if e != nil {
					t.Fatal(e)
				}
				record, e = redactor.Redact(ctx, record)
				if e != nil {
					t.Fatal(e)
				}
				return record
			}
			record := build()
			digest, err := identitypostgres.AuditBindingDigest(b, record)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Audits: []identitypostgres.AuditPlan{{EventType: "identity.user.create", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, CapabilityIssuance: &issue, Delivery: deliveryPlan})
			if err != nil {
				t.Fatal("prepare", err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, cmd, plan)
			if err != nil {
				t.Fatal("reserve", err)
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("begin", err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			user, err := repo.ApplyUserCreation(ctx, w, cmd)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "missing" {
				stageErr := issuer.Stage(ctx, w, prepared)
				if mode == "wrong-envelope" {
					var invalid identity.InvalidInputError
					if !errors.As(stageErr, &invalid) {
						t.Fatal("tampered envelope was not rejected at staging", stageErr)
					}
					c.Abort(w, stageErr)
					commandBytes, _ := base64.RawURLEncoding.DecodeString(string(id))
					var users, grants, audits, events int
					if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$3),(SELECT count(*) FROM audit.identity_command_bindings WHERE tenant_id=$1 AND command_id=$4),(SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$4)`, string(b.TenantID), string(b.UserID), string(id), commandBytes).Scan(&users, &grants, &audits, &events); err != nil || users != 0 || grants != 0 || audits != 0 || events != 0 {
						t.Fatal("tampered envelope retained durable effects", err)
					}
					return
				} else if stageErr != nil {
					t.Fatal("stage", stageErr)
				}
			}
			if sending != nil && mode != "missing-delivery" {
				if err := sending.contributor.Stage(ctx, w, sealed); err != nil {
					t.Fatal(err)
				}
			}
			primary, err := w.DatabaseTime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			recordInput.OccurredAt = primary
			record = build()
			if err := w.StageAudit(0, record); err != nil {
				t.Fatal(err)
			}
			if err := w.StageLifecycle(0, primary); err != nil {
				t.Fatal(err)
			}
			commandBytes, _ := base64.RawURLEncoding.DecodeString(string(id))
			counts := func(want int, grants int) {
				t.Helper()
				var u, i, a, l int
				e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$3),(SELECT count(*) FROM audit.identity_command_bindings WHERE tenant_id=$1 AND command_id=$4),(SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$4)`, string(b.TenantID), string(b.UserID), string(id), commandBytes).Scan(&u, &i, &a, &l)
				if e != nil || u != want || i != grants || a != want || l != want {
					t.Fatal("atomic native issuance", u, i, a, l, e)
				}
				if sending != nil {
					var n int
					if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1 AND ciphertext IS NOT NULL`, commandBytes).Scan(&n); err != nil || n != grants {
						t.Fatal("atomic encrypted issuance", n, err)
					}
				}
			}
			// An independent connection cannot see the provisional domain mutation.
			var visible int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)).Scan(&visible); err != nil || visible != 0 {
				t.Fatal("provisional user visible", err)
			}
			counts(0, 0)
			// Inject a native audit write failure after issuer persistence. NOT VALID
			// preserves preceding rows but rejects this command's later audit insert.
			if mode == "late-failure" {
				if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT issuance_test_failure CHECK(false) NOT VALID`); err != nil {
					t.Fatal(err)
				}
			}
			result, err := c.Commit(w, identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
			if mode == "late-failure" {
				if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT issuance_test_failure`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "success" || mode == "multi-grant" || mode == "reset-origin" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("native issue commit", err)
				}
				counts(1, len(inputs))
				_, replay, err := c.ReserveCommand(ctx, b, cmd, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("replay", err)
				}
				counts(1, len(inputs))
				var wire [32]byte
				if mode == "reset-origin" {
					wire = resetWire
					testResetIssuanceOrigin(t, ctx, pool, issuer, resetProof, id, issue.Grants[0])
				} else if sending == nil {
					if err := prepared.TransferForDelivery(ctx, 0, func(_ context.Context, token []byte) error { wire = sha256.Sum256(token); return nil }); err != nil {
						t.Fatal(err)
					}
				} else {
					wire = sending.digests[0]
					if err := prepared.TransferForDelivery(ctx, 0, func(context.Context, []byte) error { t.Error("transferred proof reused"); return nil }); err == nil {
						t.Fatal("proof custody reused")
					}
				}
				var stored []byte
				var state, subject, signing string
				if err := pool.Raw().QueryRow(ctx, `SELECT proof_fingerprint,state,subject_id,signing_key_id FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID).Scan(&stored, &state, &subject, &signing); err != nil || string(stored) != string(wire[:]) || state != "issued" || subject != string(b.UserID) || signing != signingID {
					t.Fatal("original binding", err)
				}
				if sending != nil {
					sending.process(t, ctx, pool, b, *deliveryPlan, keys)
				}
			} else {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("mismatched issuance committed")
				}
				counts(0, 0)
			}
		})
	}
}
