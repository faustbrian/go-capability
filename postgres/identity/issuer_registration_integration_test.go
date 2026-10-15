//go:build integration

package identitycapability_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// The fixture owns only the native signup phase; real signing, registration,
// issued storage, audit and outbox use public owners. It does not implement
// password material/HIBP or the email confirmation workflow.
type signupIssuerPhase struct {
	domain   *identitypostgres.PasswordRegistrationDomain
	intent   identitypostgres.PasswordRegistrationIntent
	command  identity.Command
	issuer   *identitycapability.Issuer
	prepared identitycapability.PreparedIssuance
	skip     bool
	delivery *deliverypostgres.Contributor
	sealed   deliverypostgres.PreparedDelivery
}

func (*signupIssuerPhase) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *signupIssuerPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.PasswordSignupFeature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *signupIssuerPhase) ValidateFeatureCommand(c identity.Command, _ identitypostgres.CommandPlan) error {
	if c != p.command {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *signupIssuerPhase) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if !p.skip {
		if _, err := p.domain.Apply(ctx, w, p, c, p.intent); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.issuer.Stage(ctx, w, p.prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.delivery != nil {
		if err := p.delivery.Stage(ctx, w, p.sealed); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	s, _ := c.PasswordSignupFeature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (*signupIssuerPhase) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3)`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	found := false
	if !rows.Next() {
		rows.Close()
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	err = rows.Scan(&found)
	if err == nil && (rows.Next() || rows.Err() != nil) {
		err = identity.UnavailableError{}
	}
	rows.Close()
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	if found {
		return identitypostgres.RecoveryCommitted, nil
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

func testRegistrationIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, dsn, databaseName string) {
	for _, mode := range []string{"success", "target-retention", "target-retention-rollback", "origin-read", "encrypted-delivery", "restored-delivery", "restored-late-failure", "missing-registration", "foreign-target", "wrong-envelope", "wrong-replay", "late-failure", "disconnect-before", "disconnect-after", "recovery-issued", "recovery-missing", "recovery-conflict"} {
		t.Run(mode, func(t *testing.T) {
			lateFailure := mode == "late-failure" || mode == "restored-late-failure" || mode == "target-retention-rollback"
			selectedPool, selectedRepo := pool, repo
			var fault *signupCommitFault
			if strings.HasPrefix(mode, "disconnect-") {
				fault = &signupCommitFault{before: mode == "disconnect-before"}
				var err error
				selectedPool, err = database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = databaseName
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if selectedPool.Close(cleanup) != nil {
						t.Error("fault pool cleanup failed")
					}
				}()
				selectedRepo, err = identitypostgres.NewRepository(selectedPool, identitypostgres.Config{MaximumDuration: time.Second})
				if err != nil {
					t.Fatal(err)
				}
			}
			domain, err := identitypostgres.NewPasswordRegistrationDomain(selectedRepo, identitypostgres.PasswordRegistrationDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, err := capability.NewHMACSHA256Signer("signing-v1", key)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(key)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: verifier}})
			if err != nil {
				t.Fatal(err)
			}
			issuerConfig := identitycapability.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second}
			issuerConfig.RetainEmailVerificationTargets = strings.HasPrefix(mode, "target-retention")
			issuer, err := identitycapability.NewIssuer(issuerConfig)
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			uid, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: string(id), ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.password.signup", PolicyID: "test-policy", PolicyVersion: 1, SchemaID: "password-signup", SchemaVersion: 1, CorrelationID: "signup-correlation"}
			creation := b
			creation.UserID, creation.AnonymousFlowID, creation.OperationID, creation.SchemaID = identity.UserID(uid), "", "identity.user.create", "identity-user"
			intent := identitypostgres.PasswordRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Identifier: identity.Identifier{ID: identity.IdentifierID(uid), UserID: identity.UserID(uid), Kind: identity.IdentifierEmail, CanonicalValue: string(uid) + "@example.test", Version: 1}, Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: identity.UserID(uid), Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
			fields, err := identitypostgres.PasswordRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			cmd, err := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, "$synthetic$signup-verifier", auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))))
			if err != nil {
				t.Fatal(err)
			}
			target := identity.UserID(uid)
			if mode == "foreign-target" {
				target = "foreign-user"
			}
			payload := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: string(target), Tenant: string(b.TenantID), Resource: "identifier", Operation: "identity.identifier.verify", ExpiresAt: now.Add(5 * time.Minute), MaxUses: 1}
			if issuerConfig.RetainEmailVerificationTargets {
				payload.Resource = string(intent.Identifier.ID)
			}
			if mode == "origin-read" {
				payload.Caveats = map[string]string{"email.profile": "registration-v1", "email.confirm_operation": "identity.email.verification-confirm", "email.intent": strings.Repeat("a", 64), "email.binding_key_version": "1"}
			}
			prepared, err := issuer.PrepareRegistration(ctx, b, target, []capability.Payload{payload})
			if err != nil {
				t.Fatal("native registration preparation", err)
			}
			issue, err := prepared.Plan()
			if err != nil {
				t.Fatal(err)
			}
			var originProof capability.Proof
			if mode == "origin-read" {
				// Capture only opaque test custody, not a plaintext fixture or log.
				if err := prepared.TransferForDelivery(ctx, 0, func(_ context.Context, token []byte) error {
					var e error
					originProof, e = capability.ParseProof(string(token), capability.DefaultLimits())
					return e
				}); err != nil {
					t.Fatal(err)
				}
				defer originProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
				reader, ok := any(issuer).(registrationOriginReader)
				if !ok {
					t.Fatal("native registration origin reader is missing")
				}
				grant, origin, version, readErr := reader.ReadRegistrationOrigin(ctx, pool, originProof)
				var denied identity.ForbiddenError
				if !errors.As(readErr, &denied) || grant.EnvelopeDigest() != ([32]byte{}) || origin != "" || version != 0 {
					t.Fatal("unpersisted preparation became registration provenance")
				}
			}
			if mode == "wrong-envelope" {
				issue.Grants[0].ProofFingerprint = [32]byte{9}
			}
			if mode == "wrong-replay" {
				issue.Grants[0].ReplayDigest = [32]byte{9}
			}
			phase := &signupIssuerPhase{domain: domain, intent: intent, command: cmd, issuer: issuer, prepared: prepared, skip: mode == "missing-registration"}
			contributors := []identitypostgres.Contributor{selectedRepo, auditing, lifecycle, phase, issuer}
			var sending *issuanceDeliveryFixture
			var deliveryPlan *identitypostgres.DeliveryPlan
			if mode == "encrypted-delivery" || strings.HasPrefix(mode, "restored-") {
				sending = newIssuanceDeliveryFixture(t)
				phase.delivery = sending.contributor
				if strings.HasPrefix(mode, "restored-") {
					config := identitycapability.IssuancePreparationConfig{Deployment: "test", ActiveEnvelopeKey: "issuer-envelope-v1", EnvelopeKeys: map[string][]byte{"issuer-envelope-v1": bytes.Repeat([]byte{8}, 32)}, VerificationKeys: []identitycapability.PreparationVerificationKey{{ID: "signing-v1", HMAC: key}}, Clock: func() time.Time { return now }}
					codec, e := identitycapability.NewIssuancePreparationCodec(issuer, config)
					if e != nil {
						t.Fatal(e)
					}
					phase.sealed = sending.prepare(t, ctx, b, prepared, 1, payload.ExpiresAt, codec)
					deliveryWire, e := sending.contributor.CheckpointPreparation(ctx, phase.sealed, 1)
					if e != nil {
						t.Fatal(e)
					}
					// Only encrypted checkpoints and original declaration cross this
					// boundary. The complete journal-retention journey is owned by
					// the signup workflow, not this native staging composition.
					issuer, e = identitycapability.NewIssuer(issuerConfig)
					if e != nil {
						t.Fatal(e)
					}
					codec, e = identitycapability.NewIssuancePreparationCodec(issuer, config)
					if e != nil {
						t.Fatal(e)
					}
					phase.prepared, e = codec.RestorePreparation(ctx, b, 1, issue, sending.issuanceCheckpoint)
					if e != nil {
						t.Fatal("restored native issuance", e)
					}
					phase.issuer = issuer
					contributors[len(contributors)-1] = issuer
					fresh := newIssuanceDeliveryFixture(t)
					fresh.digests = append([][32]byte(nil), sending.digests...)
					fresh.registrationUser = target
					phase.sealed, e = fresh.contributor.RestorePreparation(ctx, b, 1, deliveryWire)
					if e != nil {
						t.Fatal("restored native delivery", e)
					}
					sending = fresh
					phase.delivery = fresh.contributor
				} else {
					phase.sealed = sending.prepare(t, ctx, b, prepared, 1, payload.ExpiresAt)
				}
				p, e := phase.sealed.Plan()
				if e != nil {
					t.Fatal(e)
				}
				deliveryPlan = &p
				contributors = append(contributors, phase.delivery)
			}
			registry, err := identitypostgres.NewContributorRegistry(contributors)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := authorization.NewDecisionService(testPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := identitypostgres.NewCoordinator(selectedPool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: policy}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
			if err != nil {
				t.Fatal(err)
			}
			record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "protected", "aggregate.type": "user", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0"}})
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
			digest, err := identitypostgres.FeatureAuditBindingDigest(b, op, "user", record)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Feature: &identitypostgres.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "user", Audits: []identitypostgres.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "user.created.v1"}, CapabilityIssuance: &issue, Delivery: deliveryPlan})
			if err != nil {
				t.Fatal("native signup plan", err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, cmd, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, err := c.ApplyFeature(ctx, w, cmd)
			if err == nil {
				var visible int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(uid)).Scan(&visible); e != nil || visible != 0 {
					t.Fatal("provisional signup visible", e)
				}
				if lateFailure {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT signup_issue_failure CHECK(false) NOT VALID`); e != nil {
						t.Fatal(e)
					}
				}
				result, err = c.Commit(w, result)
				if lateFailure {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT signup_issue_failure`); e != nil {
						t.Fatal(e)
					}
				}
			} else {
				_, _ = c.Abort(w, err)
			}
			want := 0
			if mode == "success" || mode == "target-retention" || mode == "origin-read" || mode == "encrypted-delivery" || mode == "restored-delivery" || mode == "disconnect-after" || strings.HasPrefix(mode, "recovery-") {
				want = 1
				if fault == nil && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != b) {
					t.Fatal("native anonymous issuance failed", err)
				}
				var subject, origin string
				var fingerprint []byte
				if e := pool.Raw().QueryRow(ctx, `SELECT subject_id,origin_command_id,proof_fingerprint FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID).Scan(&subject, &origin, &fingerprint); e != nil || subject != string(uid) || origin != string(id) || !bytes.Equal(fingerprint, issue.Grants[0].ProofFingerprint[:]) {
					t.Fatal("stored native subject/provenance changed", e)
				}
				var target *string
				if e := pool.Raw().QueryRow(ctx, `SELECT verification_identifier_id FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID).Scan(&target); e != nil || issuerConfig.RetainEmailVerificationTargets && (target == nil || *target != string(intent.Identifier.ID)) || !issuerConfig.RetainEmailVerificationTargets && target != nil {
					t.Fatal("native issuance target was invented or lost", e)
				}
				if mode == "origin-read" {
					reader := any(issuer).(registrationOriginReader)
					validator, ok := any(issuer).(registrationProofValidator)
					if !ok {
						t.Fatal("scanner-safe registration proof validation is missing")
					}
					for n := 0; n < 2; n++ {
						g, command, version, e := validator.ValidateRegistrationProof(ctx, pool, originProof)
						if e != nil || command != id || version != 1 || g.EnvelopeDigest() != issue.Grants[0].ProofFingerprint {
							t.Fatal("issued proof was not validated without reservation", e)
						}
					}
					for n := 0; n < 2; n++ {
						grant, commandID, version, readErr := reader.ReadRegistrationOrigin(ctx, pool, originProof)
						if readErr != nil || commandID != id || version != 1 || grant.EnvelopeDigest() != issue.Grants[0].ProofFingerprint || grant.Payload().Subject != string(uid) {
							t.Fatal("original registration provenance read failed", readErr)
						}
					}
					rotatedConfig := issuerConfig
					rotatedConfig.CurrentReplayKeyVersion = 3
					rotatedConfig.RetainedReplayKeys = map[uint32][32]byte{1: {1}, 3: {3}}
					rotated, e := identitycapability.NewIssuer(rotatedConfig)
					if e != nil {
						t.Fatal(e)
					}
					if grant, commandID, version, e := rotated.ReadRegistrationOrigin(ctx, pool, originProof); e != nil || commandID != id || version != 1 || grant.EnvelopeDigest() != issue.Grants[0].ProofFingerprint {
						t.Fatal("rotation replaced original provenance", e)
					}
					rotatedConfig.RetainedReplayKeys = map[uint32][32]byte{3: {3}}
					missingKey, e := identitycapability.NewIssuer(rotatedConfig)
					if e != nil {
						t.Fatal(e)
					}
					grant, commandID, version, readErr := missingKey.ReadRegistrationOrigin(ctx, pool, originProof)
					var unavailable identity.UnavailableError
					if !errors.As(readErr, &unavailable) || grant.EnvelopeDigest() != ([32]byte{}) || commandID != "" || version != 0 {
						t.Fatal("missing retained key did not fail closed")
					}
					rotatedConfig.RetainedReplayKeys = map[uint32][32]byte{1: {9}, 3: {3}}
					wrongKey, e := identitycapability.NewIssuer(rotatedConfig)
					if e != nil {
						t.Fatal(e)
					}
					grant, commandID, version, readErr = wrongKey.ReadRegistrationOrigin(ctx, pool, originProof)
					var forbidden identity.ForbiddenError
					if !errors.As(readErr, &forbidden) || grant.EnvelopeDigest() != ([32]byte{}) || commandID != "" || version != 0 {
						t.Fatal("mismatched retained key exposed provenance")
					}
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					grant, commandID, version, readErr = reader.ReadRegistrationOrigin(cancelled, pool, originProof)
					if readErr == nil || grant.EnvelopeDigest() != ([32]byte{}) || commandID != "" || version != 0 {
						t.Fatal("cancelled read exposed provenance")
					}
					grant, commandID, version, readErr = reader.ReadRegistrationOrigin(ctx, pool, capability.Proof{})
					if !errors.As(readErr, &forbidden) || grant.EnvelopeDigest() != ([32]byte{}) || commandID != "" || version != 0 {
						t.Fatal("empty proof exposed provenance")
					}
					for _, column := range []string{"payload_digest", "replay_digest", "proof_fingerprint"} {
						t.Run("mismatched-"+column, func(t *testing.T) {
							var original []byte
							if e := pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID).Scan(&original); e != nil {
								t.Fatal(e)
							}
							defer func() {
								if _, e := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET `+column+`=$1 WHERE capability_id=$2`, original, issue.Grants[0].CapabilityID); e != nil {
									t.Error("original fixture restoration failed")
								}
							}()
							if _, e := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET `+column+`=$1 WHERE capability_id=$2`, bytes.Repeat([]byte{9}, 32), issue.Grants[0].CapabilityID); e != nil {
								t.Fatal(e)
							}
							g, command, version, e := reader.ReadRegistrationOrigin(ctx, pool, originProof)
							if !errors.As(e, &forbidden) || g.EnvelopeDigest() != ([32]byte{}) || command != "" || version != 0 {
								t.Fatal("mismatched persisted evidence exposed provenance")
							}
						})
					}
					reads := make(chan bool, 6)
					for n := 0; n < cap(reads); n++ {
						go func() {
							g, command, version, e := reader.ReadRegistrationOrigin(ctx, pool, originProof)
							reads <- e == nil && command == id && version == 1 && g.EnvelopeDigest() == issue.Grants[0].ProofFingerprint
						}()
					}
					for n := 0; n < cap(reads); n++ {
						if !<-reads {
							t.Error("concurrent original provenance read failed")
						}
					}
					var state string
					var uses int
					if e := pool.Raw().QueryRow(ctx, `SELECT state,uses FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID).Scan(&state, &uses); e != nil || state != "issued" || uses != 0 {
						t.Fatal("origin read consumed or reserved proof", e)
					}
					for _, state := range []string{"reserved", "finalized", "released", "expired", "revoked"} {
						t.Run("validate-"+state, func(t *testing.T) {
							defer func() {
								if _, e := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state='issued',uses=0,command_id=NULL,command_fingerprint=NULL,generation=NULL WHERE capability_id=$1`, issue.Grants[0].CapabilityID); e != nil {
									t.Error("fixture state restoration failed")
								}
							}()
							uses := 0
							if state == "finalized" {
								uses = 1
							}
							if _, e := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state=$2,uses=$3,command_id=$4,command_fingerprint=$5,generation=1 WHERE capability_id=$1`, issue.Grants[0].CapabilityID, state, uses, string(id), bytes.Repeat([]byte{8}, 32)); e != nil {
								t.Fatal(e)
							}
							g, command, version, e := validator.ValidateRegistrationProof(ctx, pool, originProof)
							var denied identity.ForbiddenError
							if !errors.As(e, &denied) || g.EnvelopeDigest() != ([32]byte{}) || command != "" || version != 0 {
								t.Fatal("nonissued proof became usable validation", e)
							}
							if g, command, version, e := reader.ReadRegistrationOrigin(ctx, pool, originProof); e != nil || command != id || version != 1 || g.EnvelopeDigest() != issue.Grants[0].ProofFingerprint {
								t.Fatal("validation policy erased historical provenance", e)
							}
						})
					}
				}
				_, replay, e := c.ReserveCommand(ctx, b, cmd, plan)
				if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Binding != b {
					t.Fatal("anonymous original replay", e)
				}
				changed := plan
				changedIssue := issue
				changedIssue.RegistrationUserID = "different-user"
				changed.CapabilityIssuance = &changedIssue
				changed, e = c.PrepareCommandPlan(b, cmd, changed)
				if e != nil {
					t.Fatal(e)
				}
				_, conflict, e := c.ReserveCommand(ctx, b, cmd, changed)
				var ce identity.ConflictError
				if !errors.As(e, &ce) || conflict.Outcome != identity.CommitOutcomeConflict {
					t.Fatal("changed target reused original", e)
				}
				if sending != nil {
					sending.process(t, ctx, pool, b, *deliveryPlan, keys)
				}
			} else if err == nil {
				t.Fatal("unsafe registration issuance committed")
			}
			if fault != nil || strings.HasPrefix(mode, "recovery-") {
				if fault != nil && (err == nil || !fault.hit.Load() || result.Outcome != identity.CommitOutcomeUnknown) {
					t.Fatal("commit fault did not expose ambiguity", err)
				}
				key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				// Partial primary evidence must not reconstruct a committed
				// receipt. This is distinct from terminal journal recovery.
				if strings.HasPrefix(mode, "recovery-") {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='pending',result_version=NULL,terminal_class=NULL,result=NULL,terminal_at=NULL,lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
						t.Fatal(e)
					}
					if mode == "recovery-missing" {
						if _, e := pool.Raw().Exec(ctx, `DELETE FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID); e != nil {
							t.Fatal(e)
						}
					}
					if mode == "recovery-conflict" {
						if _, e := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET subject_id='different-user' WHERE capability_id=$1`, issue.Grants[0].CapabilityID); e != nil {
							t.Fatal(e)
						}
					}
				} else if mode == "disconnect-before" {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
						t.Fatal(e)
					}
				}
				query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
				caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
				recovered, e := c.RecoverCommand(ctx, query, caller)
				if mode == "disconnect-after" {
					if e != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != b {
						t.Fatal("original anonymous committed recovery failed", recovered.Outcome, e)
					}
				} else if recovered.Outcome != identity.CommitOutcomeInProgress || e == nil {
					t.Fatal("unproved issuer evidence fabricated outcome", recovered.Outcome, e)
				}
				if mode == "recovery-missing" || mode == "recovery-conflict" {
					return
				}
			}
			var users, issued, identifiers, credentials, bindings int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$3),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND NOT verified),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(uid), string(id)).Scan(&users, &issued, &identifiers, &credentials, &bindings); e != nil || users != want || issued != want || identifiers != want || credentials != want || bindings != want {
				t.Fatal("native registration issuance was not atomic", e)
			}
			commandBytes, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			// This success/late-persistence-failure pair checks restored effects.
			// Existing admission-denial variants intentionally retain failure audit;
			// that is not a rolled-back success effect and must not be suppressed.
			if strings.HasPrefix(mode, "restored-") {
				var audits, outbox int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE tenant_id=$1 AND command_id=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2)`, string(b.TenantID), commandBytes).Scan(&audits, &outbox); e != nil || audits != want || outbox != want {
					t.Fatal("restored registration audit/outbox not atomic", e)
				}
			}
			if sending != nil {
				var deliveries int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), commandBytes).Scan(&deliveries); e != nil || deliveries != want {
					t.Fatal("registration delivery not atomic", e)
				}
				if want == 0 {
					sending.process(t, ctx, pool, b, *deliveryPlan, keys, true)
				}
			}
		})
	}
}

// Local compile-time-independent consumer seam makes missing native behavior
// fail at runtime before adding the owned public method. This is provenance
// lookup coverage, not the complete email Validate/Confirm journey.
type registrationOriginReader interface {
	ReadRegistrationOrigin(context.Context, *database.Pool, capability.Proof) (capability.Grant, identity.CommandID, uint32, error)
}

type registrationProofValidator interface {
	ValidateRegistrationProof(context.Context, *database.Pool, capability.Proof) (capability.Grant, identity.CommandID, uint32, error)
}
