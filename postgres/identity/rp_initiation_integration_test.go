//go:build integration

package identitycapability_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This is a producer/transaction contract, not social authentication. Session,
// preauth and RP admission remain explicit fixture seams. Actual signing,
// encrypted output, journal, issuance, audit and outbox use their public owners.
type rpInitiationConsumer struct {
	pool        *database.Pool
	issuer      *identitycapability.Issuer
	codec       *identitycapability.IssuancePreparationCodec
	command     identity.Command
	declaration kernel.CommandPlan
	now         time.Time
	denyCommit  bool
	loseOutput  bool
	generated   atomic.Int64
	staged      atomic.Int64
	restoreOnce atomic.Bool
}

// The outer wire contains only metadata and the actual issuer's encrypted
// checkpoint. Its plan is authenticated by the checkpoint's original AAD.
type rpInitiationOutput struct {
	Checkpoint                 []byte
	ID, Purpose                string
	ReplayVersion, MaximumUses uint32
	Replay, Envelope           [32]byte
	ExpiresAt                  time.Time
}

func (o rpInitiationOutput) plan(d kernel.ContributorDescriptor) kernel.CapabilityIssuancePlan {
	return kernel.CapabilityIssuancePlan{Contributor: d, Grants: []kernel.CapabilityPlan{{CapabilityID: o.ID, Purpose: capability.Purpose(o.Purpose), ReplayKeyVersion: o.ReplayVersion, MaxUses: o.MaximumUses, ReplayDigest: o.Replay, ProofFingerprint: o.Envelope, ExpiresAt: o.ExpiresAt}}}
}

func (*rpInitiationConsumer) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}
}
func (p *rpInitiationConsumer) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *rpInitiationConsumer) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *rpInitiationConsumer) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *rpInitiationConsumer) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	_, _, _, err := w.FeatureScope(p)
	if err != nil {
		return err
	}
	return ctx.Err()
}
func (p *rpInitiationConsumer) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.command || generation == 0 {
		return nil, identity.InvalidInputError{}
	}
	s, _ := c.Feature()
	id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
	var marker string
	// A separate connection must see the acknowledged marker before signing.
	if err := p.pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&marker); err != nil || marker != strconv.FormatUint(generation, 10) {
		return nil, identity.ForbiddenError{}
	}
	p.generated.Add(1)
	subject := string(s.Binding.UserID)
	if subject == "" {
		subject = s.Binding.AnonymousFlowID
	}
	prepared, err := p.issuer.Prepare(ctx, s.Binding, []capability.Payload{{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: subject, Tenant: string(s.Binding.TenantID), Resource: s.Binding.RecordID, Operation: "identity.oauth.callback", IssuedAt: p.now, NotBefore: p.now, ExpiresAt: p.now.Add(10 * time.Minute), MaxUses: 1}})
	if err != nil {
		return nil, err
	}
	plan, err := prepared.Plan()
	if err != nil {
		return nil, err
	}
	checkpoint, err := p.codec.CheckpointPreparation(ctx, prepared, generation, nil)
	if err != nil {
		return nil, err
	}
	if p.loseOutput {
		return nil, identity.UnavailableError{}
	}
	g := plan.Grants[0]
	return json.Marshal(rpInitiationOutput{Checkpoint: checkpoint, ID: g.CapabilityID, Purpose: string(g.Purpose), ReplayVersion: g.ReplayKeyVersion, MaximumUses: g.MaxUses, Replay: g.ReplayDigest, Envelope: g.ProofFingerprint, ExpiresAt: g.ExpiresAt})
}
func (p *rpInitiationConsumer) restore(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identitycapability.PreparedIssuance, kernel.CapabilityIssuancePlan, error) {
	if c != p.command || len(wire) == 0 || len(wire) > 64<<10 {
		return identitycapability.PreparedIssuance{}, kernel.CapabilityIssuancePlan{}, identity.InvalidInputError{}
	}
	var output rpInitiationOutput
	if json.Unmarshal(wire, &output) != nil {
		return identitycapability.PreparedIssuance{}, kernel.CapabilityIssuancePlan{}, identity.InvalidInputError{}
	}
	s, _ := c.Feature()
	plan := output.plan(p.issuer.Descriptor())
	prepared, err := p.codec.RestorePreparation(ctx, s.Binding, generation, plan, output.Checkpoint)
	return prepared, plan, err
}
func (p *rpInitiationConsumer) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p.restoreOnce.CompareAndSwap(true, false) {
		return identity.Command{}, kernel.CommandPlan{}, identity.UnavailableError{}
	}
	_, issuance, err := p.restore(ctx, c, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan := p.declaration
	plan.Contributors = append(append([]kernel.ContributorDescriptor(nil), plan.Contributors...), p.issuer.Descriptor())
	plan.CapabilityIssuance = &issuance
	return c, plan, nil
}
func (p *rpInitiationConsumer) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	prepared, _, err := p.restore(ctx, c, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.rp_initiation_fixture(command_id,transaction_id) VALUES($1,$2)`, string(s.Binding.CommandID), s.Binding.RecordID); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.issuer.Stage(ctx, w, prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.staged.Add(1)
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}
func (p *rpInitiationConsumer) CheckFeatureCommit(ctx context.Context, w kernel.Work, _ identity.Command) error {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if p.denyCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (*rpInitiationConsumer) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM public.rp_initiation_fixture WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var present bool
	if !rows.Next() || rows.Scan(&present) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if present {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

func testNativeRPInitiation(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.rp_initiation_fixture(command_id text PRIMARY KEY,transaction_id text UNIQUE NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"link", "signin", "link-denied", "signin-denied", "unknown-generation", "retained-restart"} {
		t.Run(mode, func(t *testing.T) {
			anonymous := mode == "signin" || mode == "signin-denied"
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "original-user", ActorID: "original-user", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "rp-policy", PolicyVersion: 1, CorrelationID: string(id), RecordID: string(id)}
			if anonymous {
				op.OperationID, op.SchemaID, op.SubjectRequirement = "identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1", identity.FeatureSubjectAnonymousFlow
				b.OperationID, b.SchemaID, b.UserID, b.AnonymousFlowID, b.ActorID, b.ActorKind = op.OperationID, op.SchemaID, "", string(id), "oauth-service", authorization.SubjectServiceAccount
			}
			cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			key := bytes.Repeat([]byte{0x52}, 32)
			signer, _ := capability.NewHMACSHA256Signer("rp-v1", key)
			verifier, _ := capability.NewHMACSHA256Verifier(key)
			keys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "rp-v1", Verifier: verifier}})
			issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			codec, err := identitycapability.NewIssuancePreparationCodec(issuer, identitycapability.IssuancePreparationConfig{Deployment: "rp-fixture", ActiveEnvelopeKey: "envelope-v1", EnvelopeKeys: map[string][]byte{"envelope-v1": bytes.Repeat([]byte{0x62}, 32)}, VerificationKeys: []identitycapability.PreparationVerificationKey{{ID: "rp-v1", HMAC: key}}, Clock: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			owner := &rpInitiationConsumer{pool: pool, issuer: issuer, codec: codec, command: cmd, now: now, denyCommit: mode == "link-denied" || mode == "signin-denied"}
			owner.loseOutput = mode == "unknown-generation"
			owner.restoreOnce.Store(mode == "retained-restart")
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, owner, issuer})
			if err != nil {
				t.Fatal(err)
			}
			policy, err := authorization.NewDecisionService(testPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: policy}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
			actor := audit.ActorHuman
			if anonymous {
				actor = audit.ActorService
			}
			record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "oauth_transaction", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "protected", "aggregate.type": "oauth_transaction", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"}})
			if err != nil {
				t.Fatal(err)
			}
			redactor, _ := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
			record, err = redactor.Redact(ctx, record)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "oauth_transaction", record)
			if err != nil {
				t.Fatal(err)
			}
			declaration := kernel.CommandPlan{Contributors: registry.Descriptors()[:4], Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, SubjectType: "oauth_transaction", Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}}
			owner.declaration, err = coordinator.PrepareFeaturePreparationPlan(cmd, declaration)
			if err != nil {
				t.Fatal("original RP declaration denied", err)
			}
			result, executionErr := coordinator.ExecutePreparedFeature(ctx, cmd, owner.declaration)
			encodedID, _ := base64.RawURLEncoding.DecodeString(string(id))
			if owner.loseOutput || mode == "retained-restart" {
				var state string
				var retained bool
				if executionErr == nil || pool.Raw().QueryRow(ctx, `SELECT state,preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1`, encodedID).Scan(&state, &retained) != nil || state != "pending" || retained != (mode == "retained-restart") || owner.generated.Load() != 1 || owner.staged.Load() != 0 {
					t.Fatal("uncertain RP generation lost original pending custody")
				}
				if retained {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, encodedID); err == nil {
						t.Fatal("pending retained RP output could be erased")
					}
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, encodedID); err != nil {
					t.Fatal(err)
				}
				result, executionErr = coordinator.ExecutePreparedFeature(ctx, cmd, owner.declaration)
				if owner.loseOutput {
					if executionErr != nil || result.Outcome != identity.CommitOutcomeInProgress || owner.generated.Load() != 1 || owner.staged.Load() != 0 {
						t.Fatal("uncertain RP start regenerated after abandoned lease")
					}
					return
				}
			}
			var rows, grants, audits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.rp_initiation_fixture WHERE command_id=$1),(SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$2)`, string(id), encodedID).Scan(&rows, &grants, &audits, &events); err != nil {
				t.Fatal(err)
			}
			var retainedSecret, generationPresent bool
			if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NOT NULL OR preparation_ciphertext_generation IS NOT NULL,preparation_started_generation IS NOT NULL FROM identity.commands WHERE command_id=$1`, encodedID).Scan(&retainedSecret, &generationPresent); err != nil || retainedSecret || !generationPresent {
				t.Fatal("terminal RP start retained a second recoverable secret copy")
			}
			if owner.denyCommit {
				// The coordinator retains its terminal denial audit separately;
				// domain, grant and lifecycle effects must all roll back.
				if executionErr == nil || rows != 0 || grants != 0 || audits != 1 || events != 0 || owner.generated.Load() != 1 || owner.staged.Load() != 1 {
					t.Fatalf("late RP denial mismatch: rows=%d grants=%d audits=%d events=%d generated=%d staged=%d", rows, grants, audits, events, owner.generated.Load(), owner.staged.Load())
				}
				return
			}
			if executionErr != nil || result.Outcome != identity.CommitOutcomeCommitted || rows != 1 || grants != 1 || audits != 1 || events != 1 || owner.generated.Load() != 1 || owner.staged.Load() != 1 {
				t.Fatal("RP creation and original state issuance did not commit together", executionErr)
			}
			var subject, purpose string
			var issuedAt, expiresAt time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT subject_id,purpose,signed_issued_at,expires_at FROM public.capability_identity_one_use WHERE origin_command_id=$1`, string(id)).Scan(&subject, &purpose, &issuedAt, &expiresAt); err != nil {
				t.Fatal(err)
			}
			want := string(b.UserID)
			if anonymous {
				want = b.AnonymousFlowID
			}
			if subject != want || purpose != "identity.oauth.callback" || !issuedAt.Equal(now) || !expiresAt.Equal(now.Add(10*time.Minute)) {
				t.Fatal("RP state changed original subject, purpose or deadline")
			}
			replay, err := coordinator.ExecutePreparedFeature(ctx, cmd, owner.declaration)
			if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || owner.generated.Load() != 1 || owner.staged.Load() != 1 {
				t.Fatal("terminal RP replay generated another state", err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, encodedID, []byte{1}); err == nil {
				t.Fatal("terminal RP journal secret was resurrected")
			}
		})
	}
}
