//go:build integration

package identitycapability_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// The continuation/factor owner and prior primary issuance are fixture seams.
// Child signing/issuance, parent reservation/use, audit/outbox and journal
// recovery use real owners. This is not a public MFA authentication journey.
type mfaIssuerPhase struct {
	command    identity.Command
	primary    identitypostgres.CapabilityPlan
	challenge  identitypostgres.MFAContinuationPlan
	issuer     *identitycapability.Issuer
	prepared   identitycapability.PreparedIssuance
	denyCommit bool
	finalPlan  identitypostgres.CommandPlan
	checkpoint string
}

func (*mfaIssuerPhase) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}
func (p *mfaIssuerPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *mfaIssuerPhase) ValidateFeatureCommand(c identity.Command, _ identitypostgres.CommandPlan) error {
	if c != p.command {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *mfaIssuerPhase) ValidateMagicLinkConsumption(c identity.Command, proof identitypostgres.CapabilityPlan) error {
	if c != p.command || proof != p.primary {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *mfaIssuerPhase) ValidateMagicLinkMFAChallenge(c identity.Command, scope identitypostgres.MFAContinuationPlan) error {
	if c != p.command || scope != p.challenge {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *mfaIssuerPhase) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.checkpoint = "apply"
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	m, err := w.MagicLinkMFAChallenge(p)
	if err != nil || m != p.challenge {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	if _, err = w.Exec(ctx, `INSERT INTO public.issuer_mfa_continuations(command_id,continuation_id,scope_digest) VALUES($1,$2,$3)`, string(s.Binding.CommandID), string(m.ID), m.ScopeDigest[:]); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.issuer.Stage(ctx, w, p.prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.checkpoint = "staged"
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (p *mfaIssuerPhase) CheckFeatureCommit(ctx context.Context, w identitypostgres.Work, c identity.Command) error {
	p.checkpoint = "commit-check"
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if c != p.command || p.denyCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (*mfaIssuerPhase) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM public.issuer_mfa_continuations WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	defer rows.Close()
	var present bool
	if !rows.Next() || rows.Scan(&present) != nil || rows.Next() || rows.Err() != nil {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if present {
		return identitypostgres.RecoveryCommitted, nil
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

// This fixture supplies original retained admission, not real risk/factor
// authority. It cannot be used as a production authentication adapter.
func (p *mfaIssuerPhase) ValidateFeaturePreparation(c identity.Command, plan identitypostgres.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (*mfaIssuerPhase) AdmitFeaturePreparation(ctx context.Context, _ identitypostgres.Work, _ identity.Command) error {
	return ctx.Err()
}
func (p *mfaIssuerPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.checkpoint = "generate"
	if c != p.command || generation == 0 {
		return nil, identity.InvalidInputError{}
	}
	s, _ := c.Feature()
	return []byte(string(s.Binding.CommandID) + ":" + strconv.FormatUint(generation, 10)), ctx.Err()
}
func (p *mfaIssuerPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, identitypostgres.CommandPlan, error) {
	expected, err := p.GenerateFeaturePreparation(ctx, c, generation)
	if err != nil || string(expected) != string(wire) {
		return identity.Command{}, identitypostgres.CommandPlan{}, identity.InvalidInputError{}
	}
	p.checkpoint = "restore"
	return c, p.finalPlan, nil
}
func (p *mfaIssuerPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (identitypostgres.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, identity.InvalidInputError{}
	}
	return mfaIssuerAdmission{p}, ctx.Err()
}
func (p *mfaIssuerPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identitypostgres.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return mfaIssuerAdmission{p}, nil
}

type mfaIssuerAdmission struct{ phase *mfaIssuerPhase }

func (a mfaIssuerAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a mfaIssuerAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.phase.GenerateFeaturePreparation(ctx, a.phase.command, generation)
}

func testMFAIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.issuer_mfa_continuations(command_id text PRIMARY KEY,continuation_id text UNIQUE NOT NULL,scope_digest bytea NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "late-denial", "recovery-absent", "recovery-identity", "recovery-replay", "recovery-origin"} {
		t.Run(mode, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			childID, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			requestID, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: string(id), ActorID: "mfa-actor", ActorKind: authorization.SubjectUser, OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, PolicyID: "test-policy", PolicyVersion: 1, CorrelationID: "mfa-correlation"}
			op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
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
			issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			parent := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: "mfa-user", Tenant: "tenant-a", ID: "parent-" + string(id), Resource: "identity.magiclink/email-id", Operation: b.OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(10 * time.Minute), MaxUses: 1, Caveats: map[string]string{"magiclink.identifier": "email-id"}}
			parent.CorrelationID = string(requestID)
			token, err := capability.Issue(ctx, parent, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := capability.ParseProof(token, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			grant, err := capability.Verify(ctx, token, keys, capability.VerifyOptions{Issuer: "https://identity.example.test", Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			primary, err := issuer.PrepareMagicLinkConsumption(ctx, b, "mfa-user", "email-id", proof, grant.EnvelopeDigest(), 1)
			if err != nil {
				t.Fatal(err)
			}
			// Seed the prior primary issuance only; child issuance below must be native.
			parentCanonical, err := capability.CanonicalPayload(parent, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			parentDigest := sha256.Sum256(parentCanonical)
			clear(parentCanonical)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$6,1,$9,$10,$10,'signing-v1',$11,$10)`, string(b.TenantID), string(primary.Purpose), int64(primary.ReplayKeyVersion), primary.ReplayDigest[:], primary.CapabilityID, primary.ProofFingerprint[:], primary.ExpiresAt, string(requestID), parent.Subject, now, parentDigest[:]); err != nil {
				t.Fatal(err)
			}
			m := identitypostgres.MFAContinuationPlan{ID: childID, UserID: "mfa-user", ScopeDigest: [32]byte{7}, PolicyVersion: 1, FactorVersion: 2, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			payload := capability.Payload{Version: 1, Issuer: parent.Issuer, Audiences: []string{"identity"}, Subject: string(m.UserID), Tenant: string(b.TenantID), ID: string(m.ID), Resource: "mfa/continuations/" + string(m.ID), Operation: "identity.mfa.complete", IssuedAt: now, NotBefore: now, ExpiresAt: m.ExpiresAt, MaxUses: 1, Caveats: map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": hex.EncodeToString(m.ScopeDigest[:])}}
			prepared, err := issuer.PrepareMFAContinuation(ctx, b, payload)
			if err != nil {
				t.Fatal(err)
			}
			issue, err := prepared.Plan()
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: primary.CapabilityID}}}})
			if err != nil {
				t.Fatal(err)
			}
			phase := &mfaIssuerPhase{command: cmd, primary: primary, challenge: m, issuer: issuer, prepared: prepared, denyCommit: mode == "late-denial"}
			participant := identitycapability.NewParticipant()
			registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, auditing, lifecycle, phase, participant, issuer})
			if err != nil {
				t.Fatal(err)
			}
			policy, err := authorization.NewDecisionService(testPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: policy}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
			if err != nil {
				t.Fatal(err)
			}
			record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "protected", "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0"}})
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
			digest, err := identitypostgres.FeatureAuditBindingDigest(b, op, "authentication_attempt", record)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Feature: &identitypostgres.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "authentication_attempt", Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "mfa.challenge.created.v1"}, Capability: &primary, MFAContinuation: &m, CapabilityIssuance: &issue})
			if err != nil {
				t.Fatal("prepare challenge", err)
			}
			phase.finalPlan = plan
			query := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
			if strings.HasPrefix(mode, "recovery-") {
				if _, _, err := c.ReserveCommand(ctx, b, cmd, plan); err != nil {
					t.Fatal("reserve challenge", err)
				}
				child := issue.Grants[0]
				if mode != "recovery-absent" {
					capID, replay, origin := "conflicting-"+string(id), sha256.Sum256([]byte("conflicting-"+string(id))), ""
					if mode == "recovery-identity" {
						capID = child.CapabilityID
					}
					if mode == "recovery-replay" {
						replay = child.ReplayDigest
					}
					if mode == "recovery-origin" {
						origin = string(id)
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6::bytea,$7,1,NULLIF($8::text,''),CASE WHEN $8='' THEN NULL ELSE $6::bytea END,CASE WHEN $8='' THEN NULL ELSE 1 END,CASE WHEN $8='' THEN NULL ELSE 'conflicting-user' END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END,CASE WHEN $8='' THEN NULL ELSE 'signing-v1' END,CASE WHEN $8='' THEN NULL ELSE $6::bytea END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END)`, string(b.TenantID), string(child.Purpose), int64(child.ReplayKeyVersion), replay[:], capID, child.ProofFingerprint[:], child.ExpiresAt, origin, now); err != nil {
						t.Fatal(err)
					}
				}
				key, _ := base64.RawURLEncoding.DecodeString(string(id))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
					t.Fatal(err)
				}
				recovered, recoveryErr := c.RecoverFeatureCommand(ctx, query, caller)
				if mode == "recovery-absent" {
					if recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Binding != b {
						t.Fatal("original absent producer did not prove rollback", recovered.Outcome, recoveryErr)
					}
				} else if recoveryErr == nil || recovered.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("conflicting child fabricated noncommit", recovered.Outcome, recoveryErr)
				}
				return
			}
			original := plan
			original.CapabilityIssuance = nil
			original.Contributors = plan.Contributors[:len(plan.Contributors)-1]
			original, err = c.PrepareFeaturePreparationPlan(cmd, original)
			if err != nil {
				t.Fatal("prepare original challenge", err)
			}
			result, err := c.ExecutePreparedFeature(ctx, cmd, original)
			var children, continuations int
			var uses int32
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),(SELECT count(*) FROM public.issuer_mfa_continuations WHERE command_id=$1),(SELECT uses FROM public.capability_identity_one_use WHERE capability_id=$2)`, string(id), primary.CapabilityID).Scan(&children, &continuations, &uses); e != nil {
				t.Fatal(e)
			}
			if mode == "late-denial" {
				if err == nil || children != 0 || continuations != 0 || uses != 0 {
					t.Fatal("late denial retained issuance or primary use", err)
				}
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || children != 1 || continuations != 1 || uses != 1 {
				t.Fatal("split native MFA issuance", phase.checkpoint, err)
			}
			var subject, capabilityID, origin string
			var issuedAt, expiresAt time.Time
			var fingerprint, replayDigest, payloadDigest []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT subject_id,capability_id,origin_command_id,signed_issued_at,expires_at,proof_fingerprint,replay_digest,payload_digest FROM public.capability_identity_one_use WHERE origin_command_id=$1`, string(id)).Scan(&subject, &capabilityID, &origin, &issuedAt, &expiresAt, &fingerprint, &replayDigest, &payloadDigest); err != nil {
				t.Fatal(err)
			}
			child := issue.Grants[0]
			canonical, err := capability.CanonicalPayload(payload, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			expectedPayloadDigest := sha256.Sum256(canonical)
			clear(canonical)
			if subject != string(m.UserID) || capabilityID != string(m.ID) || origin != string(id) || !issuedAt.Equal(m.IssuedAt) || !expiresAt.Equal(m.ExpiresAt) || string(fingerprint) != string(child.ProofFingerprint[:]) || string(replayDigest) != string(child.ReplayDigest[:]) || string(payloadDigest) != string(expectedPayloadDigest[:]) {
				t.Fatal("durable child metadata diverged from original signed issuance")
			}
			recovered, err := c.RecoverFeatureCommand(ctx, query, caller)
			if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != b {
				t.Fatal("durable child receipt lost", err)
			}
			t.Run("consumed parent provenance", func(t *testing.T) {
				testMFAMagicLinkParent(t, ctx, pool, issuer, prepared, parent, primary, requestID, id)
			})
		})
	}
}
