//go:build integration

package identitycapability_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Only the native feature seam is supplied by this fixture. Signing, primary
// fences, issuance, encrypted delivery, audit and lifecycle use real owners.
// This is not recovery-factor policy or complete password-reset orchestration.
type resetIssuerPhase struct {
	prospective  *identitypostgres.MagicLinkRegistrationIntent
	creation     *identitypostgres.MagicLinkRegistrationDomain
	command      identity.Command
	recipient    identitypostgres.RecipientRecord
	credential   identitypostgres.CredentialAdmission
	issuer       *identitycapability.Issuer
	prepared     identitycapability.PreparedIssuance
	delivery     *deliverypostgres.Contributor
	sealed       deliverypostgres.PreparedDelivery
	skip         bool
	magicLink    bool
	supersession identitycapability.MagicLinkSupersessionScope
	recoveryOnly bool
}

func (p *resetIssuerPhase) Descriptor() identitypostgres.ContributorDescriptor {
	if p.magicLink {
		return identitypostgres.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
	}
	return identitypostgres.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *resetIssuerPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *resetIssuerPhase) ValidateFeatureCommand(c identity.Command, _ identitypostgres.CommandPlan) error {
	if c != p.command {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *resetIssuerPhase) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.supersession.Digest() != ([32]byte{}) {
		if err := identitycapability.LockMagicLinkSupersession(ctx, w, p, p.supersession); err != nil {
			return identity.FeatureReceipt{}, fmt.Errorf("supersession fence: %w", err)
		}
	}
	if !p.skip {
		var err error
		if p.prospective != nil {
			err = p.creation.RequireProspectiveRecipient(ctx, w, p, c, *p.prospective)
		} else if p.magicLink {
			err = w.RequireMagicLinkRecipient(ctx, p, p.recipient)
		} else {
			_, err = w.RequireRecipientCredential(ctx, p, p.recipient, p.credential)
		}
		if err != nil {
			return identity.FeatureReceipt{}, fmt.Errorf("recipient fence: %w", err)
		}
	}
	if err := p.issuer.Stage(ctx, w, p.prepared); err != nil {
		return identity.FeatureReceipt{}, fmt.Errorf("issuer stage: %w", err)
	}
	if err := p.delivery.Stage(ctx, w, p.sealed); err != nil {
		return identity.FeatureReceipt{}, fmt.Errorf("delivery stage: %w", err)
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (p *resetIssuerPhase) RecoverParticipant(context.Context, identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	// These cases reserve but never execute this effect-free feature seam.
	// Real issuer, delivery, audit and lifecycle owners vote independently.
	if p.recoveryOnly {
		return identitypostgres.RecoveryNotCommitted, nil
	}
	return identitypostgres.RecoveryUnknown, nil
}

func testResetRecipientIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	testRecipientIssuance(t, ctx, pool, repo, auditing, lifecycle, false)
}

func testMagicLinkRecipientIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	testRecipientIssuance(t, ctx, pool, repo, auditing, lifecycle, true)
}

func testRecipientIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, magicLink bool) {
	modes := []string{"commit", "restored", "missing-fence", "wrong-origin", "late-failure"}
	if magicLink {
		modes = append(modes, "supersession", "recovery-absent", "recovery-grant", "recovery-replay", "recovery-origin")
		modes = append(modes, "prospective-commit", "prospective-restored", "prospective-supersession", "prospective-missing-fence", "prospective-wrong-origin", "prospective-late-failure")
		history, err := (identitypostgres.IdentifierMutationMigrationSource{Base: identitypostgres.MigrationSource{}, Version: 64}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var installed bool
		if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.identifier_retirements') IS NOT NULL`).Scan(&installed); err != nil {
			t.Fatal(err)
		}
		if !installed {
			if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			prospective := strings.HasPrefix(mode, "prospective-")
			mode = strings.TrimPrefix(mode, "prospective-")
			uid, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			if !prospective {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant-a',$1,'active',101,2,3,4)`, string(uid)); err != nil {
					t.Fatal("seed existing recipient", err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('tenant-a',$1,$1,'email',$2,true,true,7,2,1,clock_timestamp())`, string(uid), string(uid)+"@example.test"); err != nil {
					t.Fatal(err)
				}
				if !magicLink {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a',$1,'password',1,'identity/password',5,true)`, string(uid)); err != nil {
						t.Fatal(err)
					}
				}
			}
			r, err := repo.ResolveRecipient(ctx, identitypostgres.RecipientQuery{TenantID: "tenant-a", Kind: identity.IdentifierEmail, CanonicalValue: string(uid) + "@example.test", Eligibility: identitypostgres.RecipientVerified})
			if err != nil || r.Suppressed != prospective {
				t.Fatal("recipient", err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: string(id), ActorID: "reset-actor", ActorKind: authorization.SubjectUser, OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, PolicyID: "test-policy", PolicyVersion: 1, CorrelationID: "reset-correlation"}
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			if magicLink {
				b.OperationID, b.SchemaID = "identity.magic-link.request", "magic-link-request"
				op.Owner, op.OperationID, op.SchemaID = "identity/magiclink", b.OperationID, b.SchemaID
			}
			cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "selected-original-reset"}}}})
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
			limits := capability.DefaultLimits()
			if prospective {
				limits.MaxCaveats = 18
			}
			issuerConfig := identitycapability.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: limits}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second}
			issuer, err := identitycapability.NewIssuer(issuerConfig)
			if err != nil {
				t.Fatal(err)
			}
			payload := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: string(uid), Tenant: "tenant-a", Resource: "identity.password/password", Operation: "identity.password.reset-complete", CorrelationID: string(id), IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), MaxUses: 1, Caveats: map[string]string{"password.identifier": string(uid), "password.identifier-version": "7", "password.credential-version": "5", "password.credential-authority-version": "4", "password.user-authority-version": "2"}}
			if magicLink {
				payload.Resource, payload.Operation = "identity.magiclink/"+string(r.Identifier.ID), "identity.magic-link.consume"
				payload.Caveats = map[string]string{"magiclink.identifier": string(r.Identifier.ID), "magiclink.identifier-version": "7", "magiclink.verification-version": "1", "magiclink.identifier-authority-version": "3", "magiclink.user-authority-version": "2", "magiclink.credential-authority-version": "4", "magiclink.canonical-email": r.Query.CanonicalValue}
			}
			var creation *identitypostgres.MagicLinkRegistrationDomain
			var intent *identitypostgres.MagicLinkRegistrationIntent
			if prospective {
				creation, err = identitypostgres.NewMagicLinkRegistrationDomain(repo, identitypostgres.MagicLinkRegistrationDomainConfig{ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
				if err != nil {
					t.Fatal(err)
				}
				cb := b
				cb.OperationID, cb.AnonymousFlowID, cb.UserID, cb.SchemaID = "identity.user.create", "", identity.UserID(uid), "prospective-user"
				intent = &identitypostgres.MagicLinkRegistrationIntent{Creation: identity.CreateUserCommand{Binding: cb, Status: identity.StatusActive}, Identifier: identity.Identifier{ID: identity.IdentifierID(uid), UserID: identity.UserID(uid), Kind: identity.IdentifierEmail, CanonicalValue: r.Query.CanonicalValue, Version: 1}, ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3}
				digest, err := identitypostgres.MagicLinkRegistrationDigest(*intent)
				if err != nil {
					t.Fatal(err)
				}
				payload.Resource = "identity.magiclink/" + string(uid)
				payload.Caveats = map[string]string{"magiclink.identifier": string(uid), "magiclink.canonical-email": r.Query.CanonicalValue, "magiclink.prospective": "1", "magiclink.intent": "signup-if-allowed", "magiclink.creation-digest": fmt.Sprintf("%x", digest), "magiclink.email-policy-version": "3"}
				for _, key := range []string{"magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
					payload.Caveats[key] = "1"
				}
			}
			if mode == "wrong-origin" {
				payload.CorrelationID = "other-command"
			}
			var scope identitycapability.MagicLinkSupersessionScope
			if prospective && mode == "commit" {
				for n := len(payload.Caveats); n < 18; n++ {
					payload.Caveats[fmt.Sprintf("original-flow-%d", n)] = "bound"
				}
			}
			if mode == "supersession" {
				payload.Caveats["magiclink.callback"] = "https://identity.example.test/callback"
				if !prospective {
					payload.Caveats["magiclink.intent"] = "signin-only"
				}
				payload.Caveats["magiclink.flow"] = b.AnonymousFlowID
				payload.Caveats["magiclink.flow-binding"] = strings.Repeat("1", 64)
				payload.Caveats["magiclink.profile"] = strings.Repeat("2", 64)
				scope, err = identitycapability.MagicLinkScopeFromPayload(payload)
				if err != nil {
					t.Fatal(err)
				}
				digest := scope.Digest()
				payload.Caveats["magiclink.supersession"] = fmt.Sprintf("%x", digest)
			}
			var prepared identitycapability.PreparedIssuance
			if prospective {
				prepared, err = issuer.PrepareMagicLinkProspectiveRecipient(ctx, b, identity.UserID(uid), payload)
			} else if magicLink {
				prepared, err = issuer.PrepareMagicLinkRecipient(ctx, b, identity.UserID(uid), payload)
			} else {
				prepared, err = issuer.PrepareResetRecipient(ctx, b, identity.UserID(uid), payload)
			}
			if err != nil {
				t.Fatal("prepare original reset", err)
			}
			issue, _ := prepared.Plan()
			sending := newIssuanceDeliveryFixture(t)
			sending.limits = limits
			var sealed deliverypostgres.PreparedDelivery
			if mode == "restored" {
				codec, err := identitycapability.NewIssuancePreparationCodec(issuer, identitycapability.IssuancePreparationConfig{Deployment: "test", ActiveEnvelopeKey: "issuer-envelope", EnvelopeKeys: map[string][]byte{"issuer-envelope": bytes.Repeat([]byte{8}, 32)}, VerificationKeys: []identitycapability.PreparationVerificationKey{{ID: "signing-v1", HMAC: key}}, Clock: func() time.Time { return now }})
				if err != nil {
					t.Fatal(err)
				}
				sealed = sending.prepare(t, ctx, b, prepared, 1, payload.ExpiresAt, codec)
				prepared, err = codec.RestorePreparation(ctx, b, 1, issue, sending.issuanceCheckpoint)
				if err != nil {
					t.Fatal("restore original issuance", err)
				}
			} else {
				sealed = sending.prepare(t, ctx, b, prepared, 1, payload.ExpiresAt)
			}
			sending.registrationUser = identity.UserID(uid)
			sending.prospectiveRecipient = prospective
			if magicLink && (mode == "commit" || mode == "supersession") {
				sending.inspectDelivered = func(ctx context.Context, wire string) error {
					proof, err := capability.ParseProof(wire, limits)
					if err != nil {
						return err
					}
					defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
					g, origin, key, superseded, err := issuer.ReadMagicLinkOrigin(ctx, pool, proof)
					if err != nil || superseded || origin != id || key != 1 || g.EnvelopeDigest() != issue.Grants[0].ProofFingerprint {
						t.Fatal("original magic origin changed", err)
					}
					if prospective && mode == "commit" {
						if len(g.Payload().Caveats) != 18 {
							t.Fatal("selected profile lost persisted caveats")
						}
						narrowConfig := issuerConfig
						narrowConfig.Crypto.Limits.MaxCaveats = 16
						narrow, err := identitycapability.NewIssuer(narrowConfig)
						if err != nil {
							t.Fatal(err)
						}
						if _, _, _, _, err := narrow.ReadMagicLinkOrigin(ctx, pool, proof); err == nil {
							t.Fatal("narrow policy read wider persisted authority")
						}
					}
					// Legacy unselected rows remain interpretable, but cannot
					// manufacture a supersession decision from another purpose.
					if _, _, _, err := issuer.ValidateIssuedProof(ctx, pool, proof, "identity.magic-link.consume"); err != nil {
						t.Fatal("legacy inspection denied", err)
					}
					if mode == "supersession" {
						next, _ := identity.NewCommandID()
						if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET superseded_by_command_id=$2 WHERE capability_id=$1`, issue.Grants[0].CapabilityID, string(next)); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET superseded_by_command_id=NULL WHERE capability_id=$1`, issue.Grants[0].CapabilityID); err != nil {
								t.Error(err)
							}
						}()
						g, origin, key, superseded, err = issuer.ReadMagicLinkOrigin(ctx, pool, proof)
						if err != nil || !superseded || origin != id || key != 1 || g.EnvelopeDigest() != issue.Grants[0].ProofFingerprint {
							t.Fatal("authenticated supersession lost original custody", err)
						}
						assertIssuanceOriginDenied(t, issuer, ctx, pool, proof, "identity.magic-link.consume", true)
						g, origin, key, err = issuer.ReadIssuanceOrigin(ctx, pool, proof, "identity.magic-link.consume")
						if err != nil || origin != id || key != 1 || g.EnvelopeDigest() != issue.Grants[0].ProofFingerprint {
							t.Fatal("supersession erased historical retry provenance", err)
						}
						foreignOrigin, err := identity.NewCommandID()
						if err != nil {
							return err
						}
						if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET origin_command_id=$2 WHERE capability_id=$1`, issue.Grants[0].CapabilityID, string(foreignOrigin)); err != nil {
							t.Fatal(err)
						}
						g, origin, key, superseded, err = issuer.ReadMagicLinkOrigin(ctx, pool, proof)
						if err == nil || superseded || g.EnvelopeDigest() != ([32]byte{}) || origin != "" || key != 0 {
							t.Fatal("foreign originating command exposed authenticated status")
						}
						if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET origin_command_id=$2 WHERE capability_id=$1`, issue.Grants[0].CapabilityID, string(id)); err != nil {
							t.Fatal(err)
						}
						digest := scope.Digest()
						foreign := digest
						foreign[0]++
						if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET supersession_scope=$2 WHERE capability_id=$1`, issue.Grants[0].CapabilityID, foreign[:]); err != nil {
							t.Fatal(err)
						}
						g, origin, key, superseded, err = issuer.ReadMagicLinkOrigin(ctx, pool, proof)
						if err == nil || superseded || g.EnvelopeDigest() != ([32]byte{}) || origin != "" || key != 0 {
							t.Fatal("foreign journal scope exposed authenticated status")
						}
						if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET supersession_scope=$2 WHERE capability_id=$1`, issue.Grants[0].CapabilityID, digest[:]); err != nil {
							t.Fatal(err)
						}
						cancelled, stop := context.WithCancel(ctx)
						stop()
						g, origin, key, superseded, err = issuer.ReadMagicLinkOrigin(cancelled, pool, proof)
						if err == nil || superseded || g.EnvelopeDigest() != ([32]byte{}) || origin != "" || key != 0 {
							t.Fatal("cancelled status exposed projections")
						}
					}
					return nil
				}
			}
			deliveryPlan, err := sealed.Plan()
			if err != nil {
				t.Fatal(err)
			}
			phase := &resetIssuerPhase{command: cmd, recipient: r, credential: identitypostgres.CredentialAdmission{Credential: identity.CredentialRef{ID: "password", TenantID: "tenant-a", UserID: identity.UserID(uid), Kind: identity.CredentialPassword, Owner: "identity/password", Version: 5}, UserAuthorityVersion: 2, IdentifierAuthorityVersion: 3, CredentialAuthorityVersion: 4}, issuer: issuer, prepared: prepared, delivery: sending.contributor, sealed: sealed, skip: mode == "missing-fence"}
			phase.magicLink = magicLink
			phase.creation, phase.prospective = creation, intent
			phase.supersession = scope
			phase.recoveryOnly = strings.HasPrefix(mode, "recovery-")
			registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, auditing, lifecycle, phase, issuer, sending.contributor})
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
			record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: "tenant-a", CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "protected", "aggregate.type": "user", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0"}})
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
			eventType := "password.reset.requested.v1"
			if magicLink {
				eventType = "magic-link.requested.v1"
			}
			plan, err := c.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Feature: &identitypostgres.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "user", Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: eventType}, CapabilityIssuance: &issue, Delivery: &deliveryPlan})
			if err != nil {
				t.Fatal("prepare plan", err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, cmd, plan)
			if err != nil {
				t.Fatal(err)
			}
			if phase.recoveryOnly {
				grant := issue.Grants[0]
				if mode != "recovery-absent" {
					capID, replay, origin := string(uid), grant.ProofFingerprint, ""
					if mode == "recovery-grant" {
						capID = grant.CapabilityID
					}
					if mode == "recovery-replay" {
						replay = grant.ReplayDigest
					}
					if mode == "recovery-origin" {
						origin = string(id)
					}
					// A valid retained row may conflict by any one identity. It
					// cannot be treated as absent merely because its exact origin
					// fingerprint or subject differs from the prepared grant.
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6::bytea,$7,1,NULLIF($8::text,''),CASE WHEN $8='' THEN NULL ELSE $6::bytea END,CASE WHEN $8='' THEN NULL ELSE 1 END,CASE WHEN $8='' THEN NULL ELSE 'conflicting-user' END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END,CASE WHEN $8='' THEN NULL ELSE 'signing-v1' END,CASE WHEN $8='' THEN NULL ELSE $6::bytea END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END)`, string(b.TenantID), string(grant.Purpose), int64(grant.ReplayKeyVersion), replay[:], capID, grant.ProofFingerprint[:], payload.ExpiresAt, origin, now); err != nil {
						t.Fatal("seed conflicting issuance", err)
					}
				}
				key, _ := base64.RawURLEncoding.DecodeString(string(id))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
					t.Fatal(err)
				}
				query := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
				caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
				recovered, recoveryErr := c.RecoverFeatureCommand(ctx, query, caller)
				if mode == "recovery-absent" {
					if recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Binding != b {
						t.Fatal("absent issuance did not close as not committed", recovered.Outcome, recoveryErr)
					}
				} else if recoveryErr == nil || recovered.Outcome != identity.CommitOutcomeInProgress || recovered.Binding != b {
					t.Fatal("conflicting issuance fabricated terminal outcome", recovered.Outcome, recoveryErr)
				}
				return
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, executionErr := c.ApplyFeature(ctx, w, cmd)
			if executionErr == nil {
				if mode == "late-failure" {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT reset_issue_failure CHECK(false) NOT VALID`); err != nil {
						t.Fatal(err)
					}
				}
				result, executionErr = c.Commit(w, result)
				if mode == "late-failure" {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT reset_issue_failure`); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				_, _ = c.Abort(w, executionErr)
			}
			want := 0
			if mode == "commit" || mode == "restored" || mode == "supersession" {
				want = 1
				if executionErr != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != b {
					t.Fatal("commit reset issuance", executionErr)
				}
				var subject, origin string
				var fingerprint []byte
				if err := pool.Raw().QueryRow(ctx, `SELECT subject_id,origin_command_id,proof_fingerprint FROM public.capability_identity_one_use WHERE capability_id=$1`, issue.Grants[0].CapabilityID).Scan(&subject, &origin, &fingerprint); err != nil || subject != string(uid) || origin != string(id) || !bytes.Equal(fingerprint, issue.Grants[0].ProofFingerprint[:]) {
					t.Fatal("persisted original scope", err)
				}
				_, replay, err := c.ReserveCommand(ctx, b, cmd, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("replay", err)
				}
			} else if executionErr == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied issuance committed")
			}
			var issued, delivered int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),(SELECT count(*) FROM identity.delivery_intents WHERE effect_id=$2)`, string(id), deliveryPlan.Intents[0].EffectID).Scan(&issued, &delivered); err != nil || issued != want || delivered != want {
				t.Fatalf("atomic reset issuance/delivery %d/%d: %v", issued, delivered, err)
			}
			sending.process(t, ctx, pool, b, deliveryPlan, keys, want == 0)
			if prospective {
				var users, emails int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id='tenant-a' AND user_id=$1),(SELECT count(*) FROM identity.identifiers WHERE tenant_id='tenant-a' AND user_id=$1)`, string(uid)).Scan(&users, &emails); err != nil || users != 0 || emails != 0 {
					t.Fatal("issuance created or verified prospective account", err)
				}
			}
		})
	}
}
