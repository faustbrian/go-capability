//go:build integration

package identitycapability_test

import (
	"context"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Provider/session/policy and counter admission are deliberate owner doubles.
// Capability signing, issued metadata, consumption, identity mutation, audit,
// lifecycle and command receipts use actual public native owners. This proves
// the already-issued link contract, not OAuth exchange or session authority.
type linkConsumptionProvider struct {
	issuer  *identitycapability.Issuer
	proof   capability.Proof
	mode    string
	checked time.Time
}

func (*linkConsumptionProvider) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}
}

func (p *linkConsumptionProvider) PrepareAccountLink(ctx context.Context, command identity.Command) (identity.Command, kernel.CommandCounterPlan, kernel.CapabilityPlan, error) {
	plan, err := p.issuer.PrepareAccountLinkConsumption(ctx, command, p.proof, 1)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, kernel.CapabilityPlan{}, err
	}
	c, err := identity.NewAccountLinkCounterCommand(command, identity.AccountLinkCounterContext{Network: "192.0.2.10", PreparedAt: p.checked, KeyVersions: []uint32{1}})
	return c, kernel.CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{4}}, plan, err
}

func (*linkConsumptionProvider) ValidateAccountLink(command identity.Command, plan kernel.CommandPlan) error {
	spec, _, ok := command.AccountLinkCounterCommand()
	if !ok || plan.Capability == nil || plan.Capability.ProofFingerprint != spec.Proof.EnvelopeDigest() {
		return identity.InvalidInputError{}
	}
	return nil
}

func (p *linkConsumptionProvider) CheckAccountLink(ctx context.Context, h kernel.AccountLinkWork) error {
	spec, final, err := h.Command(p)
	if err != nil {
		return err
	}
	epoch, err := h.CredentialAuthorityVersion(p)
	if err != nil {
		return err
	}
	version := spec.Change.ExpectedUserVersion
	if final {
		version++
	}
	rows, err := h.Query(ctx, `SELECT version::text,credential_version::text,status FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(spec.Binding.TenantID), string(spec.Binding.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var actual, credentials, status string
	if !rows.Next() || rows.Scan(&actual, &credentials, &status) != nil || rows.Next() || rows.Err() != nil || actual != strconv.FormatUint(version, 10) || credentials != strconv.FormatUint(epoch, 10) || status != "active" {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *linkConsumptionProvider) PersistAccountLink(ctx context.Context, h kernel.AccountLinkWork) error {
	spec, final, err := h.Command(p)
	if err != nil || final {
		return identity.InvalidInputError{}
	}
	_, err = h.Exec(ctx, `INSERT INTO public.capability_link_provider_fixture(command_id,finalized) VALUES($1,false)`, string(spec.Binding.CommandID))
	return err
}

func (p *linkConsumptionProvider) FinalizeAccountLink(ctx context.Context, h kernel.AccountLinkWork) error {
	spec, final, err := h.Command(p)
	if err != nil || !final {
		return identity.InvalidInputError{}
	}
	n, err := h.Exec(ctx, `UPDATE public.capability_link_provider_fixture SET finalized=true WHERE command_id=$1 AND NOT finalized`, string(spec.Binding.CommandID))
	if err != nil {
		return err
	}
	if n != 1 || p.mode == "rollback" {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *linkConsumptionProvider) RecoverParticipant(ctx context.Context, h kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := h.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if p.mode == "pending-unknown" {
		// No local consumption is not proof that an external exchange failed.
		return kernel.RecoveryUnknown, nil
	}
	rows, err := h.Query(ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_link_provider_fixture WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

type linkConsumptionCounters struct{}

func (*linkConsumptionCounters) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}
func (*linkConsumptionCounters) ValidateCommandCounters(identity.Command, kernel.CommandCounterPlan) error {
	return nil
}
func (p *linkConsumptionCounters) ReserveCommandCounters(_ context.Context, h kernel.CommandCounterWork) (kernel.CommandCounterDisposition, error) {
	_, err := h.Binding(p)
	return kernel.CommandCounterAllowed, err
}
func (p *linkConsumptionCounters) CheckCommandCounters(_ context.Context, h kernel.CommandCounterAdmissionWork) error {
	_, err := h.Binding(p)
	return err
}
func (p *linkConsumptionCounters) RecoverParticipant(_ context.Context, h kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	_, err := h.CommandCounterBinding(p)
	return kernel.RecoveryNotCommitted, err
}

func linkConsumerAudit(t *testing.T, ctx context.Context, b identity.CommandBinding, now time.Time, creation bool) (audit.Record, kernel.AuditPlan) {
	t.Helper()
	action, aggregate, id := "identity.account.link", "account", b.RecordID
	if creation {
		action, aggregate, id = "identity.user.create", "user", string(b.UserID)
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{Action: action, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: aggregate, ID: id}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "standard", "aggregate.type": aggregate, "aggregate.id": id, "aggregate.before_version": "0", "aggregate.after_version": "1"}})
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
	digest, err := kernel.AuditBindingDigest(b, record)
	if err != nil {
		t.Fatal(err)
	}
	return record, kernel.AuditPlan{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}
}

// Persist the real signed grant through native issuance under an independently
// authorized creation origin. No SQL inserts manufacture capability authority.
func issueNativeLinkConsumerProof(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) (*linkConsumptionProvider, identity.Command, kernel.CapabilityPlan) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("link-consumer", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	keys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "link-consumer", Verifier: verifier}})
	crypto := capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}
	issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{Crypto: crypto, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := capability.NewService(crypto)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: commandID, TenantID: "tenant-a", UserID: identity.UserID(user), ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.account.link-token", RecordID: string(commandID), LinkMode: identity.AccountLinkExplicit, PolicyID: "link-policy", PolicyVersion: 1, SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: string(commandID)}
	spec := identity.AccountLinkCommand{Binding: b, SessionID: "session", SessionVersion: 1, Change: identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: identity.Account{ID: identity.AccountID(b.RecordID), TenantID: b.TenantID, UserID: b.UserID, Provider: "configured-provider", Issuer: "https://provider.example.test", Subject: string(user), Version: 1}, ExpectedUserVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}}
	spec.Change.Method = &identity.LoginMethod{AccountID: spec.Change.Account.ID, Credential: identity.CredentialRef{ID: identity.CredentialID(commandID), TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, Usable: true}
	payload, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: spec, Issuer: crypto.Issuer, Audience: "identity", ID: "unsigned-placeholder", IssuedAt: now, ExpiresAt: now.Add(4 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = ""
	origin := b
	origin.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	origin.OperationID, origin.SchemaID, origin.RecordID, origin.LinkMode, origin.CorrelationID = "identity.user.create", "identity-user", "", 0, string(origin.CommandID)
	creation, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: origin, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(ctx, origin, []capability.Payload{payload})
	if err != nil {
		t.Fatal("native signing", err)
	}
	t.Cleanup(func() {
		_ = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
	})
	issuance, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, issuer})
	if err != nil {
		t.Fatal(err)
	}
	c, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
	if err != nil {
		t.Fatal(err)
	}
	_, auditPlan := linkConsumerAudit(t, ctx, origin, now, true)
	plan, err := c.PrepareCommandPlan(origin, creation, kernel.CommandPlan{Contributors: registry.Descriptors(), Audits: []kernel.AuditPlan{auditPlan}, Lifecycle: &kernel.LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, CapabilityIssuance: &issuance})
	if err != nil {
		t.Fatal(err)
	}
	reservation, _, err := c.ReserveCommand(ctx, origin, creation, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Abort(w, identity.UnavailableError{})
	created, err := repo.ApplyUserCreation(ctx, w, creation)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Stage(ctx, w, prepared); err != nil {
		t.Fatal("native issuance staging", err)
	}
	primary, err := w.DatabaseTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := linkConsumerAudit(t, ctx, origin, primary, true)
	if err := w.StageAudit(0, record); err != nil {
		t.Fatal(err)
	}
	if err := w.StageLifecycle(0, primary); err != nil {
		t.Fatal(err)
	}
	result, err := c.Commit(w, identity.CommandResult{Binding: origin, Outcome: identity.CommitOutcomeCommitted, User: created, AuditEventID: record.ID()})
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native issuance transaction", err)
	}
	var proof capability.Proof
	if err := prepared.TransferForDelivery(ctx, 0, func(_ context.Context, raw []byte) error {
		var err error
		proof, err = capability.ParseProof(string(raw), capability.DefaultLimits())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	spec.Proof, err = service.Verify(ctx, proof, "identity.account.link-token", "identity")
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewAccountLinkCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	return &linkConsumptionProvider{issuer: issuer, proof: proof, checked: now}, command, issuance.Grants[0]
}

func testNativeAccountLinkConsumption(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.capability_link_provider_fixture(command_id text PRIMARY KEY,finalized boolean NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "rollback", "pending-negative", "pending-unknown", "takeover"} {
		t.Run(mode, func(t *testing.T) {
			provider, command, issued := issueNativeLinkConsumerProof(t, ctx, pool, repo, auditing, lifecycle)
			provider.mode = mode
			spec, _ := command.LinkAccount()
			participant := identitycapability.NewParticipant()
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, participant, &linkConsumptionCounters{}, provider})
			if err != nil {
				t.Fatal(err)
			}
			c, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			owner, err := kernel.NewAccountLinkUnitOfWork(c, repo, kernel.AccountLinkUnitOfWorkConfig{RetentionPolicyVersion: 1})
			if err != nil {
				t.Fatal(err)
			}
			q := identity.RecoveryQuery{CommandID: spec.Binding.CommandID, TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, ActorID: spec.Binding.ActorID, ActorKind: spec.Binding.ActorKind, OperationID: spec.Binding.OperationID, RecordID: spec.Binding.RecordID, LinkMode: spec.Binding.LinkMode}
			assertState := func(want string, uses int32, generation uint64, linked bool) {
				t.Helper()
				var state, actualGeneration string
				var actualUses int32
				var envelope, replay []byte
				var expiry time.Time
				if err := pool.Raw().QueryRow(ctx, `SELECT state,uses,generation::text,proof_fingerprint,replay_digest,expires_at FROM public.capability_identity_one_use WHERE capability_id=$1`, issued.CapabilityID).Scan(&state, &actualUses, &actualGeneration, &envelope, &replay, &expiry); err != nil || state != want || actualUses != uses || actualGeneration != strconv.FormatUint(generation, 10) || string(envelope) != string(issued.ProofFingerprint[:]) || string(replay) != string(issued.ReplayDigest[:]) || !expiry.Equal(issued.ExpiresAt) {
					t.Fatal("native capability transition or original custody changed", state, actualUses, actualGeneration, err)
				}
				account, err := repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: spec.Change.Account, Mode: spec.Change.Mode})
				wantVersion, wantRecord, wantEffects := uint64(1), uint64(0), 0
				if linked {
					wantVersion, wantRecord, wantEffects = 2, 1, 1
				}
				var effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_link_provider_fixture WHERE command_id=$1 AND finalized`, string(spec.Binding.CommandID)).Scan(&effects); e != nil || err != nil || account.Access.User.Version != wantVersion || account.RecordVersion != wantRecord || account.CredentialVersion != wantVersion || len(account.Access.Methods) != wantEffects || effects != wantEffects {
					t.Fatal("capability and protected mutation were not atomic", err, e)
				}
			}
			if mode == "pending-negative" || mode == "pending-unknown" || mode == "takeover" {
				prepared, counters, capPlan, err := provider.PrepareAccountLink(ctx, command)
				if err != nil || capPlan != issued {
					t.Fatal("consumer changed native issued plan", err)
				}
				_, auditPlan := linkConsumerAudit(t, ctx, spec.Binding, provider.checked, false)
				plan, err := c.PrepareCommandPlan(spec.Binding, prepared, kernel.CommandPlan{Contributors: registry.Descriptors(), Audits: []kernel.AuditPlan{auditPlan}, Lifecycle: &kernel.LifecyclePlan{EventType: "social_provider.linked.v1", AfterVersion: 1}, Capability: &capPlan, CommandCounters: &counters})
				if err != nil {
					t.Fatal(err)
				}
				old, result, err := c.ReserveCommand(ctx, spec.Binding, prepared, plan)
				if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("initial native reservation", err)
				}
				assertState("reserved", 0, 1, false)
				id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND command_id=$2`, string(spec.Binding.TenantID), id); err != nil {
					t.Fatal(err)
				}
				if mode == "takeover" {
					result, err := owner.Execute(ctx, command)
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("current generation could not consume native proof", result.Outcome, err)
					}
					assertState("finalized", 1, 2, true)
				} else {
					recovered, err := owner.Recover(ctx, q)
					if mode == "pending-unknown" {
						if recovered.Outcome != identity.CommitOutcomeInProgress {
							t.Fatal("unknown provider outcome guessed", recovered.Outcome, err)
						}
						assertState("reserved", 0, 1, false)
						return
					}
					if recovered.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("native noncommit recovery", recovered.Outcome, err)
					}
					assertState("released", 0, 2, false)
				}
				if _, err := c.Begin(ctx, old); err == nil {
					t.Fatal("stale generation retained native execution authority")
				}
				return
			}
			result, err := owner.Execute(ctx, command)
			if mode == "rollback" {
				if result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("late rollback lost known noncommit", result.Outcome, err)
				}
				assertState("released", 0, 1, false)
				if recovered, err := owner.Recover(ctx, q); recovered.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("rollback receipt recovery", recovered.Outcome, err)
				}
				if replay, _ := owner.Execute(ctx, command); replay.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("terminal released proof reactivated on exact retry")
				}
				assertState("released", 0, 1, false)
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Link == nil || result.Link.AccountID != spec.Change.Account.ID {
				t.Fatal("native protected account link", result.Outcome, err)
			}
			assertState("finalized", 1, 1, true)
			replayed, err := owner.Execute(ctx, command)
			if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.AuditEventID != result.AuditEventID {
				t.Fatal("exact replay changed native receipt", err)
			}
			if recovered, err := owner.Recover(ctx, q); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.AuditEventID != result.AuditEventID {
				t.Fatal("committed native receipt recovery", err)
			}
			assertState("finalized", 1, 1, true)
		})
	}
}
