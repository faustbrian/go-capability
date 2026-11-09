//go:build integration

package identitycapability_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// OAuth exchange/session/policy and risk are explicit other-owner doubles.
// This consumer uses actual signing, encrypted custody, issuance, two separate
// one-use reservations, the native coordinator/account writer, audit and outbox.
// It does not prove a real OIDC callback or an authenticated session journey.
type preparedLinkConsumer struct {
	pool        *database.Pool
	issuer      *identitycapability.Issuer
	crypto      capability.Service
	envelopes   *envelope.Service
	template    identity.AccountLinkCommand
	state       kernel.CapabilityPlan
	declaration kernel.CommandPlan
	now         time.Time
	generated   atomic.Int64
	restored    atomic.Int64
	phase       atomic.Int32
	mode        string
	finalPlan   atomic.Value
}

// This explicit wire is used only inside authenticated encrypted fixture
// custody. Kernel capability plans intentionally reject general serialization.
type preparedLinkOutput struct {
	Proof                      []byte
	ID, Purpose                string
	ReplayVersion, MaximumUses uint32
	Replay, Envelope           [32]byte
	ExpiresAt                  time.Time
}

func (o preparedLinkOutput) issuance(issuer kernel.ContributorDescriptor) kernel.CapabilityIssuancePlan {
	return kernel.CapabilityIssuancePlan{Contributor: issuer, Grants: []kernel.CapabilityPlan{{CapabilityID: o.ID, Purpose: capability.Purpose(o.Purpose), ReplayKeyVersion: o.ReplayVersion, MaxUses: o.MaximumUses, ReplayDigest: o.Replay, ProofFingerprint: o.Envelope, ExpiresAt: o.ExpiresAt}}}
}

func (*preparedLinkConsumer) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}
}
func (*preparedLinkConsumer) PrepareAccountLink(context.Context, identity.Command) (identity.Command, kernel.CommandCounterPlan, kernel.CapabilityPlan, error) {
	return identity.Command{}, kernel.CommandCounterPlan{}, kernel.CapabilityPlan{}, identity.InvalidInputError{}
}
func (p *preparedLinkConsumer) ValidateAccountLinkPreparation(c identity.Command, plan kernel.CommandPlan) error {
	s, _, _, ok := c.AccountLinkPreparationInput()
	if !ok || s.Binding != p.template.Binding || plan.AccountLinkState == nil || *plan.AccountLinkState != p.state || plan.Capability != nil {
		return identity.InvalidInputError{}
	}
	return nil
}
func (*preparedLinkConsumer) ValidateAccountLink(c identity.Command, plan kernel.CommandPlan) error {
	s, _, ok := c.AccountLinkCounterCommand()
	if !ok || plan.AccountLinkState == nil || plan.Capability == nil || s.Proof.EnvelopeDigest() != plan.Capability.ProofFingerprint {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *preparedLinkConsumer) AdmitAccountLinkPreparation(ctx context.Context, h kernel.AccountLinkPreparationWork, original identity.Command) error {
	s, err := h.Command(p)
	want, _, _, ok := original.AccountLinkPreparationInput()
	if err != nil || !ok || s.Binding != want.Binding || s.FlowFingerprint != want.FlowFingerprint {
		return identity.ForbiddenError{}
	}
	_, err = h.DatabaseTime(ctx)
	return err
}
func (p *preparedLinkConsumer) outputContext(original identity.Command, generation uint64) (envelope.Context, error) {
	s, callback, bearer, ok := original.AccountLinkPreparationInput()
	if !ok || generation == 0 {
		return envelope.Context{}, identity.InvalidInputError{}
	}
	// Attribution intentionally refuses diagnostic serialization. This native
	// fixture instead binds its explicit scalar projection into hashed AAD.
	b := s.Binding
	fields := []string{string(b.CommandID), string(b.TenantID), string(b.UserID), string(b.ActorID), string(b.ActorKind), b.OperationID, b.RecordID, string(b.LinkMode), b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), b.SchemaID, strconv.FormatUint(uint64(b.SchemaVersion), 10), b.CorrelationID, s.ProviderID, strconv.FormatUint(s.ProviderConfigVersion, 10), s.FlowID, base64.RawURLEncoding.EncodeToString(s.FlowFingerprint[:]), s.SessionID, strconv.FormatUint(s.SessionVersion, 10), s.Counters.Network, s.Counters.PreparedAt.Format(time.RFC3339Nano)}
	for _, version := range s.Counters.KeyVersions {
		fields = append(fields, strconv.FormatUint(uint64(version), 10))
	}
	frame, err := json.Marshal(fields)
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	digest := sha256.New()
	_, _ = digest.Write(frame)
	err = callback.Use(context.Background(), func(_ context.Context, code, state []byte) error {
		for _, value := range [][]byte{code, state, []byte(bearer.Token())} {
			sum := sha256.Sum256(value)
			_, _ = digest.Write(sum[:])
		}
		return nil
	})
	if err != nil {
		return envelope.Context{}, err
	}
	return envelope.NewContext(map[string]string{"profile": "prepared-link-consumer-v1", "original": base64.RawURLEncoding.EncodeToString(digest.Sum(nil)), "generation": strconv.FormatUint(generation, 10)})
}
func (p *preparedLinkConsumer) GenerateAccountLinkPreparation(ctx context.Context, original identity.Command, generation uint64) ([]byte, error) {
	// A second connection must see both committed facts before any provider
	// exchange or child signing can begin. An open reservation transaction fails
	// this public-path oracle rather than being called a durable acknowledgment.
	id, _ := base64.RawURLEncoding.DecodeString(string(p.template.Binding.CommandID))
	var state, actualGeneration, marker string
	var uses int
	err := p.pool.Raw().QueryRow(ctx, `SELECT c.state,c.uses,c.generation::text,j.preparation_started_generation::text FROM public.capability_identity_one_use c JOIN identity.commands j ON j.command_id=$1 WHERE c.capability_id=$2`, id, p.state.CapabilityID).Scan(&state, &uses, &actualGeneration, &marker)
	if err != nil || state != "reserved" || uses != 0 || marker != strconv.FormatUint(generation, 10) || actualGeneration != marker {
		return nil, identity.ForbiddenError{}
	}
	p.generated.Add(1)
	if p.mode == "unknown-exchange" {
		return nil, identity.UnavailableError{}
	}
	input := p.template
	payload, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: input, Issuer: "https://identity.example.test", Audience: "identity", ID: "payload-construction-only", IssuedAt: p.now, ExpiresAt: p.now.Add(3 * time.Minute)})
	if err != nil {
		return nil, err
	}
	payload.ID = ""
	prepared, err := p.issuer.Prepare(ctx, input.Binding, []capability.Payload{payload})
	if err != nil {
		return nil, err
	}
	issue, err := prepared.Plan()
	if err != nil {
		return nil, err
	}
	p.finalPlan.Store(issue.Grants[0])
	var wire []byte
	err = prepared.TransferForDelivery(ctx, 0, func(ctx context.Context, proof []byte) error {
		g := issue.Grants[0]
		plain, err := json.Marshal(preparedLinkOutput{Proof: proof, ID: g.CapabilityID, Purpose: string(g.Purpose), ReplayVersion: g.ReplayKeyVersion, MaximumUses: g.MaxUses, Replay: g.ReplayDigest, Envelope: g.ProofFingerprint, ExpiresAt: g.ExpiresAt})
		if err != nil {
			return err
		}
		defer clear(plain)
		aad, err := p.outputContext(original, generation)
		if err != nil {
			return err
		}
		sealed, err := p.envelopes.Encrypt(ctx, envelope.EncryptRequest{KeyReference: "fixture-output", Context: aad, Plaintext: plain})
		if err != nil {
			return err
		}
		wire, err = sealed.MarshalBinary()
		return err
	})
	return wire, err
}
func (p *preparedLinkConsumer) RestoreAccountLinkPreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, kernel.CapabilityIssuancePlan, error) {
	attempt := p.restored.Add(1)
	if p.mode == "retained-restart" && attempt == 1 {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, identity.UnavailableError{}
	}
	fail := func() (identity.Command, kernel.CommandPlan, kernel.CapabilityIssuancePlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, identity.ForbiddenError{}
	}
	aad, err := p.outputContext(original, generation)
	if err != nil {
		return fail()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return fail()
	}
	plain, err := p.envelopes.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return fail()
	}
	defer clear(plain)
	var output preparedLinkOutput
	if json.Unmarshal(plain, &output) != nil {
		return fail()
	}
	defer clear(output.Proof)
	proof, err := capability.ParseProof(string(output.Proof), capability.DefaultLimits())
	if err != nil {
		return fail()
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	spec := p.template
	spec.Proof, err = p.crypto.Verify(ctx, proof, "identity.account.link-token", "identity")
	if err != nil {
		return fail()
	}
	bare, err := identity.NewAccountLinkCommand(spec)
	if err != nil {
		return fail()
	}
	input, _, _, _ := original.AccountLinkPreparationInput()
	generated, err := identity.NewAccountLinkCounterCommand(bare, input.Counters)
	if err != nil {
		return fail()
	}
	plan := p.declaration
	issue := output.issuance(p.issuer.Descriptor())
	final := issue.Grants[0]
	plan.Capability = &final
	return generated, plan, issue, nil
}
func (p *preparedLinkConsumer) CheckAccountLink(ctx context.Context, h kernel.AccountLinkWork) error {
	s, final, err := h.Command(p)
	p.phase.Store(5)
	if final {
		p.phase.Store(7)
	}
	if err != nil || s.Binding != p.template.Binding {
		return identity.ForbiddenError{}
	}
	original, wire, generation, err := h.Preparation(p)
	if err != nil {
		return err
	}
	restored, _, _, err := p.RestoreAccountLinkPreparation(ctx, original, generation, wire)
	actual, _, ok := restored.AccountLinkCounterCommand()
	if err != nil || !ok || actual.Binding != s.Binding || actual.Proof.EnvelopeDigest() != s.Proof.EnvelopeDigest() || actual.SessionID != s.SessionID || actual.SessionVersion != s.SessionVersion {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *preparedLinkConsumer) PersistAccountLink(ctx context.Context, h kernel.AccountLinkWork) error {
	p.phase.Store(6)
	s, final, err := h.Command(p)
	if err != nil || final {
		return identity.InvalidInputError{}
	}
	_, err = h.Exec(ctx, `INSERT INTO public.capability_prepared_link_provider_fixture(command_id,finalized) VALUES($1,false)`, string(s.Binding.CommandID))
	return err
}
func (p *preparedLinkConsumer) FinalizeAccountLink(ctx context.Context, h kernel.AccountLinkWork) error {
	p.phase.Store(8)
	s, final, err := h.Command(p)
	if err != nil || !final {
		return identity.InvalidInputError{}
	}
	n, err := h.Exec(ctx, `UPDATE public.capability_prepared_link_provider_fixture SET finalized=true WHERE command_id=$1 AND NOT finalized`, string(s.Binding.CommandID))
	if err != nil || n != 1 || p.mode == "rollback" {
		return identity.UnavailableError{}
	}
	return nil
}
func (p *preparedLinkConsumer) RecoverParticipant(ctx context.Context, h kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p.mode == "unknown-exchange" {
		return kernel.RecoveryUnknown, nil
	}
	b, err := h.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := h.Query(ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_prepared_link_provider_fixture WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var present bool
	if !rows.Next() || rows.Scan(&present) != nil || rows.Next() || rows.Err() != nil || present {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

func testNativePreparedAccountLink(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.capability_prepared_link_provider_fixture(command_id text PRIMARY KEY,finalized boolean NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "rollback", "unknown-exchange", "missing-issuer", "retained-restart"} {
		t.Run(mode, func(t *testing.T) { testNativePreparedAccountLinkCase(t, ctx, pool, repo, auditing, lifecycle, mode) })
	}
}

func testNativePreparedAccountLinkCase(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, mode string) {
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x61}, 32)
	signer, _ := capability.NewHMACSHA256Signer("prepared-link", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	keys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "prepared-link", Verifier: verifier}})
	crypto := capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}
	issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{Crypto: crypto, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := capability.NewService(crypto)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := identity.NewSubjectID()
	commandID, _ := identity.NewCommandID()
	b := identity.CommandBinding{CommandID: commandID, TenantID: "tenant-a", UserID: identity.UserID(user), ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.account.link-token", RecordID: string(commandID), LinkMode: identity.AccountLinkExplicit, PolicyID: "link-policy", PolicyVersion: 1, SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: string(commandID)}
	origin := b
	origin.CommandID, _ = identity.NewCommandID()
	origin.OperationID, origin.SchemaID, origin.RecordID, origin.LinkMode, origin.CorrelationID = "identity.user.create", "identity-user", "", 0, string(origin.CommandID)
	creation, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: origin, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Prepare(ctx, origin, []capability.Payload{{Version: 1, Issuer: crypto.Issuer, Audiences: []string{"identity"}, Subject: string(user), Tenant: string(b.TenantID), Operation: "identity.oauth.callback", Resource: b.RecordID, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(4 * time.Minute), MaxUses: 1}})
	if err != nil {
		t.Fatal(err)
	}
	stateIssue, err := issued.Plan()
	if err != nil {
		t.Fatal(err)
	}
	seedRegistry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, issuer})
	if err != nil {
		t.Fatal(err)
	}
	config := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}}
	seed, err := kernel.NewCoordinator(pool, seedRegistry, config)
	if err != nil {
		t.Fatal(err)
	}
	_, createAudit := linkConsumerAudit(t, ctx, origin, now, true)
	createPlan, err := seed.PrepareCommandPlan(origin, creation, kernel.CommandPlan{Contributors: seedRegistry.Descriptors(), Audits: []kernel.AuditPlan{createAudit}, Lifecycle: &kernel.LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, CapabilityIssuance: &stateIssue})
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := seed.ReserveCommand(ctx, origin, creation, createPlan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := seed.Begin(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Abort(w, identity.UnavailableError{})
	created, err := repo.ApplyUserCreation(ctx, w, creation)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Stage(ctx, w, issued); err != nil {
		t.Fatal(err)
	}
	primary, _ := w.DatabaseTime(ctx)
	record, _ := linkConsumerAudit(t, ctx, origin, primary, true)
	if w.StageAudit(0, record) != nil || w.StageLifecycle(0, primary) != nil {
		t.Fatal("seed staging failed")
	}
	if result, err := seed.Commit(w, identity.CommandResult{Binding: origin, Outcome: identity.CommitOutcomeCommitted, User: created, AuditEventID: record.ID()}); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual user/state issuance failed", err)
	}
	defer issued.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
	provider := &preparedLinkConsumer{pool: pool, issuer: issuer, crypto: service, state: stateIssue.Grants[0], now: now, mode: mode}
	provider.template = identity.AccountLinkCommand{Binding: b, SessionID: "session", SessionVersion: 1, Change: identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: identity.Account{ID: identity.AccountID(b.RecordID), TenantID: b.TenantID, UserID: b.UserID, Provider: "configured-provider", Issuer: "https://provider.example.test", Subject: string(user), Version: 1}, ExpectedUserVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}}
	provider.template.Change.Method = &identity.LoginMethod{AccountID: provider.template.Change.Account.ID, Credential: identity.CredentialRef{ID: identity.CredentialID(commandID), TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, Usable: true}
	keyProvider, err := keyring.New(map[string][]byte{"fixture-output": bytes.Repeat([]byte{0x62}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	provider.envelopes, err = envelope.NewService(keyProvider)
	if err != nil {
		t.Fatal(err)
	}
	participant, counters := identitycapability.NewParticipant(), &linkConsumptionCounters{}
	entries := []kernel.Contributor{repo, auditing, lifecycle, participant, counters, provider, issuer}
	if mode == "missing-issuer" {
		entries = entries[:6]
	}
	registry, err := kernel.NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c, err := kernel.NewCoordinator(pool, registry, config)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := kernel.NewAccountLinkUnitOfWork(c, repo, kernel.AccountLinkUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, linkedAudit := linkConsumerAudit(t, ctx, b, now, false)
	provider.declaration = kernel.CommandPlan{Contributors: registry.Descriptors()[:6], Audits: []kernel.AuditPlan{linkedAudit}, Lifecycle: &kernel.LifecyclePlan{EventType: "social_provider.linked.v1", AfterVersion: 1}, AccountLinkState: &provider.state, CommandCounters: &kernel.CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{4}}}
	callback, err := identity.NewOAuthCallbackInput([]byte("synthetic-exchanged-code"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	original, err := identity.NewAccountLinkPreparationCommand(identity.AccountLinkPreparationCommand{Binding: b, ProviderID: provider.template.Change.Account.Provider, ProviderConfigVersion: 1, FlowID: "original-flow", FlowFingerprint: [32]byte{8}, SessionID: "session", SessionVersion: 1, Counters: identity.AccountLinkCounterContext{Network: "192.0.2.10", PreparedAt: now, KeyVersions: []uint32{1}}}, callback, authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))))
	if err != nil {
		t.Fatal(err)
	}
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	result, err := owner.ExecutePrepared(ctx, original, provider.declaration)
	if mode == "missing-issuer" {
		if err == nil || result.Outcome != identity.CommitOutcomeInvalid || provider.generated.Load() != 0 || provider.restored.Load() != 0 {
			t.Fatal("missing issuer was discovered after irreversible exchange", result.Outcome, err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(commandID))
		var claimed, used int
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),state,uses FROM public.capability_identity_one_use WHERE capability_id=$2`, id, provider.state.CapabilityID).Scan(&claimed, &state, &used); err != nil || claimed != 0 || state != "issued" || used != 0 {
			t.Fatal("incomplete composition reserved original authority", err)
		}
		return
	}
	if mode == "retained-restart" {
		if result.Outcome != identity.CommitOutcomeUnknown || err == nil || provider.generated.Load() != 1 || provider.restored.Load() != 1 {
			t.Fatal("interrupted retained output invented a terminal outcome", result.Outcome, err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		rotated := config
		rotated.CurrentFingerprintKeyVersion, rotated.RetainedFingerprintKeys = 2, map[uint32][32]byte{1: {2}, 2: {3}}
		c, err = kernel.NewCoordinator(pool, registry, rotated)
		if err != nil {
			t.Fatal(err)
		}
		owner, err = kernel.NewAccountLinkUnitOfWork(c, repo, kernel.AccountLinkUnitOfWorkConfig{RetentionPolicyVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		result, err = owner.ExecutePrepared(ctx, original, provider.declaration)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || provider.generated.Load() != 1 {
			t.Fatal("retained restart regenerated or lost original output", result.Outcome, err)
		}
		var generation, started string
		var erased bool
		var fingerprintKey int64
		if err := pool.Raw().QueryRow(ctx, `SELECT j.generation::text,j.preparation_started_generation::text,j.preparation_ciphertext IS NULL AND j.preparation_ciphertext_generation IS NULL,c.fingerprint_key_version FROM identity.commands j JOIN identity.identity_command_id_claims c USING(command_id) WHERE command_id=$1`, id).Scan(&generation, &started, &erased, &fingerprintKey); err != nil || generation != "2" || started != "1" || !erased || fingerprintKey != 1 {
			t.Fatal("restart lost original exchange/claim provenance or retained terminal ciphertext", err)
		}
	}
	if mode == "unknown-exchange" {
		if result.Outcome != identity.CommitOutcomeUnknown || err == nil || provider.generated.Load() != 1 || provider.restored.Load() != 0 || provider.finalPlan.Load() != nil {
			t.Fatal("ambiguous exchange invented a terminal mutation", result.Outcome, err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		retry, err := owner.ExecutePrepared(ctx, original, provider.declaration)
		if err != nil || retry.Outcome != identity.CommitOutcomeInProgress || provider.generated.Load() != 1 || provider.restored.Load() != 0 {
			t.Fatal("expired ambiguous start repeated exchange", retry.Outcome, err)
		}
		var state string
		var uses int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,uses FROM public.capability_identity_one_use WHERE capability_id=$1`, provider.state.CapabilityID).Scan(&state, &uses); err != nil || state != "reserved" || uses != 0 {
			t.Fatal("ambiguous exchange released or consumed original state", err)
		}
		var before, after string
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&before); err != nil {
			t.Fatal(err)
		}
		recovered, err := owner.Recover(ctx, query)
		if err != nil || recovered.Outcome != identity.CommitOutcomeInProgress || provider.generated.Load() != 1 || provider.restored.Load() != 0 {
			t.Fatal("uncertain original preparation lost supported recovery", recovered.Outcome, err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&after); err != nil || before != after {
			t.Fatal("uncertain recovery transferred original exchange generation", err)
		}
		return
	}
	wanted := identity.CommitOutcomeCommitted
	linked := mode != "rollback"
	if mode == "rollback" {
		wanted = identity.CommitOutcomeNotCommitted
	}
	if err != nil || result.Outcome != wanted || (result.Link != nil) != linked || provider.generated.Load() != 1 {
		id, _ := base64.RawURLEncoding.DecodeString(string(commandID))
		var started, retained, attached bool
		var class string
		readErr := pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,coalesce(terminal_class,'') FROM identity.commands WHERE command_id=$1`, id).Scan(&started, &retained, &attached, &class)
		t.Fatalf("prepared public link did not commit: outcome=%d phase=%d class=%s generated=%d restored=%d started=%t retained=%t attached=%t error=%T read=%T", result.Outcome, provider.phase.Load(), class, provider.generated.Load(), provider.restored.Load(), started, retained, attached, err, readErr)
	}
	commandBytes, _ := base64.RawURLEncoding.DecodeString(string(commandID))
	var erased bool
	if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL FROM identity.commands WHERE command_id=$1`, commandBytes).Scan(&erased); err != nil || !erased {
		t.Fatal("terminal link retained provider output custody", err)
	}
	state, uses := "finalized", 1
	if mode == "rollback" {
		state, uses = "released", 0
	}
	finalPlan := provider.finalPlan.Load().(kernel.CapabilityPlan)
	var matched int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE capability_id IN ($1,$2) AND state=$3 AND uses=$4`, provider.state.CapabilityID, finalPlan.CapabilityID, state, uses).Scan(&matched); err != nil || matched != 2 {
		t.Fatal("original state and newly issued link grant diverged", err)
	}
	account, err := repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: provider.template.Change.Account, Mode: identity.AccountLinkExplicit})
	if err != nil || linked && (account.RecordVersion != 1 || account.CredentialVersion != 2 || account.Access.User.Version != 2) || !linked && (account.RecordVersion != 0 || account.CredentialVersion != 1 || account.Access.User.Version != 1) {
		t.Fatal("account mutation and two proof outcomes diverged", err)
	}
	recovered, err := owner.Recover(ctx, query)
	if err != nil || recovered.Outcome != wanted {
		t.Fatal("historical receipt lost after preparation issuance", recovered.Outcome, err)
	}
	before := provider.restored.Load()
	replay, err := owner.ExecutePrepared(ctx, original, provider.declaration)
	if err != nil || replay.Outcome != result.Outcome || (replay.Link != nil) != (result.Link != nil) || replay.Link != nil && *replay.Link != *result.Link || provider.generated.Load() != 1 || provider.restored.Load() != before {
		t.Fatal("terminal replay regenerated or restored provider output", err)
	}
}
