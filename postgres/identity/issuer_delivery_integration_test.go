//go:build integration

package identitycapability_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// The fixture supplies only deployment keys/templates. Persistence and encrypted
// custody remain owned by the public native delivery contributor.
type issuanceDeliveryFixture struct {
	contributor          *deliverypostgres.Contributor
	renderer             *delivery.TemplateRenderer
	digests              [][32]byte
	service              *secretenvelope.Service
	config               deliverypostgres.ContributorConfig
	templates            []delivery.Template
	registrationUser     identity.UserID
	prospectiveRecipient bool
	issuanceCheckpoint   []byte
	inspectDelivered     func(context.Context, string) error
	limits               capability.Limits
}

func newIssuanceDeliveryFixture(t *testing.T) *issuanceDeliveryFixture {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{"envelope-a": bytes.Repeat([]byte{4}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := secretenvelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	config := deliverypostgres.ContributorConfig{Deployment: "test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {3}}, ActiveEnvelopeKeyID: "envelope-a", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypostgres.ProviderProfile{1: {Provider: "test-provider", PolicyVersion: 1}}}
	contributor, err := deliverypostgres.NewContributor(config, service)
	if err != nil {
		t.Fatal(err)
	}
	templates := []delivery.Template{{ID: "verify", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", ContentType: "text/plain", Subject: "Verification", Body: "{{.token}}", MaxRenderedBytes: 8192, RequiredVariables: []string{"token"}, VariableSchema: []delivery.VariableSchema{{Name: "token", Kind: "text", Sensitive: true}}}}
	renderer, err := delivery.NewTemplateRenderer(templates)
	if err != nil {
		t.Fatal(err)
	}
	return &issuanceDeliveryFixture{contributor: contributor, renderer: renderer, service: service, config: config, templates: templates, limits: capability.DefaultLimits()}
}

type issuanceSender func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

func (s issuanceSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return s(ctx, a)
}

func (f *issuanceDeliveryFixture) process(t *testing.T, ctx context.Context, pool *database.Pool, b identity.CommandBinding, p identitypostgres.DeliveryPlan, resolver capability.Resolver, empty ...bool) {
	t.Helper()
	policy, err := authorization.NewDecisionService(testPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	profile := delivery.DefaultConfig()
	profile.Production = true
	profile.DedupeTTL = 25 * time.Hour
	service, err := deliverypostgres.NewEnqueueService(ctx, pool, deliverypostgres.EnqueueConfig{Custody: f.config, Coordinator: identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}}, PolicyID: "test-policy", PolicyVersion: 1, AuditRetentionVersion: 1, Timeout: 2 * time.Second, NamespaceKey: [32]byte{7}, Policies: map[uint64]delivery.Config{1: profile}, StateTracking: true}, f.service, policy, f.templates)
	if err != nil {
		t.Fatal("native worker composition", err)
	}
	calls := 0
	worker, err := service.NewWorker(deliverypostgres.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "worker-correlation", Request: authorization.Request{Tenant: "tenant-a", Action: "identity.delivery.process", Subject: authorization.Subject{ID: "worker-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "worker-a"}}}, ProviderConfigVersion: 1}, issuanceSender(func(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		calls++
		if f.inspectDelivered != nil {
			if err := f.inspectDelivered(ctx, a.Body); err != nil {
				t.Error("delivered custody inspection failed", err)
			}
		}
		grant, err := capability.Verify(ctx, a.Body, resolver, capability.VerifyOptions{Issuer: "https://identity.example.test", Now: time.Now().UTC(), Limits: f.limits})
		if err != nil {
			t.Error("delivered original signature invalid")
		} else if grant.EnvelopeDigest() != f.digests[0] {
			t.Error("worker delivered another token")
		}
		user := b.UserID
		if f.registrationUser != "" {
			user = f.registrationUser
		}
		if err == nil && grant.Payload().Subject != string(user) {
			t.Error("worker changed verification subject")
		}
		if a.IntentID != delivery.IntentID(p.Intents[0].EffectID) || a.TenantID != delivery.TenantID(b.TenantID) || a.Recipient != "recipient@example.invalid" || a.Subject != "Verification" || !a.ValidUntil.Equal(p.Intents[0].ExpiresAt) {
			t.Error("worker changed original intent")
		}
		var committed bool
		commandID, decodeErr := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT (EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2) = NOT $4::boolean) AND EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE origin_command_id=$3 AND subject_id=$2 AND state='issued') AND EXISTS(SELECT 1 FROM identity.commands WHERE tenant_id=$1 AND command_id=$5 AND state='committed')`, string(b.TenantID), string(user), string(b.CommandID), f.prospectiveRecipient, commandID).Scan(&committed); err != nil || !committed {
			t.Error("sender preceded original commit")
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := worker.ProcessOne(ctx)
	if len(empty) > 0 && empty[0] {
		if err != nil || out.Claimed || calls != 0 {
			t.Fatal("rolled-back delivery reached provider", err)
		}
		return
	}
	if err != nil || !out.Claimed || out.Completion.State != delivery.StateDelivered || calls != 1 {
		t.Fatal("native worker failed", err)
	}
	var erased bool
	if err := pool.Raw().QueryRow(ctx, `SELECT state='confirmed' AND ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL FROM identity.delivery_intents WHERE effect_id=$1`, p.Intents[0].EffectID).Scan(&erased); err != nil || !erased {
		t.Fatal("terminal custody retained", err)
	}
	if out, err := worker.ProcessOne(ctx); err != nil || out.Claimed || calls != 1 {
		t.Fatal("terminal message resent", err)
	}
}

func (f *issuanceDeliveryFixture) prepare(t *testing.T, ctx context.Context, b identity.CommandBinding, issued identitycapability.PreparedIssuance, count int, expiry time.Time, checkpoint ...*identitycapability.IssuancePreparationCodec) deliverypostgres.PreparedDelivery {
	t.Helper()
	f.digests = make([][32]byte, count)
	plan, e := issued.Plan()
	if e != nil {
		t.Fatal(e)
	}
	f.registrationUser = plan.RegistrationUserID
	subject := string(b.UserID)
	if subject == "" {
		subject = b.AnonymousFlowID
	}
	// Render and encrypt within the transfer callback; no plaintext leaves it.
	// Each one-item preparation receives its original effect index. Multiple
	// effects must instead be admitted as one batch, so this test selects one.
	if count != 1 {
		t.Fatal("single-message fixture requires one grant")
	}
	var sealed deliverypostgres.PreparedDelivery
	encrypt := func(ctx context.Context, token []byte) error {
		f.digests[0] = sha256.Sum256(token)
		recipient := delivery.Recipient{Channel: delivery.ChannelEmail, Address: "recipient@example.invalid", ScopeDigest: strings.Repeat("a", 64)}
		rendered, err := f.renderer.Render(ctx, delivery.Message{Purpose: "verification", Channel: delivery.ChannelEmail, Recipient: recipient, TemplateID: "verify", TemplateVersion: 1, LocaleChain: []string{"en"}, Variables: []delivery.TemplateVariable{{Name: "token", Kind: "text", TextValue: string(token), Sensitive: true}}})
		if err != nil {
			return err
		}
		sealed, err = f.contributor.Prepare(ctx, b, []deliverypostgres.IntentInput{{EffectIndex: 0, Purpose: "verification", SubjectID: subject, TemplateID: "verify", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: expiry, Recipient: recipient, Rendered: rendered}})
		return err
	}
	var err error
	if len(checkpoint) == 0 {
		err = issued.TransferForDelivery(ctx, 0, encrypt)
	} else {
		f.issuanceCheckpoint, err = checkpoint[0].CheckpointPreparation(ctx, issued, 1, func(ctx context.Context, index uint16, token []byte) error {
			if index != 0 {
				return identity.InvalidInputError{}
			}
			return encrypt(ctx, token)
		})
	}
	if err != nil {
		t.Fatal("original proof encryption", err)
	}
	return sealed
}
