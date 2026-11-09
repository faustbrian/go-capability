package identitycapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type oauthCallbackConsumptionPreparer interface {
	PrepareOAuthCallbackConsumption(context.Context, identity.CommandBinding, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareOAuthCallbackConsumption(t testing.TB, i *Issuer, ctx context.Context, b identity.CommandBinding, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	p, ok := any(i).(oauthCallbackConsumptionPreparer)
	if !ok {
		t.Fatal("original RP callback-state consumption preparation is missing")
	}
	return p.PrepareOAuthCallbackConsumption(ctx, b, proof, version)
}

func TestPrepareOAuthCallbackConsumptionPreservesOriginalState(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "link", true: "anonymous signin"}[anonymous], func(t *testing.T) {
			i, config, b, payload := issuerFixture(t)
			b = oauthRPIssuerBinding(b, anonymous)
			payload.Operation, payload.Resource, payload.Subject = "identity.oauth.callback", b.RecordID, string(b.UserID)
			if anonymous {
				payload.Subject = b.AnonymousFlowID
			}
			payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
			payload.ExpiresAt = payload.IssuedAt.Add(10 * time.Minute)
			issued, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
			if err != nil {
				t.Fatal(err)
			}
			issuance, _ := issued.Plan()
			want := issuance.Grants[0]
			proof := issued.state.proofs[0]
			plan, err := prepareOAuthCallbackConsumption(t, i, context.Background(), b, proof, want.ReplayKeyVersion)
			if err != nil || plan != want || plan.Purpose != "identity.oauth.callback" {
				t.Fatal("original RP state identity or expiry changed", err)
			}
			config.CurrentReplayKeyVersion, config.RetainedReplayKeys = 3, map[uint32][32]byte{2: {2}, 3: {3}}
			rotated, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if got, err := prepareOAuthCallbackConsumption(t, rotated, context.Background(), b, proof, want.ReplayKeyVersion); err != nil || got != want {
						t.Error("retained state replay identity changed after rotation", err)
					}
				})
			}
			wg.Wait()
			if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
				if sha256.Sum256(raw) != want.ProofFingerprint {
					t.Error("original state proof was replaced")
				}
				return nil
			}); err != nil {
				t.Fatal("read-only preparation transferred original custody", err)
			}
			if out, err := prepareOAuthCallbackConsumption(t, i, context.Background(), b, proof, want.ReplayKeyVersion); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("transferred state proof regained custody", err)
			}
		})
	}
}

func TestPrepareOAuthCallbackConsumptionRejectsSignedForeignProfiles(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for name, mutate := range map[string]func(*capability.Payload){
			"foreign tenant":        func(p *capability.Payload) { p.Tenant = "foreign" },
			"foreign subject":       func(p *capability.Payload) { p.Subject = "foreign" },
			"foreign transaction":   func(p *capability.Payload) { p.Resource = "foreign-rp-transaction" },
			"final link grant":      func(p *capability.Payload) { p.Operation = "identity.account.link-token" },
			"multiple audiences":    func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
			"reusable":              func(p *capability.Payload) { p.MaxUses = 0 },
			"multiple uses":         func(p *capability.Payload) { p.MaxUses = 2 },
			"subjectless bearer":    func(p *capability.Payload) { p.Subject, p.Bearer = "", true },
			"changed not-before":    func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
			"extended original TTL": func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second) },
		} {
			t.Run(name, func(t *testing.T) {
				i, config, b, payload := issuerFixture(t)
				b = oauthRPIssuerBinding(b, anonymous)
				payload.ID, payload.Operation, payload.Resource, payload.Subject = "original-state-proof", "identity.oauth.callback", b.RecordID, string(b.UserID)
				if anonymous {
					payload.Subject = b.AnonymousFlowID
				}
				payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
				payload.ExpiresAt = payload.IssuedAt.Add(10 * time.Minute)
				mutate(&payload)
				proof, _, err := i.service.Issue(context.Background(), payload)
				if err != nil {
					t.Fatal("foreign-profile fixture could not be signed", err)
				}
				t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
				if out, err := prepareOAuthCallbackConsumption(t, i, context.Background(), b, proof, 1); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
					t.Fatal("signed foreign profile admitted or misclassified", err)
				}
			})
		}
	}
}

func TestPrepareOAuthCallbackConsumptionRejectsForeignComposition(t *testing.T) {
	var invalid identity.InvalidInputError
	i, config, b, payload := issuerFixture(t)
	b = oauthRPIssuerBinding(b, false)
	payload.Operation, payload.Resource = "identity.oauth.callback", b.RecordID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.OperationID = "identity.user.create" },
		func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID, b.LinkMode = "identity.account.link-token", "identity-account", identity.AccountLinkExplicit
		},
		func(b *identity.CommandBinding) { b.SchemaID += "-foreign" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.RecordID = "" },
		func(b *identity.CommandBinding) { b.ActorID = "another-user" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "other-flow" },
		func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
	} {
		bad := b
		mutate(&bad)
		if out, err := prepareOAuthCallbackConsumption(t, i, context.Background(), bad, proof, 2); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("foreign original RP binding admitted or misclassified", err)
		}
	}
	for _, version := range []uint32{0, 9} {
		if out, err := prepareOAuthCallbackConsumption(t, i, context.Background(), b, proof, version); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("unretained replay key admitted", err)
		}
	}
	if out, err := prepareOAuthCallbackConsumption(t, i, context.Background(), b, capability.Proof{}, 2); !errors.Is(err, identity.ForbiddenError{}) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("zero proof admitted", err)
	}
	if out, err := prepareOAuthCallbackConsumption(t, nil, context.Background(), b, proof, 2); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("nil issuer admitted", err)
	}
	if out, err := prepareOAuthCallbackConsumption(t, i, nilContextForTest(), b, proof, 2); !errors.As(err, &invalid) || out != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("nil context admitted", err)
	}
}

func TestPrepareOAuthCallbackConsumptionRechecksConfiguredAuthority(t *testing.T) {
	i, originalConfig, b, payload := issuerFixture(t)
	b = oauthRPIssuerBinding(b, false)
	payload.Operation, payload.Resource = "identity.oauth.callback", b.RecordID
	payload.IssuedAt, payload.NotBefore = originalConfig.Crypto.Clock(), originalConfig.Crypto.Clock()
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, mode := range []string{"expired", "foreign-key", "foreign-issuer", "foreign-audience", "revoked", "unavailable", "panic", "cancelled", "cancelled-after-success", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			config, ctx := originalConfig, context.Background()
			var expected error = identity.ForbiddenError{}
			switch mode {
			case "expired":
				config.Crypto.Clock = func() time.Time { return payload.ExpiresAt }
			case "foreign-key":
				v, _ := capability.NewHMACSHA256Verifier([]byte("foreign-key-012345678901234567890123"))
				config.Crypto.Resolver, _ = capability.NewKeySet([]capability.Key{{Issuer: config.Crypto.Issuer, ID: "signing-v1", Verifier: v}})
			case "foreign-issuer":
				config.Crypto.Issuer = "https://foreign.example.test"
			case "foreign-audience":
				config.Audience = "foreign"
			case "revoked":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private callback diagnostics")
				})
			case "panic":
				expected = identity.UnavailableError{}
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private callback diagnostics") })
			case "cancelled", "cancelled-after-success":
				expected = identity.CancelledError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				if mode == "cancelled" {
					cancel()
				} else {
					config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { cancel(); return false, nil })
				}
			case "deadline":
				expected = identity.DeadlineExceededError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			}
			issuer, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			out, err := prepareOAuthCallbackConsumption(t, issuer, ctx, b, proof, 2)
			if !errors.Is(err, expected) || out != (identitypostgres.CapabilityPlan{}) || strings.Contains(err.Error(), "private callback diagnostics") {
				t.Fatal("configured authority failure admitted, leaked or misclassified", err)
			}
		})
	}
}

func oauthRPIssuerBinding(b identity.CommandBinding, anonymous bool) identity.CommandBinding {
	b.OperationID, b.SchemaID = "identity.account.link-start", "identity.account.link-start.rp-v1"
	b.SchemaVersion, b.PolicyVersion = 1, 1
	b.PolicyID, b.CorrelationID, b.RecordID = "configured-rp-policy", "rp-correlation", "original-rp-transaction"
	b.ActorID, b.ActorKind = identity.ActorID(b.UserID), authorization.SubjectUser
	if anonymous {
		b.OperationID, b.SchemaID = "identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1"
		b.UserID, b.AnonymousFlowID = "", "original-preauth-flow"
		b.ActorID, b.ActorKind = "configured-rp-service", authorization.SubjectServiceAccount
	}
	return b
}

func TestOAuthRPIssuerRejectsForeignProfiles(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		i, config, binding, payload := issuerFixture(t)
		b := oauthRPIssuerBinding(binding, anonymous)
		payload.Operation, payload.Resource, payload.Subject = "identity.oauth.callback", b.RecordID, string(b.UserID)
		if anonymous {
			payload.Subject = b.AnonymousFlowID
		}
		payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
		payload.ExpiresAt = payload.IssuedAt.Add(10 * time.Minute)
		for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
			"foreign schema":         func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaID += "-foreign" },
			"foreign version":        func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
			"missing record":         func(b *identity.CommandBinding, _ *capability.Payload) { b.RecordID = "" },
			"missing actor":          func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorID = "" },
			"missing policy":         func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyID = "" },
			"missing policy version": func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyVersion = 0 },
			"missing correlation":    func(b *identity.CommandBinding, _ *capability.Payload) { b.CorrelationID = "" },
			"missing subject":        func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID, b.AnonymousFlowID = "", "" },
			"mixed subject":          func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID, b.AnonymousFlowID = "user", "flow" },
			"foreign actor":          func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectAPIKey },
			"account link mode":      func(b *identity.CommandBinding, _ *capability.Payload) { b.LinkMode = identity.AccountLinkExplicit },
			"foreign resource":       func(_ *identity.CommandBinding, p *capability.Payload) { p.Resource += "-foreign" },
			"final link grant":       func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.account.link-token" },
			"foreign subject":        func(_ *identity.CommandBinding, p *capability.Payload) { p.Subject += "-foreign" },
			"missing issued time":    func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = time.Time{} },
			"delayed validity":       func(_ *identity.CommandBinding, p *capability.Payload) { p.NotBefore = p.NotBefore.Add(time.Second) },
			"extended lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
				p.ExpiresAt = p.IssuedAt.Add(10*time.Minute + time.Second)
			},
			"zero lifetime":    func(_ *identity.CommandBinding, p *capability.Payload) { p.ExpiresAt = p.IssuedAt },
			"bearer state":     func(_ *identity.CommandBinding, p *capability.Payload) { p.Bearer = true },
			"reusable state":   func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 2 },
			"foreign tenant":   func(_ *identity.CommandBinding, p *capability.Payload) { p.Tenant += "-foreign" },
			"foreign audience": func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"foreign"} },
		} {
			t.Run(name, func(t *testing.T) {
				bad, p := b, payload
				mutate(&bad, &p)
				if out, err := i.Prepare(context.Background(), bad, []capability.Payload{p}); err == nil || out.state != nil {
					t.Fatal("reserved RP operation admitted a foreign callback profile")
				}
			})
		}
		if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload, payload}); err == nil || out.state != nil {
			t.Fatal("RP transaction acquired two state grants")
		}
		for _, plan := range []identitypostgres.CapabilityIssuancePlan{
			{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"},
		} {
			if out, err := i.preparePlan(context.Background(), b, plan, []capability.Payload{payload}, false); err == nil || out.state != nil {
				t.Fatal("RP state admitted a user override")
			}
		}
	}
}

func TestOAuthRPIssuerPreservesOriginalCallbackGrant(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		name := "link"
		if anonymous {
			name = "anonymous signin"
		}
		t.Run(name, func(t *testing.T) {
			i, config, binding, payload := issuerFixture(t)
			b := oauthRPIssuerBinding(binding, anonymous)
			payload.Operation, payload.Resource = "identity.oauth.callback", b.RecordID
			payload.Subject = string(b.UserID)
			if anonymous {
				payload.Subject = b.AnonymousFlowID
			}
			payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
			payload.ExpiresAt = payload.IssuedAt.Add(10 * time.Minute)
			prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
			if err != nil {
				t.Fatal("original RP callback preparation denied", err)
			}
			plan, err := prepared.Plan()
			if err != nil || len(plan.Grants) != 1 || plan.RegistrationUserID != "" || plan.ResetRecipientUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" {
				t.Fatal("RP flow became a user override", err)
			}
			if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
				t.Fatal("original RP declaration rejected", err)
			}
			for _, mutate := range []func(*identitypostgres.CapabilityIssuancePlan){
				func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.account.link-token" },
				func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
				func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = "user" },
				func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
				func(p *identitypostgres.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = "user" },
				func(p *identitypostgres.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
			} {
				bad := plan
				bad.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
				mutate(&bad)
				if i.ValidateCapabilityIssuance(b, bad) == nil {
					t.Fatal("frozen RP plan admitted a different issuance profile")
				}
			}
			codec, _ := preparationFixture(t, i, config)
			disclosures := 0
			wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(ctx context.Context, _ uint16, token []byte) error {
				disclosures++
				g, verifyErr := capability.Verify(ctx, string(token), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
				if verifyErr != nil || g.EnvelopeDigest() != plan.Grants[0].ProofFingerprint {
					t.Fatal("RP checkpoint did not contain the original verified envelope")
				}
				got := g.Payload()
				if got.Subject != payload.Subject || got.Resource != b.RecordID || got.Operation != payload.Operation || got.IssuedAt != payload.IssuedAt || got.NotBefore != payload.NotBefore || got.ExpiresAt != payload.ExpiresAt {
					t.Fatal("original RP callback intent changed")
				}
				return nil
			})
			if err != nil || disclosures != 1 {
				t.Fatal("original RP checkpoint denied", err)
			}
			second, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(context.Context, uint16, []byte) error {
				t.Fatal("retained checkpoint disclosed another bearer")
				return nil
			})
			if err != nil || !bytes.Equal(second, wire) {
				t.Fatal("retained RP checkpoint replaced", err)
			}
			codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
			restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
			if err != nil || restored.state == nil || restored.state.binding != b || restored.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint || restored.state.grants[0].Payload().ExpiresAt != payload.ExpiresAt {
				t.Fatal("RP restoration replaced original subject, envelope or expiry", err)
			}
			if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("restored RP bearer redisclosed"); return nil }) == nil {
				t.Fatal("restoration reopened bearer custody")
			}
			foreign := b
			foreign.RecordID += "-foreign"
			if _, err := codec.RestorePreparation(context.Background(), foreign, 7, plan, wire); err == nil {
				t.Fatal("retained RP checkpoint changed transactions")
			}
			codec.clock = func() time.Time { return payload.ExpiresAt.Add(time.Second) }
			if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire); err == nil {
				t.Fatal("expired RP state renewed on restoration")
			}
		})
	}
}
