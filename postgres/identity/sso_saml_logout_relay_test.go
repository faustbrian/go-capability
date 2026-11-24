package identitycapability

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type samlLogoutRelayPreparer interface {
	PrepareSSOSAMLLogoutRelayConsumption(context.Context, identity.CommandBinding, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareSAMLLogoutRelay(t testing.TB, i *Issuer, ctx context.Context, b identity.CommandBinding, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(i).(samlLogoutRelayPreparer)
	if !ok {
		t.Fatal("SP-generated SAML logout RelayState preparation is missing")
	}
	return preparer.PrepareSSOSAMLLogoutRelayConsumption(ctx, b, proof, version)
}

func samlLogoutRelayFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	i, config, b, payload := ssoOIDCExplicitLinkIssuerFixture(t)
	localCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b.OperationID, b.SchemaID = "identity.sso.saml-logout-relay-issue", "sso-enterprise-saml-logout-relay-issue-v1"
	b.PolicyID = "enterprise-saml-logout-policy"
	b.CorrelationID, payload.CorrelationID = string(localCommand), string(localCommand)
	payload.Operation = "identity.sso.saml-logout-relay-settle"
	payload.ExpiresAt = payload.IssuedAt.Add(5 * time.Minute)
	payload.Caveats = map[string]string{"saml.logout": "original-provider-request-and-browser"}
	return i, config, b, payload
}

func TestSAMLLogoutRelayPreservesOriginalRestoredProof(t *testing.T) {
	i, config, b, payload := samlLogoutRelayFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("valid original logout RelayState issuance denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		t.Fatal("original logout RelayState plan missing", err)
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("original logout RelayState declaration denied", err)
	}
	wantPayload := payload
	wantPayload.ID = plan.Grants[0].CapabilityID
	if !reflect.DeepEqual(prepared.state.grants[0].Payload(), wantPayload) {
		t.Fatal("issuance replaced original signed logout intent")
	}
	want := plan.Grants[0]
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for range 2 {
		if got, err := prepareSAMLLogoutRelay(t, i, context.Background(), b, proof, want.ReplayKeyVersion); err != nil || got != want {
			t.Fatal("read-only preparation changed or consumed original logout proof", err)
		}
	}
	codec, _ := preparationFixture(t, i, config)
	var restoredProof capability.Proof
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(_ context.Context, _ uint16, raw []byte) error {
		var parseErr error
		restoredProof, parseErr = capability.ParseProof(string(raw), config.Crypto.Limits)
		return parseErr
	})
	if err != nil {
		t.Fatal("original checkpoint denied", err)
	}
	t.Cleanup(func() {
		_ = restoredProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || !reflect.DeepEqual(restored.state.grants[0].Payload(), wantPayload) {
		t.Fatal("checkpoint replaced original logout intent", err)
	}
	restoredPlan, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(restoredPlan, plan) {
		t.Fatal("checkpoint replaced original replay or expiry witness", err)
	}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	for range 4 {
		calls.Go(func() {
			if got, err := prepareSAMLLogoutRelay(t, rotated, context.Background(), b, restoredProof, want.ReplayKeyVersion); err != nil || got != want {
				t.Error("concurrent restored-proof preparation replaced original grant", err)
			}
		})
	}
	calls.Wait()
	if err := restoredProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("preparation took original proof custody", err)
	}
	if got, err := prepareSAMLLogoutRelay(t, rotated, context.Background(), b, restoredProof, want.ReplayKeyVersion); !errors.Is(err, identity.ForbiddenError{}) || got != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("transferred proof regained custody", err)
	}
}

func TestSAMLLogoutRelayIssuanceRejectsForeignProfiles(t *testing.T) {
	i, _, b, payload := samlLogoutRelayFixture(t)
	otherLocalCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
		"noncanonical local correlation": func(b *identity.CommandBinding, p *capability.Payload) {
			b.CorrelationID, p.CorrelationID = "not-a-command", "not-a-command"
		},
		"issue used as local correlation": func(b *identity.CommandBinding, p *capability.Payload) {
			b.CorrelationID, p.CorrelationID = string(b.CommandID), string(b.CommandID)
		},
		"anonymous sign-in operation": func(b *identity.CommandBinding, _ *capability.Payload) { b.OperationID = "identity.sso.saml-start" },
		"anonymous sign-in schema":    func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaID = "identity.sso.saml-start.v1" },
		"foreign version":             func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
		"missing user":                func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID = "" },
		"anonymous flow":              func(b *identity.CommandBinding, _ *capability.Payload) { b.AnonymousFlowID = "preauth" },
		"foreign actor":               func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorID += "-foreign" },
		"service actor": func(b *identity.CommandBinding, _ *capability.Payload) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"API key actor": func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectAPIKey },
		"foreign record": func(b *identity.CommandBinding, p *capability.Payload) {
			b.RecordID += "-foreign"
			p.Resource = b.RecordID
		},
		"missing policy":      func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyID = "" },
		"link mode":           func(b *identity.CommandBinding, _ *capability.Payload) { b.LinkMode = identity.AccountLinkExplicit },
		"foreign user":        func(_ *identity.CommandBinding, p *capability.Payload) { p.Subject += "-foreign" },
		"foreign tenant":      func(_ *identity.CommandBinding, p *capability.Payload) { p.Tenant += "-foreign" },
		"foreign resource":    func(_ *identity.CommandBinding, p *capability.Payload) { p.Resource += "-foreign" },
		"foreign correlation": func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID = string(otherLocalCommand) },
		"ACS purpose":         func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.sso.saml-acs" },
		"local logout purpose": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Operation = "identity.sso.saml-logout-start"
		},
		"foreign audience":    func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"bearer":              func(_ *identity.CommandBinding, p *capability.Payload) { p.Bearer = true },
		"multiple uses":       func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 2 },
		"fractional issuance": func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Nanosecond) },
		"non UTC issuance": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.IssuedAt = p.IssuedAt.In(time.FixedZone("offset", 3600))
		},
		"delayed validity": func(_ *identity.CommandBinding, p *capability.Payload) { p.NotBefore = p.NotBefore.Add(time.Second) },
		"fractional expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.Add(time.Nanosecond)
		},
		"non UTC expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.In(time.FixedZone("offset", 3600))
		},
		"extended lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second)
		},
		"zero lifetime": func(_ *identity.CommandBinding, p *capability.Payload) { p.ExpiresAt = p.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			foreign, input := b, payload
			mutate(&foreign, &input)
			if got, err := i.Prepare(context.Background(), foreign, []capability.Payload{input}); err == nil || got.state != nil {
				t.Fatal("logout RelayState issuance admitted a foreign profile")
			}
		})
	}
	if got, err := i.Prepare(context.Background(), b, []capability.Payload{payload, payload}); err == nil || got.state != nil {
		t.Fatal("one logout issue acquired multiple RelayState grants")
	}
	for _, plan := range []identitypostgres.CapabilityIssuancePlan{{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"}} {
		if got, err := i.preparePlan(context.Background(), b, plan, []capability.Payload{payload}, false); err == nil || got.state != nil {
			t.Fatal("logout issue admitted a foreign recipient override")
		}
	}
}

func TestSAMLLogoutRelayConsumptionRejectsForeignBindingAndProof(t *testing.T) {
	i, _, b, payload := samlLogoutRelayFixture(t)
	otherLocalCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = "original-logout-relay"
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"noncanonical local correlation":  func(b *identity.CommandBinding) { b.CorrelationID = "not-a-command" },
		"issue used as local correlation": func(b *identity.CommandBinding) { b.CorrelationID = string(b.CommandID) },
		"local revocation":                func(b *identity.CommandBinding) { b.OperationID = "identity.sso.saml-logout-start" },
		"sign-in": func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID = "identity.sso.saml-start", "identity.sso.saml-start.v1"
		},
		"schema":         func(b *identity.CommandBinding) { b.SchemaID += "-foreign" },
		"version":        func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"actor":          func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
		"actor kind":     func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		"anonymous flow": func(b *identity.CommandBinding) { b.AnonymousFlowID = "preauth" },
		"record":         func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			var invalid identity.InvalidInputError
			if got, err := prepareSAMLLogoutRelay(t, i, context.Background(), foreign, proof, 2); !errors.As(err, &invalid) || got != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign original issue admitted or misclassified", err)
			}
		})
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"user":              func(p *capability.Payload) { p.Subject += "-foreign" },
		"tenant":            func(p *capability.Payload) { p.Tenant += "-foreign" },
		"resource":          func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":       func(p *capability.Payload) { p.CorrelationID = string(otherLocalCommand) },
		"purpose":           func(p *capability.Payload) { p.Operation = "identity.sso.saml-acs" },
		"multiple uses":     func(p *capability.Payload) { p.MaxUses = 2 },
		"extended lifetime": func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
	} {
		t.Run("signed foreign "+name, func(t *testing.T) {
			foreign := payload
			mutate(&foreign)
			foreignProof, _, err := i.service.Issue(context.Background(), foreign)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = foreignProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			})
			if got, err := prepareSAMLLogoutRelay(t, i, context.Background(), b, foreignProof, 2); !errors.Is(err, identity.ForbiddenError{}) || got != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("signed foreign logout RelayState admitted or misclassified", err)
			}
		})
	}
}

func TestSAMLLogoutRelayConsumptionPreservesExclusiveExpiry(t *testing.T) {
	i, config, b, payload := samlLogoutRelayFixture(t)
	payload.ID = "original-logout-relay"
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	observed := payload.ExpiresAt.Add(-time.Nanosecond)
	config.Crypto.Clock = func() time.Time { return observed }
	config.Crypto.Skew = time.Minute
	verifier, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, instant := range []time.Time{observed, payload.ExpiresAt, payload.ExpiresAt.Add(time.Second)} {
		observed = instant
		if _, err := verifier.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience); err != nil {
			t.Fatal("verification skew did not reach strict-expiry boundary", err)
		}
		got, err := prepareSAMLLogoutRelay(t, verifier, context.Background(), b, proof, 2)
		if instant.Before(payload.ExpiresAt) {
			if err != nil || got.ExpiresAt != payload.ExpiresAt {
				t.Fatal("original validity shortened", err)
			}
		} else if !errors.Is(err, identity.ForbiddenError{}) || got != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("verification skew extended logout RelayState expiry", err)
		}
	}
}

func TestSAMLLogoutRelayRejectsReservedPurposeOutsideNativeIssue(t *testing.T) {
	i, _, issue, payload := samlLogoutRelayFixture(t)
	prepared, err := i.Prepare(context.Background(), issue, []capability.Payload{payload})
	if err != nil {
		t.Fatal("original native issue fixture denied", err)
	}
	proof := prepared.state.proofs[0]
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	otherCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	generic := issue
	generic.CommandID = otherCommand
	generic.OperationID, generic.SchemaID = "identity.profile.update", "profile-update"
	for name, binding := range map[string]identity.CommandBinding{
		"unrelated authenticated command": generic,
		"native operation with generic schema": func() identity.CommandBinding {
			b := issue
			b.SchemaID = "profile-update"
			return b
		}(),
		"native operation with foreign actor": func() identity.CommandBinding {
			b := issue
			b.ActorID += "-foreign"
			return b
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Run("prepare", func(t *testing.T) {
				got, err := i.Prepare(context.Background(), binding, []capability.Payload{payload})
				if got.state != nil {
					for _, proof := range got.state.proofs {
						_ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
					}
				}
				var invalid identity.InvalidInputError
				if !errors.As(err, &invalid) || got.state != nil {
					t.Fatal("foreign command issued the reserved logout settle purpose", err)
				}
			})
			t.Run("metadata", func(t *testing.T) {
				var invalid identity.InvalidInputError
				if err := i.ValidateCapabilityIssuance(binding, plan); !errors.As(err, &invalid) {
					t.Fatal("foreign command admitted reserved logout settle metadata", err)
				}
			})
			t.Run("authenticated grant", func(t *testing.T) {
				got, err := i.grantSubjectPlan(binding, string(binding.UserID), prepared.state.grants[0], plan.Grants[0].ReplayKeyVersion)
				var invalid identity.InvalidInputError
				if !errors.As(err, &invalid) || got != (identitypostgres.CapabilityPlan{}) {
					t.Fatal("foreign command projected the reserved authenticated logout grant", err)
				}
			})
		})
	}
	ordinary := payload
	ordinary.Operation = "identity.identifier.verify"
	ordinary.Resource, ordinary.CorrelationID = "identifier", "ordinary-correlation"
	ordinaryPrepared, err := i.Prepare(context.Background(), generic, []capability.Payload{ordinary})
	if err != nil {
		t.Fatal("reserved-purpose restriction changed an existing generic purpose", err)
	}
	t.Cleanup(func() {
		_ = ordinaryPrepared.state.proofs[0].Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	ordinaryPlan, err := ordinaryPrepared.Plan()
	if err != nil || i.ValidateCapabilityIssuance(generic, ordinaryPlan) != nil {
		t.Fatal("ordinary generic issuance metadata denied", err)
	}
}
