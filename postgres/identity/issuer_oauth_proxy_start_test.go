package identitycapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func oauthProxyStartIssuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	i, config, b, payload := issuerFixture(t)
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.oauth.proxy-start", "identity.oauth.proxy-start.native-v1", 1
	b.UserID, b.AnonymousFlowID, b.RecordID = "", string(flow), string(flow)
	b.ActorID, b.ActorKind = "proxy-service", authorization.SubjectServiceAccount
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "proxy-policy", 1, string(b.CommandID)
	payload.Subject, payload.Resource = b.AnonymousFlowID, b.RecordID
	payload.Operation, payload.CorrelationID = "identity.oauth.proxy-forward", b.CorrelationID
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.ExpiresAt = payload.IssuedAt.Add(5 * time.Minute)
	digest := sha256.Sum256([]byte("original proxy environment and generated request binding"))
	payload.Caveats = map[string]string{"identity.oauth.proxy.binding": base64.RawURLEncoding.EncodeToString(digest[:])}
	return i, config, b, payload
}

func TestOAuthProxyStartIssuerPreservesOriginalForwardGrantAndCheckpoint(t *testing.T) {
	i, config, b, payload := oauthProxyStartIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal("native proxy start forward preparation denied", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.RegistrationUserID != "" || plan.ResetRecipientUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" {
		t.Fatal("proxy flow became a local user or multiple grants", err)
	}
	metadata := plan.Grants[0]
	if metadata.Purpose != "identity.oauth.proxy-forward" || metadata.MaxUses != 1 || metadata.ExpiresAt != payload.ExpiresAt || metadata.ReplayKeyVersion != config.CurrentReplayKeyVersion {
		t.Fatal("proxy forward metadata changed")
	}
	if err := i.ValidateCapabilityIssuance(b, plan); err != nil {
		t.Fatal("native proxy issuance declaration denied", err)
	}
	callback := b
	callback.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	callback.OperationID, callback.SchemaID = "identity.oauth.proxy-forward", "identity.oauth.proxy-forward.native-v1"
	origin, err := identity.ParseCommandID(b.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload.Caveats["identity.oauth.proxy.binding"])
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], decoded)
	consumption, err := i.PrepareOAuthProxyForwardConsumption(context.Background(), callback, origin, digest, prepared.state.proofs[0], metadata.ReplayKeyVersion)
	if err != nil || consumption != metadata {
		t.Fatal("native start proof could not reach the unchanged forward consumer", err)
	}
	codec, _ := preparationFixture(t, i, config)
	disclosures := 0
	var borrowed []byte
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(ctx context.Context, _ uint16, token []byte) error {
		disclosures++
		borrowed = token
		grant, verifyErr := capability.Verify(ctx, string(token), config.Crypto.Resolver, capability.VerifyOptions{Issuer: config.Crypto.Issuer, Now: config.Crypto.Clock(), Limits: config.Crypto.Limits})
		if verifyErr != nil || grant.EnvelopeDigest() != metadata.ProofFingerprint {
			t.Fatal("checkpoint lost signed proxy envelope", verifyErr)
		}
		want := payload
		want.ID = metadata.CapabilityID
		if !reflect.DeepEqual(grant.Payload(), want) {
			t.Fatal("checkpoint changed signed proxy bindings")
		}
		return nil
	})
	if err != nil || disclosures != 1 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("proxy checkpoint denied or retained borrowed plaintext", err)
	}
	retained, err := codec.CheckpointPreparation(context.Background(), prepared, 7, func(context.Context, uint16, []byte) error {
		t.Fatal("retained checkpoint redisclosed proof")
		return nil
	})
	if err != nil || !bytes.Equal(wire, retained) {
		t.Fatal("retained checkpoint replaced original custody", err)
	}
	codec.clock = func() time.Time { return payload.IssuedAt.Add(time.Minute) }
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil {
		t.Fatal("original proxy checkpoint restoration denied", err)
	}
	restoredPlan, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(restoredPlan, plan) || restored.state.binding != b || restored.state.checkpointGeneration != 7 {
		t.Fatal("restoration replaced original proxy custody", err)
	}
	grants, err := restored.Grants()
	if err != nil || len(grants) != 1 || grants[0].EnvelopeDigest() != metadata.ProofFingerprint || !reflect.DeepEqual(grants[0].Payload(), prepared.state.grants[0].Payload()) {
		t.Fatal("restoration changed original signed proxy grant", err)
	}
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error {
		t.Fatal("restoration redisclosed original proxy proof")
		return nil
	}) == nil {
		t.Fatal("restoration reopened proxy delivery custody")
	}
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"tenant": func(b *identity.CommandBinding) { b.TenantID += "-foreign" },
		"flow": func(b *identity.CommandBinding) {
			b.AnonymousFlowID, b.RecordID = "AQEBAQEBAQEBAQEBAQEBAQ", "AQEBAQEBAQEBAQEBAQEBAQ"
		},
		"origin": func(b *identity.CommandBinding) { b.CorrelationID = "AgICAgICAgICAgICAgICAg" },
		"actor":  func(b *identity.CommandBinding) { b.ActorID += "-foreign" },
		"policy": func(b *identity.CommandBinding) { b.PolicyVersion++ },
	} {
		t.Run("restore foreign "+name, func(t *testing.T) {
			foreign := b
			mutate(&foreign)
			if _, err := codec.RestorePreparation(context.Background(), foreign, 7, plan, wire); err == nil {
				t.Fatal("checkpoint accepted foreign original proxy scope")
			}
		})
	}
	if _, err := codec.RestorePreparation(context.Background(), b, 8, plan, wire); err == nil {
		t.Fatal("checkpoint changed original generation")
	}
	codec.clock = func() time.Time { return payload.ExpiresAt }
	if _, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire); err == nil {
		t.Fatal("expired proxy state renewed during restoration")
	}
}

func TestOAuthProxyStartIssuerRejectsForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *capability.Payload){
		"foreign schema":  func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaID += "-foreign" },
		"foreign version": func(b *identity.CommandBinding, _ *capability.Payload) { b.SchemaVersion++ },
		"missing command": func(b *identity.CommandBinding, _ *capability.Payload) { b.CommandID = "" },
		"missing tenant":  func(b *identity.CommandBinding, _ *capability.Payload) { b.TenantID = "" },
		"noncanonical flow": func(b *identity.CommandBinding, p *capability.Payload) {
			b.AnonymousFlowID, b.RecordID, p.Subject, p.Resource = "uncanonical-flow", "uncanonical-flow", "uncanonical-flow", "uncanonical-flow"
		},
		"zero flow": func(b *identity.CommandBinding, p *capability.Payload) {
			b.AnonymousFlowID, b.RecordID, p.Subject, p.Resource = "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA"
		},
		"foreign record": func(b *identity.CommandBinding, p *capability.Payload) {
			b.RecordID, p.Resource = "AgICAgICAgICAgICAgICAg", "AgICAgICAgICAgICAgICAg"
		},
		"user override":          func(b *identity.CommandBinding, _ *capability.Payload) { b.UserID = "user" },
		"missing actor":          func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorID = "" },
		"user actor":             func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectUser },
		"API key actor":          func(b *identity.CommandBinding, _ *capability.Payload) { b.ActorKind = authorization.SubjectAPIKey },
		"missing policy":         func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyID = "" },
		"missing policy version": func(b *identity.CommandBinding, _ *capability.Payload) { b.PolicyVersion = 0 },
		"noncanonical origin": func(b *identity.CommandBinding, p *capability.Payload) {
			b.CorrelationID, p.CorrelationID = "uncanonical-origin", "uncanonical-origin"
		},
		"zero origin": func(b *identity.CommandBinding, p *capability.Payload) {
			b.CorrelationID, p.CorrelationID = "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA"
		},
		"unrelated origin command": func(b *identity.CommandBinding, p *capability.Payload) {
			b.CorrelationID, p.CorrelationID = "AgICAgICAgICAgICAgICAg", "AgICAgICAgICAgICAgICAg"
		},
		"origin reuses transaction": func(b *identity.CommandBinding, p *capability.Payload) {
			b.AnonymousFlowID, b.RecordID = string(b.CommandID), string(b.CommandID)
			p.Subject, p.Resource = b.AnonymousFlowID, b.RecordID
		},
		"link mode":              func(b *identity.CommandBinding, _ *capability.Payload) { b.LinkMode = identity.AccountLinkExplicit },
		"caller grant ID":        func(_ *identity.CommandBinding, p *capability.Payload) { p.ID = "caller-chosen" },
		"foreign subject":        func(_ *identity.CommandBinding, p *capability.Payload) { p.Subject += "-foreign" },
		"foreign tenant":         func(_ *identity.CommandBinding, p *capability.Payload) { p.Tenant += "-foreign" },
		"foreign resource":       func(_ *identity.CommandBinding, p *capability.Payload) { p.Resource += "-foreign" },
		"foreign correlation":    func(_ *identity.CommandBinding, p *capability.Payload) { p.CorrelationID += "-foreign" },
		"ordinary OAuth purpose": func(_ *identity.CommandBinding, p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"One Tap purpose": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Operation = "identity.oauth.onetap-callback"
		},
		"foreign audience":   func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences": func(_ *identity.CommandBinding, p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":             func(_ *identity.CommandBinding, p *capability.Payload) { p.Bearer = true },
		"unlimited uses":     func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":      func(_ *identity.CommandBinding, p *capability.Payload) { p.MaxUses = 2 },
		"missing issued":     func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = time.Time{} },
		"fractional issued":  func(_ *identity.CommandBinding, p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Nanosecond) },
		"non UTC issued": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.IssuedAt = p.IssuedAt.In(time.FixedZone("offset", 3600))
		},
		"non UTC not-before": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.NotBefore = p.NotBefore.In(time.FixedZone("offset", 3600))
		},
		"changed not-before": func(_ *identity.CommandBinding, p *capability.Payload) { p.NotBefore = p.NotBefore.Add(-time.Second) },
		"fractional expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.Add(time.Nanosecond)
		},
		"non UTC expiry": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.ExpiresAt.In(time.FixedZone("offset", 3600))
		},
		"extended lifetime": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second)
		},
		"zero lifetime":  func(_ *identity.CommandBinding, p *capability.Payload) { p.ExpiresAt = p.IssuedAt },
		"missing caveat": func(_ *identity.CommandBinding, p *capability.Payload) { p.Caveats = nil },
		"foreign caveat": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Caveats = map[string]string{"foreign": "binding"}
		},
		"extra caveat": func(_ *identity.CommandBinding, p *capability.Payload) { p.Caveats["foreign"] = "binding" },
		"zero binding digest": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Caveats["identity.oauth.proxy.binding"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"short binding digest": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Caveats["identity.oauth.proxy.binding"] = base64.RawURLEncoding.EncodeToString([]byte("short"))
		},
		"padded binding digest": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Caveats["identity.oauth.proxy.binding"] += "="
		},
		"noncanonical binding digest": func(_ *identity.CommandBinding, p *capability.Payload) {
			p.Caveats["identity.oauth.proxy.binding"] = strings.Repeat("A", 42) + "B"
		},
	} {
		t.Run(name, func(t *testing.T) {
			i, _, b, payload := oauthProxyStartIssuerFixture(t)
			mutate(&b, &payload)
			if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil || out.state != nil {
				t.Fatal("proxy start admitted foreign profile")
			}
		})
	}
	i, _, b, payload := oauthProxyStartIssuerFixture(t)
	for _, inputs := range [][]capability.Payload{nil, {payload, payload}} {
		if out, err := i.Prepare(context.Background(), b, inputs); err == nil || out.state != nil {
			t.Fatal("proxy start did not require exactly one forward grant")
		}
	}
	for _, plan := range []identitypostgres.CapabilityIssuancePlan{{RegistrationUserID: "user"}, {ResetRecipientUserID: "user"}, {MagicLinkRecipientUserID: "user"}, {MFAContinuationUserID: "user"}} {
		if out, err := i.preparePlan(context.Background(), b, plan, []capability.Payload{payload}, false); err == nil || out.state != nil {
			t.Fatal("proxy start admitted a local user override")
		}
	}
}

func TestOAuthProxyStartIssuerRejectsSignedScopeAndDeclarations(t *testing.T) {
	i, _, b, payload := oauthProxyStartIssuerFixture(t)
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identitypostgres.CapabilityIssuancePlan){
		"foreign purpose": func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants[0].Purpose = "identity.oauth.callback" },
		"multiple grants": func(p *identitypostgres.CapabilityIssuancePlan) { p.Grants = append(p.Grants, p.Grants[0]) },
		"registration":    func(p *identitypostgres.CapabilityIssuancePlan) { p.RegistrationUserID = "user" },
		"reset":           func(p *identitypostgres.CapabilityIssuancePlan) { p.ResetRecipientUserID = "user" },
		"magiclink":       func(p *identitypostgres.CapabilityIssuancePlan) { p.MagicLinkRecipientUserID = "user" },
		"MFA":             func(p *identitypostgres.CapabilityIssuancePlan) { p.MFAContinuationUserID = "user" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := plan
			foreign.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
			mutate(&foreign)
			if i.ValidateCapabilityIssuance(b, foreign) == nil {
				t.Fatal("proxy declaration admitted foreign profile")
			}
		})
	}
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":      func(p *capability.Payload) { p.Tenant += "-foreign" },
		"subject":     func(p *capability.Payload) { p.Subject += "-foreign" },
		"resource":    func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation": func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"purpose":     func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"extra caveat": func(p *capability.Payload) {
			p.Caveats = map[string]string{"identity.oauth.proxy.binding": p.Caveats["identity.oauth.proxy.binding"], "foreign": "binding"}
		},
		"missing caveat": func(p *capability.Payload) { p.Caveats = nil },
		"not-before":     func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"lifetime":       func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
	} {
		t.Run("signed foreign "+name, func(t *testing.T) {
			foreign := payload
			foreign.ID = plan.Grants[0].CapabilityID
			mutate(&foreign)
			proof, _, err := i.service.Issue(context.Background(), foreign)
			if err != nil {
				t.Fatal("signed foreign fixture failed", err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			grant, err := i.service.Verify(context.Background(), proof, capability.Purpose(foreign.Operation), i.audience)
			if err != nil {
				t.Fatal("foreign signed fixture verification failed", err)
			}
			if _, err := i.grantSubjectPlan(b, b.AnonymousFlowID, grant, i.current); err == nil {
				t.Fatal("foreign signed proxy scope admitted during restoration or persistence")
			}
		})
	}
}

func TestOAuthProxyStartIssuerRejectsPurposeBorrowing(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	b.OperationID = "identity.user.create"
	prepared, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	plan.Grants[0].Purpose = "identity.oauth.proxy-forward"
	if i.ValidateCapabilityIssuance(b, plan) == nil {
		t.Fatal("ordinary command borrowed proxy purpose in retained issuance")
	}
	payload.Operation = "identity.oauth.proxy-forward"
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	if out, err := i.Prepare(context.Background(), b, []capability.Payload{payload}); err == nil || out.state != nil {
		t.Fatal("ordinary command borrowed proxy forward issuance")
	}
}
