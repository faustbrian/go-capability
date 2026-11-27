package identitycapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

type oauthProxyForwardConsumptionPreparer interface {
	PrepareOAuthProxyForwardConsumption(context.Context, identity.CommandBinding, identity.CommandID, [32]byte, capability.Proof, uint32) (identitypostgres.CapabilityPlan, error)
}

func prepareOAuthProxyForwardConsumption(t testing.TB, issuer *Issuer, ctx context.Context, callback identity.CommandBinding, origin identity.CommandID, digest [32]byte, proof capability.Proof, version uint32) (identitypostgres.CapabilityPlan, error) {
	t.Helper()
	preparer, ok := any(issuer).(oauthProxyForwardConsumptionPreparer)
	if !ok {
		t.Fatal("original OAuth proxy forward consumption preparation is missing")
	}
	return preparer.PrepareOAuthProxyForwardConsumption(ctx, callback, origin, digest, proof, version)
}

func oauthProxyForwardConsumptionFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, identity.CommandID, [32]byte, capability.Payload) {
	t.Helper()
	issuer, config, callback, payload := issuerFixture(t)
	origin, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("original proxy environment and request binding"))
	callback.UserID = ""
	callback.AnonymousFlowID, callback.RecordID = "original-proxy-flow", "original-proxy-flow"
	callback.OperationID, callback.SchemaID, callback.SchemaVersion = "identity.oauth.proxy-forward", "identity.oauth.proxy-forward.native-v1", 1
	callback.ActorKind, callback.ActorID = authorization.SubjectServiceAccount, "proxy-service"
	callback.PolicyID, callback.PolicyVersion = "proxy-policy", 1
	callback.CorrelationID = string(origin)
	payload.ID, payload.Subject, payload.Resource = "original-proxy-state", callback.AnonymousFlowID, callback.RecordID
	payload.Operation, payload.CorrelationID = callback.OperationID, string(origin)
	payload.IssuedAt, payload.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	payload.Caveats = map[string]string{"identity.oauth.proxy.binding": base64.RawURLEncoding.EncodeToString(digest[:])}
	return issuer, config, callback, origin, digest, payload
}

func oauthProxyForwardProof(t testing.TB, issuer *Issuer, payload capability.Payload) capability.Proof {
	t.Helper()
	proof, _, err := issuer.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal("proxy signed fixture failed", err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	return proof
}

func TestPrepareOAuthProxyForwardConsumptionPreservesOriginalProofAndReplay(t *testing.T) {
	issuer, config, callback, origin, digest, payload := oauthProxyForwardConsumptionFixture(t)
	proof := oauthProxyForwardProof(t, issuer, payload)
	originalGrant, err := issuer.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	want, err := issuer.grantSubjectPlan(callback, callback.AnonymousFlowID, originalGrant, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Crypto.Signer = resetNeverSigner{config.Crypto.Signer}
	config.CurrentReplayKeyVersion = 3
	config.RetainedReplayKeys = map[uint32][32]byte{2: {2}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	for range 8 {
		calls.Go(func() {
			plan, err := prepareOAuthProxyForwardConsumption(t, rotated, context.Background(), callback, origin, digest, proof, 2)
			if err != nil || plan != want {
				t.Error("preparation changed original proxy proof, expiry or replay identity", err)
			}
		})
	}
	calls.Wait()
	other, err := prepareOAuthProxyForwardConsumption(t, rotated, context.Background(), callback, origin, digest, proof, 3)
	if err != nil || other.ReplayKeyVersion != 3 || other.ReplayDigest == want.ReplayDigest || other.ProofFingerprint != want.ProofFingerprint {
		t.Fatal("another retained replay key impersonated the original durable version", err)
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != want.ProofFingerprint {
			t.Error("original signed proxy bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only preparation spent original proof custody", err)
	}
	if plan, err := prepareOAuthProxyForwardConsumption(t, rotated, context.Background(), callback, origin, digest, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("transferred proxy proof regained custody", err)
	}
}

func TestPrepareOAuthProxyForwardConsumptionRejectsForeignComposition(t *testing.T) {
	issuer, _, callback, origin, digest, payload := oauthProxyForwardConsumptionFixture(t)
	proof := oauthProxyForwardProof(t, issuer, payload)
	for name, mutate := range map[string]func(*identity.CommandBinding){
		"ordinary OAuth callback": func(b *identity.CommandBinding) {
			b.OperationID, b.SchemaID = "identity.oauth.callback", "identity.oauth.callback.native-v1"
		},
		"signin schema":               func(b *identity.CommandBinding) { b.SchemaID = "identity.oauth.signin-start.rp-v1" },
		"schema version":              func(b *identity.CommandBinding) { b.SchemaVersion++ },
		"missing command":             func(b *identity.CommandBinding) { b.CommandID = "" },
		"original reused as callback": func(b *identity.CommandBinding) { b.CommandID = origin },
		"missing tenant":              func(b *identity.CommandBinding) { b.TenantID = "" },
		"missing flow":                func(b *identity.CommandBinding) { b.AnonymousFlowID = "" },
		"foreign record":              func(b *identity.CommandBinding) { b.RecordID += "-foreign" },
		"user subject":                func(b *identity.CommandBinding) { b.UserID = "user" },
		"user actor":                  func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
		"missing actor":               func(b *identity.CommandBinding) { b.ActorID = "" },
		"missing policy":              func(b *identity.CommandBinding) { b.PolicyID = "" },
		"missing policy version":      func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
		"foreign correlation":         func(b *identity.CommandBinding) { b.CorrelationID += "-foreign" },
		"member link":                 func(b *identity.CommandBinding) { b.LinkMode = identity.AccountLinkExplicit },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := callback
			mutate(&foreign)
			var invalid identity.InvalidInputError
			if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), foreign, origin, digest, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign callback composition admitted or misclassified", err)
			}
		})
	}
	for _, malformed := range []identity.CommandID{"", "not-a-command", "AAAAAAAAAAAAAAAAAAAAAA"} {
		foreign := callback
		foreign.CorrelationID = string(malformed)
		var invalid identity.InvalidInputError
		if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), foreign, malformed, digest, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("noncanonical original command admitted", err)
		}
	}
	for _, version := range []uint32{0, 99} {
		var invalid identity.InvalidInputError
		if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), callback, origin, digest, proof, version); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("unretained replay version admitted", err)
		}
	}
	for _, call := range []struct {
		issuer *Issuer
		ctx    context.Context
		digest [32]byte
	}{{nil, context.Background(), digest}, {&Issuer{}, context.Background(), digest}, {issuer, nil, digest}, {issuer, context.Background(), [32]byte{}}} {
		var invalid identity.InvalidInputError
		if plan, err := prepareOAuthProxyForwardConsumption(t, call.issuer, call.ctx, callback, origin, call.digest, proof, 2); !errors.As(err, &invalid) || plan != (identitypostgres.CapabilityPlan{}) {
			t.Fatal("invalid caller composition admitted", err)
		}
	}
	for name, mutate := range map[string]func(*identity.CommandBinding, *identity.CommandID, *[32]byte){
		"tenant": func(b *identity.CommandBinding, _ *identity.CommandID, _ *[32]byte) { b.TenantID += "-foreign" },
		"flow": func(b *identity.CommandBinding, _ *identity.CommandID, _ *[32]byte) {
			b.AnonymousFlowID += "-foreign"
			b.RecordID = b.AnonymousFlowID
		},
		"original command": func(b *identity.CommandBinding, o *identity.CommandID, _ *[32]byte) {
			*o = "AQEBAQEBAQEBAQEBAQEBAQ"
			b.CorrelationID = string(*o)
		},
		"binding digest": func(_ *identity.CommandBinding, _ *identity.CommandID, d *[32]byte) { d[0] ^= 1 },
	} {
		t.Run("foreign signed "+name, func(t *testing.T) {
			foreign, otherOrigin, otherDigest := callback, origin, digest
			mutate(&foreign, &otherOrigin, &otherDigest)
			if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), foreign, otherOrigin, otherDigest, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign authenticated proxy scope admitted", err)
			}
		})
	}
	if _, err := issuer.service.Verify(context.Background(), proof, capability.Purpose(payload.Operation), "identity"); err != nil {
		t.Fatal("denial spent original proof custody", err)
	}
	if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), callback, origin, digest, capability.Proof{}, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("absent original proof admitted", err)
	}
}

func TestPrepareOAuthProxyForwardConsumptionRejectsForeignSignedProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"ordinary purpose":       func(p *capability.Payload) { p.Operation = "identity.oauth.callback" },
		"signin purpose":         func(p *capability.Payload) { p.Operation = "identity.sso.oauth-callback" },
		"tenant":                 func(p *capability.Payload) { p.Tenant += "-foreign" },
		"subject":                func(p *capability.Payload) { p.Subject += "-foreign" },
		"resource":               func(p *capability.Payload) { p.Resource += "-foreign" },
		"correlation":            func(p *capability.Payload) { p.CorrelationID += "-foreign" },
		"binding caveat":         func(p *capability.Payload) { p.Caveats = map[string]string{"identity.oauth.proxy.binding": "foreign"} },
		"missing binding caveat": func(p *capability.Payload) { p.Caveats = nil },
		"additional caveat":      func(p *capability.Payload) { p.Caveats["unexpected"] = "policy" },
		"foreign audience":       func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences":     func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"reusable":               func(p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":          func(p *capability.Payload) { p.MaxUses = 2 },
		"bearer":                 func(p *capability.Payload) { p.Bearer, p.Subject = true, "" },
		"changed not-before":     func(p *capability.Payload) { p.NotBefore = p.IssuedAt.Add(-time.Second) },
		"extended lifetime":      func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(5*time.Minute + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, _, callback, origin, digest, payload := oauthProxyForwardConsumptionFixture(t)
			mutate(&payload)
			proof := oauthProxyForwardProof(t, issuer, payload)
			if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), callback, origin, digest, proof, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("foreign signed proxy profile admitted", err)
			}
			if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
				t.Fatal("denial transferred signed proof custody", err)
			}
		})
	}
}

func TestPrepareOAuthProxyForwardConsumptionEnforcesExclusiveLifetimeDespiteSkew(t *testing.T) {
	issuer, config, callback, origin, digest, payload := oauthProxyForwardConsumptionFixture(t)
	proof := oauthProxyForwardProof(t, issuer, payload)
	observed := payload.IssuedAt
	config.Crypto.Clock, config.Crypto.Skew = func() time.Time { return observed }, time.Minute
	verifier, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, instant := range []time.Time{payload.IssuedAt.Add(-time.Nanosecond), payload.IssuedAt, payload.ExpiresAt.Add(-time.Nanosecond), payload.ExpiresAt, payload.ExpiresAt.Add(time.Second)} {
		t.Run(instant.Sub(payload.IssuedAt).String(), func(t *testing.T) {
			observed = instant
			plan, err := prepareOAuthProxyForwardConsumption(t, verifier, context.Background(), callback, origin, digest, proof, 2)
			if !instant.Before(payload.IssuedAt) && instant.Before(payload.ExpiresAt) {
				if err != nil || plan.ExpiresAt != payload.ExpiresAt {
					t.Fatal("original proxy validity shortened", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
				t.Fatal("verification skew extended proxy validity", err)
			}
		})
	}
}

func TestPrepareOAuthProxyForwardConsumptionRechecksAuthorityAndContext(t *testing.T) {
	issuer, config, callback, origin, digest, payload := oauthProxyForwardConsumptionFixture(t)
	proof := oauthProxyForwardProof(t, issuer, payload)
	for _, mode := range []string{"revoked", "unavailable", "panic", "cancelled", "cancelled-after-verify", "caller-deadline", "preparation-timeout", "zero-clock"} {
		t.Run(mode, func(t *testing.T) {
			c, ctx := config, context.Background()
			var expected error = identity.ForbiddenError{}
			switch mode {
			case "revoked":
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				expected = identity.UnavailableError{}
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private proxy details")
				})
			case "panic":
				expected = identity.UnavailableError{}
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private proxy details") })
			case "cancelled":
				expected = identity.CancelledError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "cancelled-after-verify":
				expected = identity.CancelledError{}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					cancel()
					return false, nil
				})
			case "caller-deadline", "preparation-timeout":
				expected = identity.DeadlineExceededError{}
				if mode == "caller-deadline" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, time.Millisecond)
					defer cancel()
				}
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			case "zero-clock":
				expected = identity.UnavailableError{}
				clockCalls := 0
				c.Crypto.Clock = func() time.Time {
					clockCalls++
					if clockCalls > 1 {
						return time.Time{}
					}
					return config.Crypto.Clock()
				}
			}
			verifier, err := NewIssuer(c)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := prepareOAuthProxyForwardConsumption(t, verifier, ctx, callback, origin, digest, proof, 2)
			if !errors.Is(err, expected) || plan != (identitypostgres.CapabilityPlan{}) || strings.Contains(err.Error(), "private proxy details") {
				t.Fatal("proxy authority failure admitted, leaked or misclassified", err)
			}
		})
	}
}

func TestPrepareOAuthProxyForwardConsumptionRejectsCorruptedSignature(t *testing.T) {
	issuer, config, callback, origin, digest, payload := oauthProxyForwardConsumptionFixture(t)
	proof := oauthProxyForwardProof(t, issuer, payload)
	var wire []byte
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error { wire = bytes.Clone(raw); return nil }); err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	signature := bytes.LastIndexByte(wire, '.') + 1
	if signature <= 0 || signature >= len(wire) {
		t.Fatal("unexpected signed proof framing")
	}
	if wire[signature] == 'A' {
		wire[signature] = 'B'
	} else {
		wire[signature] = 'A'
	}
	corrupted, err := capability.ParseProof(string(wire), config.Crypto.Limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = corrupted.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	})
	if plan, err := prepareOAuthProxyForwardConsumption(t, issuer, context.Background(), callback, origin, digest, corrupted, 2); !errors.Is(err, identity.ForbiddenError{}) || plan != (identitypostgres.CapabilityPlan{}) {
		t.Fatal("unauthenticated proxy proof produced plan", err)
	}
}
