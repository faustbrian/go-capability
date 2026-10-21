package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type anonymousUpgradeConsumptionPreparer interface {
	PrepareAnonymousUpgradeConsumption(context.Context, identity.CommandBinding, capability.Proof, [32]byte, uint32, AnonymousUpgradeScope) (kernel.CapabilityPlan, error)
}

func TestPrepareAnonymousUpgradeConsumptionPublicBoundary(t *testing.T) {
	i, _, _, _ := issuerFixture(t)
	if _, ok := any(i).(anonymousUpgradeConsumptionPreparer); !ok {
		t.Fatal("original anonymous upgrade consumption preparation is missing")
	}
}

func anonymousUpgradeFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload, AnonymousUpgradeScope) {
	t.Helper()
	i, config, b, p := issuerFixture(t)
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1", 1
	b.RecordID, b.ActorID, b.ActorKind = "guest-user", identity.ActorID(b.UserID), authorization.SubjectUser
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "anonymous", 1, string(b.CommandID)
	scope := AnonymousUpgradeScope{SourceVersion: 7, SourceSessionID: "guest-session", TargetSessionID: "permanent-session", MergeDigest: [32]byte{7}, SourceExpiresAt: p.ExpiresAt.Add(time.Minute + time.Microsecond)}
	p.ID, p.Resource, p.Operation = "anonymous-upgrade-proof", b.RecordID, b.OperationID
	p.IssuedAt, p.NotBefore = config.Crypto.Clock(), config.Crypto.Clock()
	p.Caveats = map[string]string{
		"anonymous.source-version": strconv.FormatUint(scope.SourceVersion, 10),
		"anonymous.source-session": scope.SourceSessionID,
		"anonymous.target-session": scope.TargetSessionID,
		"anonymous.merge-digest":   base64.RawURLEncoding.EncodeToString(scope.MergeDigest[:]),
		"anonymous.remember":       "session",
	}
	return i, config, b, p, scope
}

// Sign through the public engine, including foreign issuer/audience profiles.
// The consuming issuer's pinned policy must reject those otherwise-valid proofs.
func signedAnonymousUpgrade(t testing.TB, config IssuerConfig, p capability.Payload) (capability.Proof, capability.Grant) {
	t.Helper()
	config.Crypto.Issuer = p.Issuer
	verifier, err := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	config.Crypto.Resolver, err = capability.NewKeySet([]capability.Key{{Issuer: p.Issuer, ID: "signing-v1", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := capability.NewService(config.Crypto)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := s.Issue(context.Background(), p)
	if err != nil {
		t.Fatal("signed fixture rejected", err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	grant, err := s.Verify(context.Background(), proof, capability.Purpose(p.Operation), p.Audiences[0])
	if err != nil {
		t.Fatal("signed fixture unverifiable", err)
	}
	return proof, grant
}

func TestPrepareAnonymousUpgradeConsumptionConservesOriginalProof(t *testing.T) {
	for _, remember := range []bool{false, true} {
		t.Run(strconv.FormatBool(remember), func(t *testing.T) {
			i, config, b, payload, scope := anonymousUpgradeFixture(t)
			scope.Remember = remember
			if remember {
				payload.Caveats["anonymous.remember"] = "persistent"
			}
			proof, grant := signedAnonymousUpgrade(t, config, payload)
			envelope := grant.EnvelopeDigest()
			plan, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, envelope, 1, scope)
			// Independently frame the existing replay contract, not grantPlan.
			key := config.RetainedReplayKeys[1]
			mac := hmac.New(sha256.New, key[:])
			_, _ = mac.Write([]byte("golib/capability/identity-replay/v1\x00"))
			for _, field := range []string{payload.Tenant, payload.Operation} {
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], uint32(len(field)))
				_, _ = mac.Write(size[:])
				_, _ = mac.Write([]byte(field))
			}
			_, _ = mac.Write(envelope[:])
			var replay [32]byte
			copy(replay[:], mac.Sum(nil))
			want := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: capability.Purpose(payload.Operation), ReplayKeyVersion: 1, ReplayDigest: replay, ProofFingerprint: envelope, ExpiresAt: payload.ExpiresAt, MaxUses: 1}
			if err != nil || plan != want {
				t.Fatal("original proof/replay/expiry changed", err)
			}
			config.CurrentReplayKeyVersion, config.RetainedReplayKeys = 3, map[uint32][32]byte{1: {1}, 3: {3}}
			rotated, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := rotated.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, envelope, 1, scope); err != nil || got != want {
				t.Fatal("rotation replaced original replay custody", err)
			}
			// Equality at the guest lifetime bound is allowed; no extension occurs.
			scope.SourceExpiresAt = payload.ExpiresAt
			if got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, envelope, 1, scope); err != nil || got != want {
				t.Fatal("equal guest expiry denied", err)
			}
			if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
				if sha256.Sum256(raw) != envelope {
					t.Fatal("borrowed proof was replaced")
				}
				return nil
			}); err != nil {
				t.Fatal("preparation transferred proof", err)
			}
			if got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, envelope, 1, scope); err == nil || got != (kernel.CapabilityPlan{}) {
				t.Fatal("transferred proof regained validity")
			}
		})
	}
}

func TestPrepareAnonymousUpgradeConsumptionRejectsSignedForeignScope(t *testing.T) {
	for name, mutate := range map[string]func(*capability.Payload){
		"tenant":               func(p *capability.Payload) { p.Tenant = "foreign" },
		"permanent-subject":    func(p *capability.Payload) { p.Subject = "foreign" },
		"guest-resource":       func(p *capability.Payload) { p.Resource = "foreign" },
		"purpose":              func(p *capability.Payload) { p.Operation = "identity.identifier.verify" },
		"issuer":               func(p *capability.Payload) { p.Issuer = "https://foreign.example.test" },
		"audience":             func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple-audiences":   func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"bearer":               func(p *capability.Payload) { p.Subject = ""; p.Bearer = true },
		"multiple-uses":        func(p *capability.Payload) { p.MaxUses = 2 },
		"unlimited-uses":       func(p *capability.Payload) { p.MaxUses = 0 },
		"source-version":       func(p *capability.Payload) { p.Caveats["anonymous.source-version"] = "8" },
		"noncanonical-version": func(p *capability.Payload) { p.Caveats["anonymous.source-version"] = "07" },
		"source-session":       func(p *capability.Payload) { p.Caveats["anonymous.source-session"] = "foreign" },
		"target-session":       func(p *capability.Payload) { p.Caveats["anonymous.target-session"] = "foreign" },
		"merge": func(p *capability.Payload) {
			p.Caveats["anonymous.merge-digest"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"noncanonical-merge": func(p *capability.Payload) { p.Caveats["anonymous.merge-digest"] += "=" },
		"remember":           func(p *capability.Payload) { p.Caveats["anonymous.remember"] = "persistent" },
		"missing":            func(p *capability.Payload) { delete(p.Caveats, "anonymous.remember") },
		"extra":              func(p *capability.Payload) { p.Caveats["anonymous.foreign"] = "other" },
		"foreign-caveat": func(p *capability.Payload) {
			delete(p.Caveats, "anonymous.remember")
			p.Caveats["organization.role"] = "session"
		},
	} {
		t.Run(name, func(t *testing.T) {
			i, config, b, payload, scope := anonymousUpgradeFixture(t)
			mutate(&payload)
			proof, grant := signedAnonymousUpgrade(t, config, payload)
			got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || got != (kernel.CapabilityPlan{}) {
				t.Fatal("signed foreign scope produced a plan", err)
			}
		})
	}
}

func TestPrepareAnonymousUpgradeConsumptionRejectsForeignInvocation(t *testing.T) {
	i, config, b, payload, original := anonymousUpgradeFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	for name, mutate := range map[string]func(*identity.CommandBinding, *AnonymousUpgradeScope, *[32]byte, *uint32){
		"operation": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.OperationID = "identity.password.signin"
		},
		"schema": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.SchemaID = "anonymous-upgrade"
		},
		"schema-version": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.SchemaVersion = 2
		},
		"actor": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.ActorID = "foreign"
		},
		"actor-kind": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.ActorKind = authorization.SubjectServiceAccount
		},
		"anonymous-flow": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.AnonymousFlowID = "foreign"
		},
		"tenant": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.TenantID = "foreign"
		},
		"source": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.RecordID = "foreign"
		},
		"source-equals-target": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.RecordID = string(b.UserID)
		},
		"target": func(b *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			b.UserID = "foreign"
			b.ActorID = "foreign"
		},
		"version-zero": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceVersion = 0
		},
		"version-mismatch": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) { s.SourceVersion++ },
		"source-session-empty": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceSessionID = ""
		},
		"source-session-long": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceSessionID = strings.Repeat("x", 129)
		},
		"source-session-space": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceSessionID = "not visible"
		},
		"target-session-unicode": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.TargetSessionID = "é"
		},
		"target-session-mismatch": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.TargetSessionID = "foreign"
		},
		"source-session-mismatch": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceSessionID = "foreign"
		},
		"merge-zero": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.MergeDigest = [32]byte{}
		},
		"merge-mismatch":   func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) { s.MergeDigest[0]++ },
		"remember":         func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) { s.Remember = true },
		"missing-envelope": func(_ *identity.CommandBinding, _ *AnonymousUpgradeScope, e *[32]byte, _ *uint32) { *e = [32]byte{} },
		"foreign-envelope": func(_ *identity.CommandBinding, _ *AnonymousUpgradeScope, e *[32]byte, _ *uint32) { *e = [32]byte{1} },
		"retired-replay":   func(_ *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, v *uint32) { *v = 99 },
		"zero-replay":      func(_ *identity.CommandBinding, _ *AnonymousUpgradeScope, _ *[32]byte, v *uint32) { *v = 0 },
		"guest-expired-before-proof": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = payload.ExpiresAt.Add(-time.Microsecond)
		},
		"guest-expiry-zero": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = time.Time{}
		},
		"guest-expiry-pre-epoch": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"guest-expiry-year-overflow": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"guest-expiry-huge-year": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = time.Date(1000000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"guest-expiry-submicro": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = s.SourceExpiresAt.Add(time.Nanosecond)
		},
		"guest-expiry-zone": func(_ *identity.CommandBinding, s *AnonymousUpgradeScope, _ *[32]byte, _ *uint32) {
			s.SourceExpiresAt = s.SourceExpiresAt.In(time.FixedZone("foreign", 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding, scope, envelope, version := b, original, grant.EnvelopeDigest(), uint32(1)
			mutate(&binding, &scope, &envelope, &version)
			if got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), binding, proof, envelope, version, scope); err == nil || got != (kernel.CapabilityPlan{}) {
				t.Fatal("foreign invocation returned a plan")
			}
		})
	}
	for _, issuer := range []*Issuer{nil, {}} {
		if got, err := issuer.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, original); err == nil || got != (kernel.CapabilityPlan{}) {
			t.Fatal("zero issuer admitted")
		}
	}
	if got, err := i.PrepareAnonymousUpgradeConsumption(nilContextForTest(), b, proof, grant.EnvelopeDigest(), 1, original); err == nil || got != (kernel.CapabilityPlan{}) {
		t.Fatal("nil context admitted")
	}
}

func TestPrepareAnonymousUpgradeConsumptionAuthorityAndExclusiveExpiry(t *testing.T) {
	i, config, b, payload, scope := anonymousUpgradeFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	for _, mode := range []string{"before-expiry", "at-expiry", "after-expiry", "revoked", "unavailable", "panic", "canceled", "cancel-after-lookup", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			c := config
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "before-expiry":
				c.Crypto.Clock = func() time.Time { return payload.ExpiresAt.Add(-time.Nanosecond) }
			case "at-expiry":
				c.Crypto.Clock = func() time.Time { return payload.ExpiresAt }
			case "after-expiry":
				c.Crypto.Clock = func() time.Time { return payload.ExpiresAt.Add(time.Nanosecond) }
			case "revoked":
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { return true, nil })
			case "unavailable":
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private-anonymous-diagnostic")
				})
			case "panic":
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private-anonymous-diagnostic") })
			case "canceled":
				cancel()
			case "cancel-after-lookup":
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { cancel(); return false, nil })
			case "deadline":
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
				c.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			}
			reader, err := NewIssuer(c)
			if err != nil {
				t.Fatal(err)
			}
			got, err := reader.PrepareAnonymousUpgradeConsumption(ctx, b, proof, grant.EnvelopeDigest(), 1, scope)
			if mode == "before-expiry" {
				want, e := i.grantPlan(b, b.UserID, grant, 1)
				if err != nil || e != nil || got != want {
					t.Fatal("unexpired original denied", err)
				}
				return
			}
			if err == nil || got != (kernel.CapabilityPlan{}) || strings.Contains(err.Error(), "private-anonymous-diagnostic") {
				t.Fatal("authority failure leaked or produced a plan")
			}
			var forbidden identity.ForbiddenError
			var unavailable identity.UnavailableError
			switch mode {
			case "unavailable", "panic":
				if !errors.As(err, &unavailable) {
					t.Fatal("availability classification lost", err)
				}
			case "canceled", "cancel-after-lookup":
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation classification lost", err)
				}
			case "deadline":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("deadline classification lost", err)
				}
			default:
				if !errors.As(err, &forbidden) {
					t.Fatal("denial classification lost", err)
				}
			}
		})
	}
}

func TestPrepareAnonymousUpgradeConsumptionRedactionAndConcurrentBorrow(t *testing.T) {
	i, config, b, payload, scope := anonymousUpgradeFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	want, err := i.grantPlan(b, b.UserID, grant, 1)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope); err != nil || got != want {
				t.Error("concurrent borrowed proof changed", err)
			}
		})
	}
	wg.Wait()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if got := fmt.Sprintf(verb, scope); strings.Contains(got, scope.SourceSessionID) || strings.Contains(got, scope.TargetSessionID) || strings.Contains(got, scope.SourceExpiresAt.Format(time.RFC3339Nano)) || strings.Contains(got, base64.RawURLEncoding.EncodeToString(scope.MergeDigest[:])) {
			t.Fatal("scope diagnostic leaked custody")
		}
	}
	if _, err := json.Marshal(scope); err == nil {
		t.Fatal("scope JSON exported custody")
	}
	if _, err := scope.MarshalText(); err == nil {
		t.Fatal("scope text exported custody")
	}
}

func TestPrepareAnonymousUpgradeConsumptionAuthenticatesActualSignature(t *testing.T) {
	i, config, b, payload, scope := anonymousUpgradeFixture(t)
	proof, grant := signedAnonymousUpgrade(t, config, payload)
	var token string
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error { token = string(raw); return nil }); err != nil {
		t.Fatal(err)
	}
	// Keep a parseable envelope while corrupting the first signature character.
	wire := []byte(token)
	n := strings.LastIndexByte(token, '.') + 1
	if n <= 0 || n >= len(wire) {
		t.Fatal("unexpected signed envelope framing")
	}
	if wire[n] == 'A' {
		wire[n] = 'B'
	} else {
		wire[n] = 'A'
	}
	corrupt, err := capability.ParseProof(string(wire), config.Crypto.Limits)
	if err != nil {
		t.Fatal("corrupted signature fixture was not parseable", err)
	}
	t.Cleanup(func() { _ = corrupt.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	for _, borrowed := range []capability.Proof{corrupt, {}} {
		got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, borrowed, grant.EnvelopeDigest(), 1, scope)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got != (kernel.CapabilityPlan{}) {
			t.Fatal("unauthenticated proof produced plan", err)
		}
	}
}

func FuzzAnonymousUpgradeConsumptionScope(f *testing.F) {
	f.Add("guest-session", "permanent-session", uint64(7), false, []byte{7})
	f.Add("", "\x00", uint64(0), true, []byte{})
	f.Fuzz(func(t *testing.T, source, target string, version uint64, remember bool, merge []byte) {
		if len(source) > 256 || len(target) > 256 || len(merge) > 256 {
			return
		}
		i, config, b, payload, scope := anonymousUpgradeFixture(t)
		proof, grant := signedAnonymousUpgrade(t, config, payload)
		scope.SourceSessionID, scope.TargetSessionID, scope.SourceVersion, scope.Remember = source, target, version, remember
		scope.MergeDigest = [32]byte{}
		copy(scope.MergeDigest[:], merge)
		got, err := i.PrepareAnonymousUpgradeConsumption(context.Background(), b, proof, grant.EnvelopeDigest(), 1, scope)
		valid := source == "guest-session" && target == "permanent-session" && version == 7 && !remember && scope.MergeDigest == ([32]byte{7})
		if valid && (err != nil || got.ProofFingerprint != grant.EnvelopeDigest()) {
			t.Fatal("exact original denied", err)
		}
		if !valid && (err == nil || got != (kernel.CapabilityPlan{})) {
			t.Fatal("hostile substituted scope admitted")
		}
	})
}
