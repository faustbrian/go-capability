package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type accountLinkConsumptionPreparer interface {
	PrepareAccountLinkConsumption(context.Context, identity.Command, capability.Proof, uint32) (kernel.CapabilityPlan, error)
}

func prepareAccountLinkConsumption(t testing.TB, i *Issuer, ctx context.Context, command identity.Command, proof capability.Proof, version uint32) (kernel.CapabilityPlan, error) {
	t.Helper()
	p, ok := any(i).(accountLinkConsumptionPreparer)
	if !ok {
		t.Fatal("original account-link consumption preparation is missing")
	}
	return p.PrepareAccountLinkConsumption(ctx, command, proof, version)
}

func accountLinkConsumptionFixture(t testing.TB, mode identity.AccountLinkMode) (*Issuer, IssuerConfig, identity.Command, capability.Proof) {
	t.Helper()
	i, config, b, _ := issuerFixture(t)
	b.ActorID, b.ActorKind = identity.ActorID(b.UserID), authorization.SubjectUser
	b.OperationID, b.SchemaID, b.SchemaVersion = "identity.account.link-token", "identity-account", 1
	b.RecordID, b.LinkMode, b.PolicyID, b.PolicyVersion, b.CorrelationID = "linked-account", mode, "identity", 1, string(b.CommandID)
	c := identity.AccountLinkCommand{Binding: b, SessionID: "session", SessionVersion: 1, Change: identity.AccountLinkChange{Mode: mode, Account: identity.Account{ID: "linked-account", TenantID: b.TenantID, UserID: b.UserID, Provider: "configured-provider", Issuer: "https://provider.example.test", Subject: "provider-subject", Version: 1}, ExpectedUserVersion: 1, ExpectedCredentialVersion: 1, ExpectedSocialLinkVersion: 1}}
	if mode == identity.AccountLinkAdministrative {
		c.Change.Reason, c.Binding.ActorID = "approved-recovery", "administrator"
	}
	if mode == identity.AccountLinkImplicit {
		c.Binding.ActorID, c.Binding.ActorKind = "trusted-provider", authorization.SubjectServiceAccount
		c.SessionID, c.SessionVersion = "", 0
		id, err := identity.NewPreAuthTransactionID()
		if err != nil {
			t.Fatal(err)
		}
		c.PreAuthTransactionID = id
		c.Change.MatchedIdentifier, c.Change.VerifiedCanonicalIdentifier = "verified-email", "verified@example.test"
		c.Change.ExpectedIdentifierAuthorityVersion, c.Change.ExpectedIdentifierVersion, c.Change.ExpectedVerificationVersion = 1, 1, 1
	}
	now := config.Crypto.Clock()
	payload, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: c, Issuer: config.Crypto.Issuer, Audience: config.Audience, ID: "link-proof", IssuedAt: now, ExpiresAt: now.Add(4 * time.Minute)})
	if err != nil {
		t.Fatal("canonical intent", err)
	}
	proof, _, err := i.service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	c.Proof, err = i.service.Verify(context.Background(), proof, capability.Purpose(b.OperationID), config.Audience)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewAccountLinkCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	return i, config, command, proof
}

func TestPrepareAccountLinkConsumptionPreservesOriginalCustody(t *testing.T) {
	i, config, command, proof := accountLinkConsumptionFixture(t, identity.AccountLinkExplicit)
	plan, err := prepareAccountLinkConsumption(t, i, context.Background(), command, proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := command.LinkAccount()
	payload, envelope := spec.Proof.Payload(), spec.Proof.EnvelopeDigest()
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
	want := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: "identity.account.link-token", ReplayKeyVersion: 1, ReplayDigest: replay, ProofFingerprint: envelope, ExpiresAt: payload.ExpiresAt, MaxUses: 1}
	if plan != want {
		t.Fatal("original signed/replay identity changed")
	}
	config.CurrentReplayKeyVersion, config.RetainedReplayKeys = 3, map[uint32][32]byte{1: {1}, 3: {3}}
	rotated, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got, e := prepareAccountLinkConsumption(t, rotated, context.Background(), command, proof, 1); e != nil || got != want {
				t.Error("repeat/rotation replaced original input", e)
			}
		})
	}
	wg.Wait()
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if sha256.Sum256(raw) != envelope {
			t.Error("original envelope replaced")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only preparation transferred custody", err)
	}
	if out, err := prepareAccountLinkConsumption(t, i, context.Background(), command, proof, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("transferred proof admitted")
	}
}

func TestPrepareAccountLinkConsumptionRejectsSubstitutionAndUnsupportedProfiles(t *testing.T) {
	i, _, command, proof := accountLinkConsumptionFixture(t, identity.AccountLinkExplicit)
	_, _, _, other := accountLinkConsumptionFixture(t, identity.AccountLinkExplicit)
	for _, p := range []capability.Proof{{}, other} {
		out, err := prepareAccountLinkConsumption(t, i, context.Background(), command, p, 1)
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || out != (kernel.CapabilityPlan{}) {
			t.Fatal("substituted original proof admitted", err)
		}
	}
	for _, mode := range []identity.AccountLinkMode{identity.AccountLinkAdministrative, identity.AccountLinkImplicit} {
		_, _, otherCommand, otherProof := accountLinkConsumptionFixture(t, mode)
		if out, err := prepareAccountLinkConsumption(t, i, context.Background(), otherCommand, otherProof, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("unsupported link profile admitted")
		}
	}
	enriched, err := identity.NewAccountLinkCounterCommand(command, identity.AccountLinkCounterContext{Network: "192.0.2.10", PreparedAt: time.Now().UTC().Truncate(time.Microsecond), KeyVersions: []uint32{1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []identity.Command{{}, enriched} {
		if out, err := prepareAccountLinkConsumption(t, i, context.Background(), c, proof, 1); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("noncanonical bare command admitted")
		}
	}
	for _, version := range []uint32{0, 9} {
		if out, err := prepareAccountLinkConsumption(t, i, context.Background(), command, proof, version); err == nil || out != (kernel.CapabilityPlan{}) {
			t.Fatal("unretained replay version admitted")
		}
	}
	if out, err := prepareAccountLinkConsumption(t, nil, context.Background(), command, proof, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("nil issuer admitted")
	}
	if out, err := prepareAccountLinkConsumption(t, i, nilContextForTest(), command, proof, 1); err == nil || out != (kernel.CapabilityPlan{}) {
		t.Fatal("nil context admitted")
	}
}

func TestPrepareAccountLinkConsumptionRechecksConfiguredAuthority(t *testing.T) {
	_, originalConfig, command, proof := accountLinkConsumptionFixture(t, identity.AccountLinkExplicit)
	for _, mode := range []string{"expired", "foreign-key", "foreign-issuer", "foreign-audience", "revoked", "unavailable", "panic", "zero-clock", "cancelled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			config := originalConfig
			ctx := context.Background()
			spec, _ := command.LinkAccount()
			switch mode {
			case "expired":
				config.Crypto.Clock = func() time.Time { return spec.Proof.Payload().ExpiresAt }
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
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) {
					return false, errors.New("private diagnostics")
				})
			case "panic":
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(context.Context, capability.RevocationQuery) (bool, error) { panic("private diagnostics") })
			case "zero-clock":
				config.Crypto.Clock = func() time.Time { return time.Time{} }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(ctx context.Context, _ capability.RevocationQuery) (bool, error) {
					<-ctx.Done()
					return false, ctx.Err()
				})
			}
			i, err := NewIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			out, err := prepareAccountLinkConsumption(t, i, ctx, command, proof, 1)
			var denied identity.ForbiddenError
			var unavailable identity.UnavailableError
			var cancelled identity.CancelledError
			var deadline identity.DeadlineExceededError
			valid := errors.As(err, &denied)
			switch mode {
			case "unavailable", "panic", "zero-clock":
				valid = errors.As(err, &unavailable)
			case "cancelled":
				valid = errors.As(err, &cancelled)
			case "deadline":
				valid = errors.As(err, &deadline)
			}
			if !valid || out != (kernel.CapabilityPlan{}) {
				t.Fatal("configured authority failure admitted or misclassified", err)
			}
		})
	}
}
