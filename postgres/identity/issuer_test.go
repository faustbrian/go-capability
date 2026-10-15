package identitycapability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func issuerFixture(t testing.TB) (*Issuer, IssuerConfig, identity.CommandBinding, capability.Payload) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	signing := []byte("0123456789abcdef0123456789abcdef")
	signer, err := capability.NewHMACSHA256Signer("signing-v1", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	c := IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 2, RetainedReplayKeys: map[uint32][32]byte{1: {1}, 2: {2}}, PreparationTimeout: time.Second}
	p, err := NewIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "user"}
	v := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: "user", Tenant: "tenant", Resource: "identifier", Operation: "identity.identifier.verify", ExpiresAt: now.Add(5 * time.Minute), MaxUses: 1}
	return p, c, b, v
}

func TestIssuerOwnsOriginalEnvelopeAndReplay(t *testing.T) {
	i, c, b, v := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.Grants[0].ReplayKeyVersion != 2 {
		t.Fatal("owned metadata absent", err)
	}
	metadata := plan.Grants[0]
	plan.Grants[0].ReplayDigest = [32]byte{}
	delete(c.RetainedReplayKeys, 2)
	frozen, _ := p.Plan()
	if frozen.Grants[0] != metadata {
		t.Fatal("caller mutated custody")
	}
	var original [32]byte
	if err := p.TransferForDelivery(context.Background(), 0, func(_ context.Context, token []byte) error { original = sha256.Sum256(token); return nil }); err != nil {
		t.Fatal(err)
	}
	if metadata.ProofFingerprint != original || metadata.ReplayDigest == original {
		t.Fatal("wrong cryptographic domains")
	}
	if err := p.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("second disclosure"); return nil }); err == nil {
		t.Fatal("revealed twice")
	}
	if i.Stage(context.Background(), identitypostgres.Work{}, p) == nil {
		t.Fatal("fabricated transaction accepted")
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("serialized custody")
	}
	if strings.Contains(fmt.Sprintf("%#v", p), metadata.CapabilityID) {
		t.Fatal("format disclosure")
	}
	q, err := i.Prepare(context.Background(), b, []capability.Payload{v})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := q.Plan()
	if other.Grants[0].CapabilityID == metadata.CapabilityID || other.Grants[0].ReplayDigest == metadata.ReplayDigest {
		t.Fatal("reconstructed existing issuance")
	}
}

func TestIssuerRejectsForeignOrUnboundedPreparation(t *testing.T) {
	i, _, b, v := issuerFixture(t)
	for _, change := range []func(*capability.Payload){
		func(p *capability.Payload) { p.ID = "caller-id" },
		func(p *capability.Payload) { p.Subject = "foreign" },
		func(p *capability.Payload) { p.Tenant = "foreign" },
		func(p *capability.Payload) { p.Bearer = true },
		func(p *capability.Payload) { p.MaxUses = 2 },
		func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Nanosecond) },
	} {
		bad := v
		change(&bad)
		if _, err := i.Prepare(context.Background(), b, []capability.Payload{bad}); err == nil {
			t.Fatal("unsafe input admitted")
		}
	}
	for _, inputs := range [][]capability.Payload{nil, make([]capability.Payload, 17)} {
		if _, err := i.Prepare(context.Background(), b, inputs); err == nil {
			t.Fatal("unbounded batch admitted")
		}
	}
	if _, err := i.Prepare(nil, b, []capability.Payload{v}); err == nil {
		t.Fatal("nil context accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := i.Prepare(cancelled, b, []capability.Payload{v}); err == nil {
		t.Fatal("cancelled signing accepted")
	}
	if err := i.PersistCapabilityIssuance(context.Background(), identitypostgres.CapabilityIssuanceWork{}); err == nil {
		t.Fatal("fabricated persistence accepted")
	}
	var zero PreparedIssuance
	if _, err := zero.Plan(); err == nil {
		t.Fatal("zero prepared issuance")
	}
}

func TestIssuerRejectsCancellationAfterSuccessfulFinalVerification(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		for _, count := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s-%d", mode, count), func(t *testing.T) {
				_, config, binding, payload := issuerFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				config.Crypto.Revocations = capability.RevocationCheckerFunc(func(call context.Context, _ capability.RevocationQuery) (bool, error) {
					calls++
					if calls == count {
						if mode == "deadline" {
							<-call.Done()
						} else {
							cancel()
						}
					}
					// Successful authority lookup cannot renew the expired invocation.
					return false, nil
				})
				issuer, err := NewIssuer(config)
				if err != nil {
					t.Fatal(err)
				}
				inputs := make([]capability.Payload, count)
				for index := range inputs {
					inputs[index] = payload
				}
				prepared, err := issuer.Prepare(ctx, binding, inputs)
				var expected error = identity.CancelledError{}
				if mode == "deadline" {
					expected = identity.DeadlineExceededError{}
				}
				if calls != count || !errors.Is(err, expected) || prepared.state != nil {
					t.Fatalf("final verification calls=%d, classified error=%t, retained custody=%t", calls, errors.Is(err, expected), prepared.state != nil)
				}
				transferred := false
				err = prepared.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error {
					transferred = true
					return nil
				})
				if err == nil || transferred {
					t.Fatal("failed preparation retained transferable proof")
				}
			})
		}
	}
}
