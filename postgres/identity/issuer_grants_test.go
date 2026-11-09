package identitycapability

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type preparedGrantReader interface {
	Grants() ([]capability.Grant, error)
}

func preparedGrants(t testing.TB, p PreparedIssuance) ([]capability.Grant, error) {
	t.Helper()
	reader, ok := any(p).(preparedGrantReader)
	if !ok {
		t.Fatal("prepared original-grant projection is missing")
	}
	return reader.Grants()
}

// The service boundary includes the signer, resolver, clock and revocation
// collaborators. None may run when projecting already authenticated grants.
type grantsNoService struct{}

func (grantsNoService) Issue(context.Context, capability.Payload) (capability.Proof, capability.Reference, error) {
	panic("grant projection invoked issuing service")
}
func (grantsNoService) Verify(context.Context, capability.Proof, capability.Purpose, string) (capability.Grant, error) {
	panic("grant projection invoked verification service")
}

func TestPreparedIssuanceGrantsPreserveOriginalAcrossCheckpointAndRestore(t *testing.T) {
	i, config, b, payload := issuerFixture(t)
	payload.Caveats = map[string]string{"original.scope": "exact-target"}
	second := payload
	second.Resource = "second-identifier"
	p, err := i.Prepare(context.Background(), b, []capability.Payload{payload, second})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := p.Plan()
	want := append([]capability.Grant(nil), p.state.grants...)
	i.service = grantsNoService{}
	assertOriginal := func(t *testing.T, value PreparedIssuance) {
		t.Helper()
		grants, err := preparedGrants(t, value)
		if err != nil || !reflect.DeepEqual(grants, want) {
			t.Fatal("original grant order, signed payload or envelope changed", err)
		}
		for n, grant := range grants {
			if grant.EnvelopeDigest() != plan.Grants[n].ProofFingerprint || grant.Payload().ID != plan.Grants[n].CapabilityID || grant.Payload().ExpiresAt != plan.Grants[n].ExpiresAt {
				t.Fatal("grant projection disagrees with original immutable plan")
			}
		}
		mutable := grants[0].Payload()
		mutable.Audiences[0], mutable.Caveats["original.scope"] = "foreign", "foreign"
		grants[0] = capability.Grant{}
		again, err := preparedGrants(t, value)
		if err != nil || !reflect.DeepEqual(again, want) {
			t.Fatal("caller mutation changed retained grant or payload", err)
		}
	}
	assertOriginal(t, p)
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), p, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOriginal(t, p)
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil {
		t.Fatal(err)
	}
	assertOriginal(t, restored)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { assertOriginal(t, restored) })
	}
	wg.Wait()
	if restored.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error {
		t.Fatal("projection reopened restored bearer disclosure")
		return nil
	}) == nil {
		t.Fatal("projection renewed restored proof lifetime")
	}
	if _, err := codec.CheckpointPreparation(context.Background(), p, 8, nil); err == nil {
		t.Fatal("projection changed original checkpoint generation")
	}
}

func TestPreparedIssuanceGrantsRejectIncompleteOrFailedCustody(t *testing.T) {
	var invalid identity.InvalidInputError
	if grants, err := preparedGrants(t, PreparedIssuance{}); !errors.As(err, &invalid) || grants != nil {
		t.Fatal("zero preparation exposed grants", err)
	}
	i, config, b, payload := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{payload, payload})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*preparedIssuance){
		"failed":          func(s *preparedIssuance) { s.preparationFailed = true },
		"missing owner":   func(s *preparedIssuance) { s.owner = nil },
		"missing grant":   func(s *preparedIssuance) { s.grants = nil },
		"partial grants":  func(s *preparedIssuance) { s.grants = s.grants[:1] },
		"missing plan":    func(s *preparedIssuance) { s.plan.Grants = nil },
		"zero grant":      func(s *preparedIssuance) { s.grants[1] = capability.Grant{} },
		"changed subject": func(s *preparedIssuance) { s.binding.UserID = "foreign" },
		"changed ID":      func(s *preparedIssuance) { s.plan.Grants[1].CapabilityID += "-foreign" },
		"changed purpose": func(s *preparedIssuance) { s.plan.Grants[1].Purpose = "foreign.operation" },
		"changed replay":  func(s *preparedIssuance) { s.plan.Grants[1].ReplayDigest[0] ^= 1 },
		"changed proof":   func(s *preparedIssuance) { s.plan.Grants[1].ProofFingerprint[0] ^= 1 },
		"changed expiry":  func(s *preparedIssuance) { s.plan.Grants[1].ExpiresAt = s.plan.Grants[1].ExpiresAt.Add(time.Second) },
		"changed uses":    func(s *preparedIssuance) { s.plan.Grants[1].MaxUses++ },
		"foreign owner": func(s *preparedIssuance) {
			owner := *i
			owner.keys = map[uint32][32]byte{2: {9}}
			s.owner = &owner
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := *p.state
			state.grants = append([]capability.Grant(nil), p.state.grants...)
			state.plan.Grants = append([]identitypostgres.CapabilityPlan(nil), p.state.plan.Grants...)
			mutate(&state)
			if grants, err := preparedGrants(t, PreparedIssuance{state: &state}); !errors.As(err, &invalid) || grants != nil {
				t.Fatal("inconsistent preparation exposed partial grants", err)
			}
		})
	}
	codec, _ := preparationFixture(t, i, config)
	if _, err := codec.CheckpointPreparation(context.Background(), p, 1, func(context.Context, uint16, []byte) error { return errors.New("encryption unavailable") }); err == nil {
		t.Fatal("failed checkpoint retained usable custody")
	}
	if grants, err := preparedGrants(t, p); !errors.As(err, &invalid) || grants != nil {
		t.Fatal("failed checkpoint exposed grants", err)
	}
}

func TestPreparedIssuanceGrantsDoNotTransferOrRenewProof(t *testing.T) {
	i, _, b, payload := issuerFixture(t)
	p, err := i.Prepare(context.Background(), b, []capability.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := p.Plan()
	if _, err := preparedGrants(t, p); err != nil {
		t.Fatal(err)
	}
	if err := p.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("grant projection consumed transferable proof", err)
	}
	grants, err := preparedGrants(t, p)
	if err != nil || len(grants) != 1 || grants[0].EnvelopeDigest() != want.Grants[0].ProofFingerprint || grants[0].Payload().ExpiresAt != want.Grants[0].ExpiresAt {
		t.Fatal("proof transfer changed original grant metadata", err)
	}
	if p.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { t.Fatal("projection reopened transferred proof"); return nil }) == nil {
		t.Fatal("projection renewed proof custody")
	}
}
