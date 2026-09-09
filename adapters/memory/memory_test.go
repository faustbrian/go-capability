//nolint:staticcheck // Compatibility proof intentionally imports the deprecated path.
package capabilitymemory_test

//lint:file-ignore SA1019 Compatibility proof intentionally imports the deprecated path.

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-capability/adapters/memory"
	legacy "github.com/faustbrian/go-capability/memory"
)

func TestSuccessorPreservesMemoryCompatibility(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	store, err := capabilitymemory.NewConsumptionStore(fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	request := capability.Consumption{
		CapabilityID: "cap-42", MaxUses: 1, ExpiresAt: now.Add(time.Minute),
	}
	result, err := store.Consume(context.Background(), request)
	if err != nil || result.Use != 1 || result.Remaining != 0 {
		t.Fatalf("Consume() = %#v, %v", result, err)
	}
	compatibilityStore, err := legacy.NewConsumptionStore(fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	compatibilityResult, err := compatibilityStore.Consume(context.Background(), request)
	if err != nil || !reflect.DeepEqual(compatibilityResult, result) {
		t.Fatalf("compatibility Consume() = %#v, %v", compatibilityResult, err)
	}
	if reflect.TypeOf(compatibilityStore) == reflect.TypeOf(store) {
		t.Fatal("successor and compatibility store identities are not distinct")
	}
	if got := reflect.TypeOf(store).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/adapters/memory" {
		t.Fatalf("ConsumptionStore package identity = %q", got)
	}
	if got := reflect.TypeOf(compatibilityStore).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/memory" {
		t.Fatalf("compatibility ConsumptionStore package identity = %q", got)
	}

	revocations := capabilitymemory.NewRevocations()
	compatibilityRevocations := legacy.NewRevocations()
	if err := compatibilityRevocations.RevokeCapability(context.Background(), "issuer", "cap-42"); err != nil {
		t.Fatal(err)
	}
	query := capability.RevocationQuery{
		Issuer: "issuer", CapabilityID: "cap-42",
	}
	if err := revocations.RevokeCapability(context.Background(), "issuer", "cap-42"); err != nil {
		t.Fatal(err)
	}
	revoked, err := revocations.Check(context.Background(), query)
	compatibilityRevoked, compatibilityErr := compatibilityRevocations.Check(context.Background(), query)
	if err != nil || compatibilityErr != nil || !revoked || compatibilityRevoked != revoked {
		t.Fatalf("Check() = (%t, %v), compatibility = (%t, %v)", revoked, err, compatibilityRevoked, compatibilityErr)
	}
	if reflect.TypeOf(compatibilityRevocations) == reflect.TypeOf(revocations) {
		t.Fatal("successor and compatibility revocation identities are not distinct")
	}
	if got := reflect.TypeOf(revocations).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/adapters/memory" {
		t.Fatalf("Revocations package identity = %q", got)
	}
	if got := reflect.TypeOf(compatibilityRevocations).Elem().PkgPath(); got != "github.com/faustbrian/go-capability/memory" {
		t.Fatalf("compatibility Revocations package identity = %q", got)
	}
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }
