package capabilitymemory_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-capability/adapters/memory"
)

func ExampleNewConsumptionStore() {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	store, _ := capabilitymemory.NewConsumptionStore(fixedClock{now: now})
	result, err := store.Consume(context.Background(), capability.Consumption{Issuer: "ordinary-issuer",
		CapabilityID: "cap-42", MaxUses: 1, ExpiresAt: now.Add(time.Minute),
	})
	fmt.Println(result.Use, result.Remaining, err == nil)
	// Output: 1 0 true
}

func ExampleNewRevocationsWithLimits() {
	store, err := capabilitymemory.NewRevocationsWithLimits(capabilitymemory.StoreLimits{MaxRecords: 1, MaxStringBytes: 16})
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	if err := store.RevokeCapability(ctx, "issuer", "cap-1"); err != nil {
		panic(err)
	}
	// Capacity failure must be handled; it does not revoke the requested key.
	err = store.RevokeKey(ctx, "issuer", "key-1")
	fmt.Println(errors.Is(err, capability.ErrCapacity))
	revoked, err := store.Check(ctx, capability.RevocationQuery{Issuer: "issuer", CapabilityID: "cap-1"})
	fmt.Println(revoked, err == nil)
	// Output:
	// true
	// true true
}
