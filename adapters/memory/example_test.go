package capabilitymemory_test

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-capability/adapters/memory"
)

func ExampleNewConsumptionStore() {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	store, _ := capabilitymemory.NewConsumptionStore(fixedClock{now: now})
	result, err := store.Consume(context.Background(), capability.Consumption{
		CapabilityID: "cap-42", MaxUses: 1, ExpiresAt: now.Add(time.Minute),
	})
	fmt.Println(result.Use, result.Remaining, err == nil)
	// Output: 1 0 true
}
