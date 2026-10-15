package capability_test

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func ExampleNewService() {
	now := time.Unix(1786276800, 0).UTC()
	signer, err := capability.NewHMACSHA256Signer("example", make([]byte, 32))
	if err != nil {
		panic(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(make([]byte, 32))
	if err != nil {
		panic(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "example", ID: "example", Verifier: verifier}})
	if err != nil {
		panic(err)
	}
	service, err := capability.NewService(capability.ServiceConfig{Issuer: "example", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if err != nil {
		panic(err)
	}
	proof, reference, err := service.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "example", Audiences: []string{"service"}, Bearer: true, Resource: "document", Operation: "download", ExpiresAt: now.Add(time.Minute), ID: "example-capability", MaxUses: 1})
	if err != nil {
		panic(err)
	}
	grant, err := service.Verify(context.Background(), proof, reference.Purpose, "service")
	if err != nil {
		panic(err)
	}
	// This proves verification only. The protected transaction owner must
	// separately authorize and atomically consume the one-time effect.
	fmt.Println(grant.Payload().ID)
	err = proof.Transfer(context.Background(), func(_ context.Context, borrowed []byte) error {
		// Send synchronously through a confidential, no-store transport here.
		// Do not retain borrowed; explicit copies have caller-owned custody.
		fmt.Println(len(borrowed) > 0)
		return nil
	})
	fmt.Println(err == nil)
	// Output:
	// example-capability
	// true
	// true
}
