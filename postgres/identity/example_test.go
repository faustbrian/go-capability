package identitycapability_test

import (
	"fmt"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
)

func ExampleNewParticipant() {
	p := identitycapability.NewParticipant()
	d := p.Descriptor()
	fmt.Println(d.Owner, d.ContractID, d.Version)
	// Output: capability/postgres capability.one-use 1
}
