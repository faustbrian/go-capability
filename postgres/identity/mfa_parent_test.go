package identitycapability

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func TestMFAMagicLinkParentRejectsMissingCustody(t *testing.T) {
	i, _, _, _ := issuerFixture(t)
	for _, issuer := range []*Issuer{nil, i} {
		parent, err := issuer.ReadMFAMagicLinkParent(context.Background(), nil, capability.Proof{}, "parent", [32]byte{1}, time.Now())
		if err == nil || parent != (MFAMagicLinkParent{}) {
			t.Fatal("missing parent custody retained metadata")
		}
	}
	var parent MFAMagicLinkParent
	if _, err := parent.Bindings(); err == nil || parent.MatchPayload(capability.Payload{}) == nil {
		t.Fatal("zero parent admitted reconstructed payload")
	}
	if fmt.Sprintf("%#v", parent) != "identitycapability.MFAMagicLinkParent(redacted)" {
		t.Fatal("parent custody not redacted")
	}
	if _, err := json.Marshal(parent); err == nil {
		t.Fatal("parent custody serialized")
	}
}
