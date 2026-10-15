package identitycapability

import (
	"context"
	"testing"
)

// BenchmarkPrepareIdentifierConsumption measures current HMAC verification and
// retained replay-plan derivation for one original, unconsumed proof. Issuer,
// key, command and proof construction are outside timing. The fixed clock and
// in-process key resolver exclude SQL, network, revocation IO and contention;
// this is not a durable consumption or end-to-end throughput measurement.
func BenchmarkPrepareIdentifierConsumption(b *testing.B) {
	issuer, command, proof := identifierConsumptionFixture(b)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		plan, err := issuer.PrepareIdentifierConsumption(ctx, command, proof, 1)
		if err != nil || plan.CapabilityID == "" || plan.ReplayDigest == ([32]byte{}) {
			b.Fatal("valid original consumption plan unavailable")
		}
	}
}
