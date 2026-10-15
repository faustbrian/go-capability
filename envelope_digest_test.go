package capability_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/faustbrian/go-capability/v2"
)

func TestLegacyVerifyBindsSignatureAndRejectsForgedIdentity(t *testing.T) {
	var previous [32]byte
	for _, key := range [][]byte{
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("fedcba9876543210fedcba9876543210"),
	} {
		signer, err := capability.NewHMACSHA256Signer("same-key-id", key)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := capability.NewHMACSHA256Verifier(key)
		if err != nil {
			t.Fatal(err)
		}
		resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
			return capability.ResolvedKey{Issuer: validPayload().Issuer, Verifier: verifier}, nil
		})
		token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		options := capability.VerifyOptions{Issuer: validPayload().Issuer, Now: testNow, Limits: capability.DefaultLimits()}
		grant, err := capability.Verify(context.Background(), token, resolver, options)
		if err != nil || grant.EnvelopeDigest() != sha256.Sum256([]byte(token)) {
			t.Fatal("legacy verification lost exact envelope identity")
		}
		if grant.EnvelopeDigest() == previous {
			t.Fatal("different signatures collapsed to payload identity")
		}
		previous = grant.EnvelopeDigest()
		parts := strings.Split(token, ".")
		signature, err := base64.RawURLEncoding.DecodeString(parts[3])
		if err != nil {
			t.Fatal(err)
		}
		signature[0] ^= 1
		parts[3] = base64.RawURLEncoding.EncodeToString(signature)
		denied, err := capability.Verify(context.Background(), strings.Join(parts, "."), resolver, options)
		if err == nil || denied.EnvelopeDigest() != ([32]byte{}) {
			t.Fatal("forged signature exposed authenticated identity")
		}
	}
}

func TestVerifiedEnvelopeDigestPreservesOriginalProofIdentity(t *testing.T) {
	now := testNow
	service := newIdentityReviewService(t, &now)
	payload := validPayload()
	proof, reference, err := service.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.Verify(context.Background(), proof, "download", "download")
	if err != nil {
		t.Fatal(err)
	}
	digest := grant.EnvelopeDigest()
	if digest == ([32]byte{}) || digest == reference.Digest {
		t.Fatal("envelope identity must be nonzero and distinct from reference identity")
	}
	copyDigest := grant.EnvelopeDigest()
	copyDigest[0] ^= 1
	copyPayload := grant.Payload()
	copyPayload.Audiences[0] = "other"
	if grant.EnvelopeDigest() != digest {
		t.Fatal("caller mutation changed envelope identity")
	}
	again, err := service.Verify(context.Background(), proof, "download", "download")
	if err != nil || again.EnvelopeDigest() != digest {
		t.Fatal("verification consumed or changed the proof")
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, encoded []byte) error {
		if sha256.Sum256(encoded) != digest {
			t.Fatal("digest does not bind the complete original envelope")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if (capability.Grant{}).EnvelopeDigest() != ([32]byte{}) {
		t.Fatal("zero grant has envelope identity")
	}
}

func TestRejectedProofHasNoEnvelopeIdentity(t *testing.T) {
	now := testNow
	service := newIdentityReviewService(t, &now)
	proof, _, err := service.Issue(context.Background(), validPayload())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, purpose, audience string }{
		{"wrong purpose", "other", "download"},
		{"wrong audience", "download", "other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			grant, err := service.Verify(context.Background(), proof, capability.Purpose(test.purpose), test.audience)
			if err == nil || grant.EnvelopeDigest() != ([32]byte{}) {
				t.Fatal("rejected proof exposed verified identity")
			}
		})
	}
	now = validPayload().ExpiresAt
	grant, err := service.Verify(context.Background(), proof, "download", "download")
	if err == nil || grant.EnvelopeDigest() != ([32]byte{}) {
		t.Fatal("expired proof exposed verified identity")
	}
}
