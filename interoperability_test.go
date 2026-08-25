package capability_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

// RFC 4231 test case 6 verifies the HMAC primitive independently of token framing.
func TestHMACSHA256RFC4231Vector(t *testing.T) {
	key := mustHex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	message := []byte("Test Using Larger Than Block-Size Key - Hash Key First")
	want := mustHex(t, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
	signer, err := capability.NewHMACSHA256Signer("rfc4231", key)
	if err != nil {
		t.Fatalf("NewHMACSHA256Signer() error = %v", err)
	}
	signature, err := signer.Sign(context.Background(), message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if hex.EncodeToString(signature) != hex.EncodeToString(want) {
		t.Fatalf("Sign() = %x, want %x", signature, want)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatalf("NewHMACSHA256Verifier() error = %v", err)
	}
	if err := verifier.Verify(context.Background(), message, want); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// RFC 8032 section 7.1 test 1 verifies the Ed25519 primitive independently.
func TestEd25519RFC8032Vector(t *testing.T) {
	seed := mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	publicKey := ed25519.PublicKey(mustHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
	want := mustHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	signer, err := capability.NewEd25519Signer("rfc8032", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	signature, err := signer.Sign(context.Background(), nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if hex.EncodeToString(signature) != hex.EncodeToString(want) {
		t.Fatalf("Sign() = %x, want %x", signature, want)
	}
	verifier, err := capability.NewEd25519Verifier(publicKey)
	if err != nil {
		t.Fatalf("NewEd25519Verifier() error = %v", err)
	}
	if err := verifier.Verify(context.Background(), nil, want); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestPythonHMACGoldenToken(t *testing.T) {
	golden, err := os.ReadFile("testdata/v1-hmac.token")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	signer, _ := capability.NewHMACSHA256Signer("interop", key)
	payload := capability.Payload{
		Version: 1, Issuer: "interop", Audiences: []string{"service"}, Bearer: true,
		Resource: "objects/42", Operation: "read",
		IssuedAt: time.Unix(1_786_276_800, 0).UTC(), NotBefore: time.Unix(1_786_276_800, 0).UTC(),
		ExpiresAt: time.Unix(1_786_276_860, 0).UTC(), ID: "interop-capability",
	}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if token != strings.TrimSpace(string(golden)) {
		t.Fatalf("Issue() does not match independent Python golden token")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return decoded
}
