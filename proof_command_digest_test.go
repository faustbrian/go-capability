package capability_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/faustbrian/go-capability/v2"
)

func commandDigestProof(t testing.TB) (capability.Proof, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/v1-hmac.token")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	proof, err := capability.ParseProof(token, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return proof, token
}

func TestProofCommandDigestMatchesOriginalCoordinatorIntent(t *testing.T) {
	proof, token := commandDigestProof(t)
	key, path := [32]byte{1}, "password-reset-proof"
	// Independent oracle uses the documented coordinator frame, not its helper.
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-command-secret-v1"))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(path))))
	mac.Write([]byte(path))
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(token))))
	mac.Write([]byte(token))
	var want [32]byte
	copy(want[:], mac.Sum(nil))
	for range 3 {
		got, err := proof.CommandDigest(key, path, len(token))
		if err != nil || got != want {
			t.Fatal("original exact intent lost", err)
		}
	}
	for _, input := range []struct {
		key  [32]byte
		path string
	}{{[32]byte{2}, path}, {key, path + "x"}, {key, "é"}, {key, "e\u0301"}} {
		got, err := proof.CommandDigest(input.key, input.path, 16<<10)
		if err != nil || got == want {
			t.Fatal("key/path intent collapsed", err)
		}
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if string(raw) != token {
			t.Fatal("fingerprinting changed proof")
		}
		if got, err := proof.CommandDigest(key, path, 16<<10); !errors.Is(err, capability.ErrInvalidToken) || got != ([32]byte{}) {
			t.Fatal("transferred proof retained fingerprint authority", err)
		}
		return nil
	}); err != nil {
		t.Fatal("fingerprinting transferred proof", err)
	}
}

func TestProofCommandDigestRejectsInvalidBoundsAndConfiguration(t *testing.T) {
	proof, token := commandDigestProof(t)
	for _, input := range []struct {
		key     [32]byte
		path    string
		maximum int
	}{
		{[32]byte{}, "reset", 16384}, {[32]byte{1}, "", 16384}, {[32]byte{1}, strings.Repeat("x", 4097), 16384}, {[32]byte{1}, "\xff", 16384}, {[32]byte{1}, "reset", 0}, {[32]byte{1}, "reset", -1},
	} {
		got, err := proof.CommandDigest(input.key, input.path, input.maximum)
		if !errors.Is(err, capability.ErrInvalidConfiguration) || got != ([32]byte{}) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	for _, original := range []capability.Proof{{}, proof} {
		got, err := original.CommandDigest([32]byte{1}, "reset", len(token)-1)
		if !errors.Is(err, capability.ErrInvalidToken) || got != ([32]byte{}) {
			t.Fatal("zero or oversized proof accepted", err)
		}
	}
	if got, err := proof.CommandDigest([32]byte{1}, strings.Repeat("x", 4096), len(token)); err != nil || got == ([32]byte{}) {
		t.Fatal("exact path/token limit rejected", err)
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("invalid digest attempt consumed custody", err)
	}
}

func TestProofCommandDigestConcurrentTransfer(t *testing.T) {
	proof, token := commandDigestProof(t)
	want, err := proof.CommandDigest([32]byte{1}, "reset", len(token))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Go(func() {
			<-start
			for range 32 {
				got, err := proof.CommandDigest([32]byte{1}, "reset", len(token))
				if err == nil && got != want || err != nil && (!errors.Is(err, capability.ErrInvalidToken) || got != ([32]byte{})) {
					t.Error("concurrent lifetime produced invalid observation")
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
			t.Error(err)
		}
	})
	close(start)
	wg.Wait()
	if got, err := proof.CommandDigest([32]byte{1}, "reset", len(token)); !errors.Is(err, capability.ErrInvalidToken) || got != ([32]byte{}) {
		t.Fatal("terminal alias resurrected", err)
	}
}

func TestProofCommandDigestPreservesConfiguredIngressAndSignatureIdentity(t *testing.T) {
	var previous [32]byte
	for _, signingKey := range []string{strings.Repeat("x", 32), strings.Repeat("y", 32)} {
		signer, err := capability.NewHMACSHA256Signer("same-key-id", []byte(signingKey))
		if err != nil {
			t.Fatal(err)
		}
		token, err := capability.Issue(context.Background(), validPayload(), signer, capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		proof, err := capability.ParseProof(token, capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		digest, err := proof.CommandDigest([32]byte{1}, "reset", 16<<10)
		if err != nil || digest == previous {
			t.Fatal("signatures collapsed to payload identity", err)
		}
		previous = digest
	}
	for _, size := range []int{5000, 20000} {
		limits := capability.DefaultLimits()
		limits.MaxTokenBytes, limits.MaxCaveatBytes = 32<<10, size
		payload := validPayload()
		payload.Caveats = map[string]string{"synthetic": strings.Repeat("x", size)}
		signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
		if err != nil {
			t.Fatal(err)
		}
		token, err := capability.Issue(context.Background(), payload, signer, limits)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := capability.ParseProof(token, limits)
		if err != nil {
			t.Fatal(err)
		}
		if len(token) <= 4096 {
			t.Fatal("fixture did not cross consumer boundary")
		}
		if digest, err := proof.CommandDigest([32]byte{1}, "reset", len(token)); err != nil || digest == ([32]byte{}) {
			t.Fatal("configured ingress narrowed", err)
		}
		if digest, err := proof.CommandDigest([32]byte{1}, "reset", 4096); !errors.Is(err, capability.ErrInvalidToken) || digest != ([32]byte{}) {
			t.Fatal("explicit consumer bound ignored", err)
		}
		_, err = capability.ParseProof(token, capability.DefaultLimits())
		if len(token) > 16<<10 && !errors.Is(err, capability.ErrInvalidToken) {
			t.Fatal("default parser accepted oversize proof", err)
		}
	}
}

func TestProofCommandDigestDoesNotCheckAuthority(t *testing.T) {
	now := testNow
	service := newIdentityReviewService(t, &now)
	proof, _, err := service.Issue(context.Background(), validPayload())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := proof.CommandDigest([32]byte{1}, "reset", 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	now = validPayload().ExpiresAt
	if _, err := service.Verify(context.Background(), proof, "download", "download"); !errors.Is(err, capability.ErrExpired) {
		t.Fatal("expired control not denied", err)
	}
	if got, err := proof.CommandDigest([32]byte{1}, "reset", 16<<10); err != nil || got != digest {
		t.Fatal("expired original intent not retained", err)
	}
	_, token := commandDigestProof(t)
	parts := strings.Split(token, ".")
	first := byte('A')
	if parts[3][0] == first {
		first = 'B'
	}
	parts[3] = string(first) + parts[3][1:]
	forged, err := capability.ParseProof(strings.Join(parts, "."), capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := forged.CommandDigest([32]byte{1}, "reset", 16<<10); err != nil || digest == ([32]byte{}) {
		t.Fatal("fingerprint inferred signature authority", err)
	}
	now = testNow
	if _, err := service.Verify(context.Background(), forged, "download", "download"); err == nil {
		t.Fatal("forged proof became authority")
	}
}
