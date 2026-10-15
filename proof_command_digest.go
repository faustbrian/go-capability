package capability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf8"
)

// CommandDigest binds the exact original canonical token, including signature,
// to a trusted coordinator's versioned secret key and field path without
// exposing or transferring custody. Supply a nonzero 32-byte key, an exact
// 1..4096-byte valid UTF-8 path and a positive maximumBytes chosen by the
// consumer's trusted transport profile. Parser limits remain unchanged; use
// Limits.MaxTokenBytes to retain a configured ingress profile. No normalization,
// key selection, signature/time/revocation check or consumption occurs.
//
// Framing matches identity-command-v1: ASCII "identity-command-secret-v1"
// without NUL, big-endian uint32 path byte length, path bytes, big-endian uint64
// token byte length and exact token bytes, authenticated with HMAC-SHA-256.
// The caller owns the outer command fingerprint, stored key version and
// retained-key recovery. This digest is sensitive correlation data, not a
// capability, reference digest, current authority or consumption receipt.
// Never expose a digest oracle or log the key, token or returned binding.
//
// Invalid key/path/maximum returns zero and ErrInvalidConfiguration. Zero,
// transferred or oversized proofs return zero and ErrInvalidToken, retaining
// original custody on failure. Copies share the existing lifetime: a snapshot
// acquired before Transfer may finish, but later observations fail. No callback
// or hashing runs under the custody lock. Work/allocation is bounded by the
// admitted token size; the private snapshot is cleared on every exit. Complete
// erasure of cryptographic state/runtime memory cannot be guaranteed. Concurrent
// calls and Transfer are safe; no IO, clocks, caches or goroutines are owned.
func (proof Proof) CommandDigest(key [32]byte, fieldPath string, maximumBytes int) ([32]byte, error) {
	pathLength := len(fieldPath)
	if pathLength < 1 || pathLength > 4096 {
		return [32]byte{}, ErrInvalidConfiguration
	}
	if key == ([32]byte{}) || !utf8.ValidString(fieldPath) || maximumBytes <= 0 {
		return [32]byte{}, ErrInvalidConfiguration
	}
	if err := proof.ValidateBounds(1, maximumBytes); err != nil {
		return [32]byte{}, err
	}
	// Custody only shrinks through terminal Transfer; after the bounds check it
	// cannot grow before this synchronized snapshot. Transfer between the two
	// observations makes snapshot fail rather than resurrecting an alias.
	token, err := proof.snapshot()
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(token)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-command-secret-v1"))
	var lengths [8]byte
	binary.BigEndian.PutUint32(lengths[:4], uint32(pathLength))
	_, _ = mac.Write(lengths[:4])
	_, _ = mac.Write([]byte(fieldPath))
	binary.BigEndian.PutUint64(lengths[:], uint64(len(token)))
	_, _ = mac.Write(lengths[:])
	_, _ = mac.Write(token)
	var digest [32]byte
	mac.Sum(digest[:0])
	return digest, nil
}
