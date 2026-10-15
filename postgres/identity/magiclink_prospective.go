package identitycapability

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/faustbrian/go-capability/v2"
)

// Structural profile validation is not selection or possession authority.
// Staging separately authenticates the same Work's native prospective fence.
func prospectiveMagicLinkProfile(p capability.Payload) bool {
	if p.Caveats["magiclink.prospective"] != "1" || p.Caveats["magiclink.intent"] != "signup-if-allowed" || !issuerText(p.Caveats["magiclink.identifier"]) || len(p.Caveats["magiclink.canonical-email"]) == 0 || len(p.Caveats["magiclink.canonical-email"]) > 512 || p.Resource != "identity.magiclink/"+p.Caveats["magiclink.identifier"] {
		return false
	}
	digest := p.Caveats["magiclink.creation-digest"]
	policy := p.Caveats["magiclink.email-policy-version"]
	// Check both hostile widths before decoding or parsing either value.
	if len(digest) != 64 || len(policy) == 0 || len(policy) > 20 {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 || strings.ToLower(digest) != digest || [32]byte(decoded) == ([32]byte{}) {
		return false
	}
	version, err := strconv.ParseUint(policy, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != policy {
		return false
	}
	for _, key := range []string{"magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
		if p.Caveats[key] != "1" {
			return false
		}
	}
	return true
}
