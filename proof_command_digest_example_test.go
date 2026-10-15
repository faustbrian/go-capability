package capability_test

import (
	"fmt"
	"os"
	"strings"

	"github.com/faustbrian/go-capability/v2"
)

func ExampleProof_CommandDigest() {
	// The published synthetic fixture and demonstration key are not production
	// credentials. Trusted composition supplies its private versioned key.
	bytes, err := os.ReadFile("testdata/v1-hmac.token")
	if err != nil {
		return
	}
	proof, err := capability.ParseProof(strings.TrimSpace(string(bytes)), capability.DefaultLimits())
	if err != nil {
		return
	}
	digest, err := proof.CommandDigest([32]byte{1}, "password-reset-proof", capability.DefaultLimits().MaxTokenBytes)
	fmt.Println(err == nil && digest != ([32]byte{}))
	fmt.Println(proof.ValidateBounds(32, 4096) == nil)
	// Output:
	// true
	// true
}
