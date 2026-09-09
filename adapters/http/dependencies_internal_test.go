package capabilityhttp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

func TestNewVerifierRejectsInvalidDependencies(t *testing.T) {
	profile := capability.URLProfile{
		Name:               "relative-v1",
		SignatureParameter: "cap",
		AllowRelative:      true,
	}
	clock := dependencyClock{now: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)}
	resolver := capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{}, nil
	})

	tests := map[string]VerifierOptions{
		"nil resolver": {
			Profile: profile,
			Clock:   clock,
			Limits:  capability.DefaultLimits(),
		},
		"nil clock": {
			Profile:  profile,
			Resolver: resolver,
			Limits:   capability.DefaultLimits(),
		},
		"negative skew": {
			Profile:  profile,
			Resolver: resolver,
			Clock:    clock,
			Skew:     -time.Nanosecond,
			Limits:   capability.DefaultLimits(),
		},
	}

	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifier(options); !errors.Is(err, capability.ErrInvalidConfiguration) {
				t.Fatalf("NewVerifier() error = %v, want %v", err, capability.ErrInvalidConfiguration)
			}
		})
	}
}

type dependencyClock struct{ now time.Time }

func (clock dependencyClock) Now() time.Time { return clock.now }
