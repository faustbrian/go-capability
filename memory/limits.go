package memory

import capabilitymemory "github.com/faustbrian/go-capability/adapters/memory"

// StoreLimits preserves the canonical finite process-local budget contract.
type StoreLimits = capabilitymemory.StoreLimits

// DefaultStoreLimits returns the canonical finite defaults.
func DefaultStoreLimits() StoreLimits { return capabilitymemory.DefaultStoreLimits() }
