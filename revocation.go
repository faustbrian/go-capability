package capability

import (
	"context"
	"time"
)

// RevocationQuery is the complete authenticated identity checked after signature and time validation.
type RevocationQuery struct {
	Issuer       string
	Tenant       string
	CapabilityID string
	KeyID        string
	Subject      string
	Resource     string
	IssuedAt     time.Time
}

// RevocationChecker checks capability, key, subject, resource, and issued-before policy.
type RevocationChecker interface {
	Check(context.Context, RevocationQuery) (bool, error)
}

// RevocationCheckerFunc adapts a function to RevocationChecker.
type RevocationCheckerFunc func(context.Context, RevocationQuery) (bool, error)

// Check implements RevocationChecker.
func (function RevocationCheckerFunc) Check(ctx context.Context, query RevocationQuery) (bool, error) {
	return function(ctx, query)
}
