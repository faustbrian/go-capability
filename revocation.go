package capability

import (
	"context"
	"time"
)

// RevocationQuery is the complete authenticated identity checked after signature and time validation.
type RevocationQuery struct {
	// Issuer is authenticated exact namespace for every matching boundary.
	Issuer string
	// Tenant scopes resource revocation; empty remains exact.
	Tenant string
	// CapabilityID is authenticated signed ID for individual revocation.
	CapabilityID string
	// KeyID is authenticated protected key identity for issuer/key revocation.
	KeyID string
	// Subject is authenticated subject; memory skips this boundary when empty.
	Subject string
	// Resource is authenticated exact application authority, not a filesystem or egress
	// permission.
	Resource string
	// IssuedAt is signed issue time; memory issued-before cutoffs match strictly earlier
	// times.
	IssuedAt time.Time
}

// RevocationChecker checks capability, key, subject, resource, and issued-before policy.
// Shared implementations must be concurrency-safe, bounded and context-aware.
// No core worker, timeout, cache or panic boundary owns collaborator execution.
type RevocationChecker interface {
	// Check returns true for revoked authority, false only after successful policy
	// read. Errors fail Verify closed as ErrRevocationUnknown; document
	// propagation/cache staleness.
	Check(context.Context, RevocationQuery) (bool, error)
}

// RevocationCheckerFunc adapts a function to RevocationChecker.
type RevocationCheckerFunc func(context.Context, RevocationQuery) (bool, error)

// Check implements RevocationChecker.
func (function RevocationCheckerFunc) Check(ctx context.Context, query RevocationQuery) (bool, error) {
	return function(ctx, query)
}
