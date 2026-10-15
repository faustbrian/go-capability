package identitycapability

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RetireEmailVerificationGrants revokes only unused issued/reserved verification
// grants for the exact removed identifier in the kernel-locked original Apply
// invocation. The native owner must propagate errors to abort the same Work.
// Live unclassified legacy grants deny removal; reserved origin/fingerprint/
// generation metadata and consumed/other-target history are preserved. No
// transaction, lock protocol, credential, worker or recovery journal is created.
// Nil, foreign, unprepared, reconstructed and returned Work deny without SQL.
func RetireEmailVerificationGrants(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil {
		return invalid()
	}
	b, err := w.EmailRemovalScope(ctx, owner, command)
	if err != nil {
		return err
	}
	return retireEmailVerificationGrants(ctx, b, w.Exec)
}

// The target comes solely from the authenticated grant in the sealed issuance
// phase, never a caller annotation, current recipient or unsigned plan field.
func (i *Issuer) verificationTarget(v capability.Payload) (identity.IdentifierID, error) {
	if i == nil {
		return "", invalid()
	}
	if !i.verificationTargets || v.Operation != "identity.identifier.verify" {
		return "", nil
	}
	target, err := identity.ParseIdentifierID(v.Resource)
	if err != nil {
		return "", invalid()
	}
	return target, nil
}

// Native removal must call this only under its existing complete identifier
// partition and propagate errors to the sole Work's abort. This private seam
// is also exercised against real PostgreSQL. No separate authority, family
// lock, transaction, clock, goroutine or recovery journal is introduced.
// Active historical grants without provable target classification deny before
// mutation; expired/terminal history is retained rather than fabricated.
func retireEmailVerificationGrants(ctx context.Context, b identity.CommandBinding, exec func(context.Context, string, ...any) (int64, error)) error {
	if ctx == nil || exec == nil {
		return invalid()
	}
	if err := issuerContext(ctx); err != nil {
		return err
	}
	if _, err := identity.ParseIdentifierID(string(b.TenantID)); err != nil {
		return invalid()
	}
	if _, err := identity.ParseIdentifierID(string(b.UserID)); err != nil {
		return invalid()
	}
	if _, err := identity.ParseIdentifierID(b.RecordID); err != nil {
		return invalid()
	}
	args := []any{string(b.TenantID), string(b.UserID), b.RecordID}
	n, err := exec(ctx, emailRetirementClassificationSQL, args[:2]...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	_, err = exec(ctx, emailRetirementSQL, args...)
	return err
}

const issueVerificationTargetSQL = `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at,verification_identifier_id) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::numeric,$12,$13,$14,$15,$16,clock_timestamp(),$17 WHERE $7>clock_timestamp() AND $13<=clock_timestamp() AND $14<=clock_timestamp() ON CONFLICT DO NOTHING`

// Originless legacy grants cannot safely be attributed even to a subject. A
// live unclassified grant in this tenant conservatively denies removal; no
// unsigned bulk backfill or subject-wide retirement can fix that ambiguity.
const emailRetirementClassificationSQL = `SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.identifier.verify' AND (subject_id=$2 OR subject_id IS NULL) AND verification_identifier_id IS NULL AND uses=0 AND state IN ('issued','reserved') AND expires_at>clock_timestamp())`
const emailRetirementSQL = `UPDATE public.capability_identity_one_use SET state='revoked' WHERE tenant_id=$1 AND subject_id=$2 AND purpose='identity.identifier.verify' AND verification_identifier_id=$3 AND uses=0 AND state IN ('issued','reserved')`
