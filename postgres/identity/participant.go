// Package identitycapability provides the optional capability-owned PostgreSQL
// participants for the identity Coordinator. They never own a pool, transaction
// or command ledger. Issuer prepares secret custody outside transactions;
// Participant handles consumption metadata only. Install Migrations first.
package identitycapability

import (
	"context"
	"fmt"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// Participant is an immutable coordinator-only one-use storage participant.
// Instances may serve concurrent independent commands; handles remain serial-use.
// The zero value is invalid. No handles, rows or runtime resources are retained.
// It supports reserve, takeover, provisional consumption, finalization, evidence
// and terminal release. Issuance, revocation and cleanup remain unfinished;
// execution still requires the complete identity-owned domain composition.
type Participant struct{ initialized bool }

// NewParticipant creates the stateless default-schema participant without I/O.
// Migration installation and permissions remain explicit composition concerns.
func NewParticipant() *Participant { return &Participant{initialized: true} }

// Descriptor returns the immutable identity of capability.one-use v1. It grants
// registration identity only, never invocation or transaction authority.
func (*Participant) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
}

// Format redacts runtime participant state.
func (*Participant) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.Participant(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition.
func (*Participant) MarshalJSON() ([]byte, error) { return nil, invalid() }

func (p *Participant) valid(ctx context.Context) error {
	if p == nil || !p.initialized || ctx == nil {
		return invalid()
	}
	if ctx.Err() == context.Canceled {
		return identity.CancelledError{}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return identity.DeadlineExceededError{}
	}
	return nil
}

// ReserveCapability locks an existing issued record and binds exact command,
// fingerprint and generation in the coordinator's reservation transaction.
// It never inserts missing state or consumes a use. Expired, terminal or changed
// input returns a redacted Conflict. Only the exact registered instance may act.
func (p *Participant) ReserveCapability(ctx context.Context, w identitypostgres.CapabilityReservationWork) error {
	if err := p.valid(ctx); err != nil {
		return err
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if b.PreviousGeneration != 0 {
		return invalid()
	}
	args := inputArgs(b)
	args = append(args, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	if err := lockMagicLinkInput(ctx, b, w.Exec); err != nil {
		return err
	}
	n, err := w.Exec(ctx, activeCapabilitySQL(reserveSQL, b), args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// RebindCapability CAS-transfers only the exact previous reserved generation.
// It preserves immutable issued input and command/fingerprint; live primary
// expiry is required. Failed takeover leaves no participant or journal prefix.
func (p *Participant) RebindCapability(ctx context.Context, w identitypostgres.CapabilityReservationWork) error {
	if err := p.valid(ctx); err != nil {
		return err
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if b.PreviousGeneration == 0 {
		return invalid()
	}
	args := boundArgs(b)
	args = append(args, strconv.FormatUint(b.Generation, 10))
	if err := lockMagicLinkInput(ctx, b, w.Exec); err != nil {
		return err
	}
	n, err := w.Exec(ctx, activeCapabilitySQL(rebindSQL, b), args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// ApplyCapability provisionally consumes the exact original reservation under
// current-generation invocation custody. It locks before checking exclusive
// primary expiry and increments only below the signed maximum. It never renews
// expiry, releases evidence or claims a committed command. Rollback restores
// the original unused reservation; only the coordinator owns transaction closure.
func (p *Participant) ApplyCapability(ctx context.Context, w identitypostgres.CapabilityApplyWork) error {
	if err := p.valid(ctx); err != nil {
		return err
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	return executeConsumption(ctx, b, false, w.Exec)
}

// FinalizeCapability CASes the same consumed current-generation reservation to
// finalized in the protected transaction, after rechecking exclusive primary
// expiry under its row lock. Missing use, repeated/terminal state or changed
// binding conflicts. Finalization is provisional until the coordinator commits;
// it neither terminalizes the command ledger nor infers an unknown outcome.
func (p *Participant) FinalizeCapability(ctx context.Context, w identitypostgres.CapabilityFinalizeWork) error {
	if err := p.valid(ctx); err != nil {
		return err
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	return executeConsumption(ctx, b, true, w.Exec)
}

// The private SQL boundary is shared with real PostgreSQL tests, not exported
// invocation authority. Production supplies only the sealed phase's bounded
// executor; no consumer callback or independent transaction can be supplied.
func executeConsumption(ctx context.Context, b identitypostgres.CapabilityReservationBinding, finalize bool, exec func(context.Context, string, ...any) (int64, error)) error {
	if ctx == nil || exec == nil || b.Generation == 0 || b.PreviousGeneration != 0 {
		return invalid()
	}
	args := append(inputArgs(b), string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	if err := lockMagicLinkInput(ctx, b, exec); err != nil {
		return err
	}
	// A clock predicate evaluated before a row-lock wait can admit expired
	// evidence. Acquire the exact row first, then evaluate primary time in a
	// separate statement while retaining the same transaction-owned lock.
	n, err := exec(ctx, activeCapabilitySQL(executionLockSQL, b), args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	sql := applySQL
	if finalize {
		sql = finalizeSQL
	}
	n, err = exec(ctx, activeCapabilitySQL(sql, b), args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// RecoverParticipant reads retained primary evidence for the exact frozen input
// and previous reserved generation. Reserved or revoked with zero uses and
// matching original reservation linkage is negative evidence;
// finalized or used is committed participant evidence, never a command receipt.
// Missing, mismatched or other terminal evidence remains unknown. Expiry alone
// changes nothing. Coordinator combines all participant evidence before release.
func (p *Participant) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if err := p.valid(ctx); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	b, err := w.CapabilityBinding(p)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, statusSQL, boundArgs(b)...)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return identitypostgres.RecoveryUnknown, err
		}
		return identitypostgres.RecoveryUnknown, nil
	}
	var state string
	var uses int32
	if err := rows.Scan(&state, &uses); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	if rows.Next() {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	return classifyConsumptionRecovery(state, uses), nil
}

// The schema forbids revoking any used grant. Exact statusSQL reservation
// linkage is essential: an unreserved issued/revoked row is not evidence for
// an unrelated consuming command. Retirement conserves that linkage.
func classifyConsumptionRecovery(state string, uses int32) identitypostgres.RecoveryStatus {
	if (state == "reserved" || state == "finalized") && uses == 1 {
		return identitypostgres.RecoveryCommitted
	}
	if (state == "reserved" || state == "revoked") && uses == 0 {
		return identitypostgres.RecoveryNotCommitted
	}
	return identitypostgres.RecoveryUnknown
}

// ReleaseCapability terminal-releases an exact unused reserved record only
// with coordinator-granted unanimous non-commit authority. The transition CASes
// previous to recovery generation with the failure audit and aborted receipt.
// It never makes evidence reusable; expiry does not reactivate or erase it.
func (p *Participant) ReleaseCapability(ctx context.Context, w identitypostgres.CapabilityReleaseWork) error {
	if err := p.valid(ctx); err != nil {
		return err
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	args := boundArgs(b)
	args = append(args, strconv.FormatUint(b.Generation, 10))
	n, err := w.Exec(ctx, releaseSQL, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func inputArgs(b identitypostgres.CapabilityReservationBinding) []any {
	return []any{string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.ReplayKeyVersion, b.Plan.ReplayDigest[:], b.Plan.CapabilityID, b.Plan.ProofFingerprint[:], b.Plan.ExpiresAt, b.Plan.MaxUses}
}
func boundArgs(b identitypostgres.CapabilityReservationBinding) []any {
	return append(inputArgs(b), string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10))
}
func invalid() error { return identity.InvalidInputError{Field: "capability_participant"} }

const issuedInputSQL = `tenant_id=$1 AND purpose=$2 AND replay_key_version=$3 AND replay_digest=$4 AND capability_id=$5 AND proof_fingerprint=$6 AND expires_at=$7 AND max_uses=$8`
const reservedInputSQL = issuedInputSQL + ` AND command_id=$9 AND command_fingerprint=$10 AND generation=$11::numeric`
const reserveSQL = `UPDATE public.capability_identity_one_use SET state='reserved',command_id=$9,command_fingerprint=$10,generation=$11::numeric WHERE ` + issuedInputSQL + ` AND state='issued' AND uses=0 AND expires_at>clock_timestamp()`
const rebindSQL = `UPDATE public.capability_identity_one_use SET generation=$12::numeric WHERE ` + reservedInputSQL + ` AND state='reserved' AND uses=0 AND expires_at>clock_timestamp()`
const statusSQL = `SELECT state,uses FROM public.capability_identity_one_use WHERE ` + reservedInputSQL + ` FOR UPDATE`
const releaseSQL = `UPDATE public.capability_identity_one_use SET state=CASE WHEN state='revoked' THEN 'revoked' ELSE 'released' END,generation=$12::numeric WHERE ` + reservedInputSQL + ` AND state IN ('reserved','revoked') AND uses=0`
const executionLockSQL = `SELECT 1 FROM public.capability_identity_one_use WHERE ` + reservedInputSQL + ` FOR UPDATE`
const applySQL = `UPDATE public.capability_identity_one_use SET uses=uses+1 WHERE ` + reservedInputSQL + ` AND state='reserved' AND uses<max_uses AND expires_at>clock_timestamp()`
const finalizeSQL = `UPDATE public.capability_identity_one_use SET state='finalized' WHERE ` + reservedInputSQL + ` AND state='reserved' AND uses=max_uses AND expires_at>clock_timestamp()`

var _ identitypostgres.CapabilityExecutionContributor = (*Participant)(nil)
