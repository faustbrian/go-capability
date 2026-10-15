package identitycapability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// ManagedEmailSupersessionScope identifies one exact issuer/audience, tenant,
// recipient, identifier and confirmation action. It is metadata, not proof or
// authority. Copies are immutable and safe for concurrent use; zero is invalid.
// A family deliberately excludes request IDs, times, key versions, callbacks and
// changing authority versions: a newly authorized resend must invalidate every
// older selected grant for that mailbox/action, not escape through new intent.
type ManagedEmailSupersessionScope struct{ digest [32]byte }

// Digest returns the opaque family identity for signed metadata and native
// transaction fencing. It grants no authority and selects no different tenant.
func (s ManagedEmailSupersessionScope) Digest() [32]byte { return s.digest }

// Format redacts correlated account and mailbox metadata.
func (ManagedEmailSupersessionScope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.ManagedEmailSupersessionScope(redacted)"))
}

func persistManagedEmailSupersession(ctx context.Context, tenant, command, capabilityID string, scope ManagedEmailSupersessionScope, exec func(context.Context, string, ...any) (int64, error)) error {
	// The shared lock primitive is purpose-neutral; the metadata/row predicates
	// below remain the distinct managed profile, not a magic-link reinterpretation.
	if err := lockMagicLinkScope(ctx, MagicLinkSupersessionScope{digest: scope.digest}, exec); err != nil {
		return err
	}
	args := []any{tenant, scope.digest[:], command, capabilityID}
	n, err := exec(ctx, managedEmailRegisterScopeSQL, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	_, err = exec(ctx, managedEmailSupersedeSQL, args[:3]...)
	return err
}

const managedEmailRegisterScopeSQL = `UPDATE public.capability_identity_one_use SET supersession_scope=$2 WHERE tenant_id=$1 AND purpose='identity.identifier.verify' AND origin_command_id=$3 AND capability_id=$4 AND state='issued' AND uses=0 AND supersession_scope IS NULL AND superseded_by_command_id IS NULL`
const managedEmailSupersedeSQL = `UPDATE public.capability_identity_one_use SET superseded_by_command_id=$3 WHERE tenant_id=$1 AND purpose='identity.identifier.verify' AND supersession_scope=$2 AND origin_command_id<>$3 AND state IN ('issued','reserved') AND uses=0 AND superseded_by_command_id IS NULL`

// MarshalJSON denies implicit scope export.
func (ManagedEmailSupersessionScope) MarshalJSON() ([]byte, error) { return nil, invalid() }

// ManagedEmailScopeFromPayload projects a bounded stable mailbox family. The
// native owner must separately authenticate/reconstruct complete original
// mailbox, callback, policy, fresh primary proof and pending-identifier state.
// This function does not sign, normalize, read a clock/store, reserve, consume
// or authorize anything. Existing four-caveat management payloads can be used to
// compute the family; an explicitly selected fifth email.supersession caveat
// must exactly equal it. Registration and magic-link profiles cannot borrow it.
// Inputs remain borrowed/immutable. Invalid input returns zero/redacted error;
// no resources or goroutines are created.
func ManagedEmailScopeFromPayload(p capability.Payload) (ManagedEmailSupersessionScope, error) {
	zero := ManagedEmailSupersessionScope{}
	if !emailPayloadShape(p, "management-v1") || p.Bearer || p.MaxUses != 1 || p.Operation != "identity.identifier.verify" || len(p.Audiences) != 1 {
		return zero, invalid()
	}
	fields := []string{p.Issuer, p.Audiences[0], p.Tenant, p.Subject, p.Resource, p.Operation, p.Caveats["email.confirm_operation"]}
	for n, value := range fields {
		limit := 128
		if n == 0 {
			limit = 4096
		} else if n == 1 {
			limit = 256
		}
		if value == "" || len(value) > limit || !utf8.ValidString(value) {
			return zero, invalid()
		}
		for _, r := range value {
			if r < 32 || r == 127 {
				return zero, invalid()
			}
		}
	}
	// The ordered tuple preserves field boundaries; the distinct metadata frame
	// cannot alias a magic-link browser family. This hash is not authentication.
	wire, err := json.Marshal(fields)
	if err != nil {
		return zero, invalid()
	}
	digest := sha256.Sum256(append([]byte("golib.capability.managed-email.supersession.v1\x00"), wire...))
	if encoded, selected := p.Caveats["email.supersession"]; selected && encoded != hex.EncodeToString(digest[:]) {
		return zero, invalid()
	}
	return ManagedEmailSupersessionScope{digest: digest}, nil
}

// CheckManagedEmailResendCooldown checks the authoritative last committed family
// issuance using database creation time, never signed proof time or caller time.
// The exact registered resend Apply invocation must already hold the same family
// fence before account/factor/domain locks. This method reacquires it defensively
// and performs no mutation, proof consumption or clock renewal. Interval is an
// explicit startup policy, between 30 seconds and 10 minutes. Missing history,
// unavailable history and cooldown deny; callers must propagate every error.
// Work and rows remain coordinator-owned and bounded by its context/lifetime.
func CheckManagedEmailResendCooldown(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, scope ManagedEmailSupersessionScope, interval time.Duration) error {
	if ctx == nil || owner == nil || scope.digest == ([32]byte{}) || interval < 30*time.Second || interval > 10*time.Minute {
		return invalid()
	}
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	_, feature, _, err := w.FeatureScope(owner)
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-send", SchemaID: "identity.email.verification-send.resend-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err != nil || feature.Operation != op || feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || b.ValidateFor(op) != nil {
		return invalid()
	}
	if err := lockMagicLinkScope(ctx, MagicLinkSupersessionScope{digest: scope.digest}, w.Exec); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT COALESCE(max(created_at)+($3::bigint*interval '1 microsecond')<=clock_timestamp(),false) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.identifier.verify' AND supersession_scope=$2`, string(b.TenantID), scope.digest[:], interval.Microseconds())
	if err != nil {
		return err
	}
	defer rows.Close()
	var allowed bool
	if !rows.Next() || rows.Scan(&allowed) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if !allowed {
		return identity.ForbiddenError{}
	}
	return nil
}
