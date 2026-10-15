package identitycapability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// MagicLinkSupersessionScope identifies one exact original browser flow and
// recipient selection. It is metadata, not proof verification or authorization.
// Copies are immutable and safe for concurrent use; the zero value is invalid.
type MagicLinkSupersessionScope struct{ digest [32]byte }

// Digest returns the opaque scope identity for signed metadata and native
// transactional fencing. It cannot grant authority or select another tenant.
func (s MagicLinkSupersessionScope) Digest() [32]byte { return s.digest }

// Format redacts scope metadata, including browser and recipient bindings.
func (MagicLinkSupersessionScope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.MagicLinkSupersessionScope(redacted)"))
}

// LockMagicLinkSupersession acquires the original-flow transaction fence before
// the invoking native feature locks account, factor or browser rows. Only the
// exact registered request/consume Apply invocation may act. It performs no
// provider work and retains no handle; the coordinator owns lock release.
// Callers must authenticate and reconstruct scope, not accept request digests.
func LockMagicLinkSupersession(ctx context.Context, w identitypostgres.Work, owner identitypostgres.FeatureExecutionContributor, scope MagicLinkSupersessionScope) error {
	if scope.digest == ([32]byte{}) || ctx == nil {
		return invalid()
	}
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	if b.OperationID != "identity.magic-link.request" && b.OperationID != "identity.magic-link.consume" {
		return invalid()
	}
	return lockMagicLinkScope(ctx, scope, w.Exec)
}

func lockMagicLinkScope(ctx context.Context, scope MagicLinkSupersessionScope, exec func(context.Context, string, ...any) (int64, error)) error {
	if ctx == nil || exec == nil || scope.digest == ([32]byte{}) {
		return invalid()
	}
	n, err := exec(ctx, magicLinkScopeLockSQL, scope.digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func persistMagicLinkSupersession(ctx context.Context, tenant, command, capabilityID string, scope MagicLinkSupersessionScope, exec func(context.Context, string, ...any) (int64, error)) error {
	if err := lockMagicLinkScope(ctx, scope, exec); err != nil {
		return err
	}
	args := []any{tenant, scope.digest[:], command, capabilityID}
	n, err := exec(ctx, magicLinkRegisterScopeSQL, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	_, err = exec(ctx, magicLinkSupersedeSQL, args[:3]...)
	return err
}

// Hash collisions serialize unrelated flows but cannot select their rows: the
// full digest and tenant remain exact predicates in all metadata mutations.
const magicLinkScopeLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),0))`
const magicLinkIssuedScopeLockSQL = `SELECT CASE WHEN supersession_scope IS NULL THEN NULL ELSE pg_advisory_xact_lock(hashtextextended(encode(supersession_scope,'hex'),0)) END FROM public.capability_identity_one_use WHERE ` + issuedInputSQL
const magicLinkRegisterScopeSQL = `UPDATE public.capability_identity_one_use SET supersession_scope=$2 WHERE tenant_id=$1 AND purpose='identity.magic-link.consume' AND origin_command_id=$3 AND capability_id=$4 AND state='issued' AND uses=0 AND supersession_scope IS NULL AND superseded_by_command_id IS NULL`
const magicLinkSupersedeSQL = `UPDATE public.capability_identity_one_use SET superseded_by_command_id=$3 WHERE tenant_id=$1 AND purpose='identity.magic-link.consume' AND supersession_scope=$2 AND origin_command_id<>$3 AND state IN ('issued','reserved') AND uses=0 AND superseded_by_command_id IS NULL`

func lockMagicLinkInput(ctx context.Context, b identitypostgres.CapabilityReservationBinding, exec func(context.Context, string, ...any) (int64, error)) error {
	if b.Plan.Purpose != "identity.magic-link.consume" && !managedVerificationSupersession(b) {
		return nil
	}
	n, err := exec(ctx, magicLinkIssuedScopeLockSQL, inputArgs(b)...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func activeCapabilitySQL(sql string, b identitypostgres.CapabilityReservationBinding) string {
	if b.Plan.Purpose != "identity.magic-link.consume" && !managedVerificationSupersession(b) {
		return sql
	}
	if strings.HasSuffix(sql, " FOR UPDATE") {
		return strings.TrimSuffix(sql, " FOR UPDATE") + " AND superseded_by_command_id IS NULL FOR UPDATE"
	}
	return sql + " AND superseded_by_command_id IS NULL"
}

// Only the new managed profile gains this schema/fence dependency. Legacy
// registration confirmation retains its original migration and SQL contract.
func managedVerificationSupersession(b identitypostgres.CapabilityReservationBinding) bool {
	if b.Plan.Purpose != "identity.identifier.verify" || b.Command.SchemaVersion != 1 {
		return false
	}
	return b.Command.OperationID == "identity.email.verification-confirm" && b.Command.SchemaID == "identity.email.verification-confirm.managed-v1" || b.Command.OperationID == "identity.email.change-confirm" && b.Command.SchemaID == "identity.email.change-confirm.managed-v1"
}

// MarshalJSON rejects serialization of opaque scope custody.
func (MagicLinkSupersessionScope) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MagicLinkScopeFromPayload projects bounded, exact original scope from a
// magic-link payload. The caller must separately authenticate the payload and
// reconstruct original intent. Token/command IDs, dates and authority versions
// are deliberately excluded: resending cannot escape its original flow by
// issuing a different token or observing newer authority. No strings normalize.
func MagicLinkScopeFromPayload(p capability.Payload) (MagicLinkSupersessionScope, error) {
	zero := MagicLinkSupersessionScope{}
	if p.Version != 1 || p.Bearer || p.MaxUses != 1 || p.Operation != "identity.magic-link.consume" || len(p.Audiences) != 1 {
		return zero, invalid()
	}
	fields := []string{p.Issuer, p.Audiences[0], p.Tenant, p.Subject, p.Resource, p.Operation,
		p.Caveats["magiclink.identifier"], p.Caveats["magiclink.canonical-email"], p.Caveats["magiclink.callback"], p.Caveats["magiclink.intent"], p.Caveats["magiclink.flow"], p.Caveats["magiclink.flow-binding"], p.Caveats["magiclink.profile"]}
	for index, value := range fields {
		limit := 512
		if index == 0 || index == 8 {
			limit = 4096
		}
		if index == 2 || index == 3 || index == 6 {
			limit = 128
		}
		if len(value) == 0 || len(value) > limit || !utf8.ValidString(value) {
			return zero, invalid()
		}
		for _, r := range value {
			if r < 32 || r == 127 {
				return zero, invalid()
			}
		}
	}
	if p.Resource != "identity.magiclink/"+fields[6] || (fields[9] != "signin-only" && fields[9] != "signup-if-allowed") || len(fields[10]) != 22 {
		return zero, invalid()
	}
	for _, b := range []byte(fields[10]) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' && b != '_' {
			return zero, invalid()
		}
	}
	for _, value := range fields[11:] {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(value) != 64 || len(decoded) != 32 || strings.ToLower(value) != value {
			return zero, invalid()
		}
	}
	if _, selected := p.Caveats["magiclink.prospective"]; selected {
		if !prospectiveMagicLinkProfile(p) {
			return zero, invalid()
		}
		// Each acknowledged request generates different prospective account and
		// identifier IDs. Those are signed creation intent, not existing authority;
		// including them (or their creation digest) lets a resend escape its family.
		// Retain the exact mailbox/browser/deployment/policy scope here. Native
		// consumption still authenticates the complete creation digest separately.
		// Existing-recipient scopes retain their exact original bytes.
		fields[3], fields[4], fields[6] = "prospective-user", "prospective-resource", "prospective-identifier"
		fields = append(fields, "prospective-mailbox-v2", p.Caveats["magiclink.email-policy-version"])
	}
	// An ordered JSON tuple preserves field boundaries without delimiter aliases.
	wire, err := json.Marshal(fields)
	if err != nil {
		return zero, invalid()
	}
	return MagicLinkSupersessionScope{digest: sha256.Sum256(append([]byte("golib.capability.magiclink.supersession.v1\x00"), wire...))}, nil
}
