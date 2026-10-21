package identitycapability

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// AnonymousUpgradeScope contains original authenticated native preparation
// metadata, never HTTP assertions or current authorization. SourceVersion is
// positive; session IDs are exact 1..128-byte visible ASCII identifiers;
// MergeDigest is nonzero. SourceExpiresAt is the original guest's positive UTC
// expiry, at microsecond precision and within years 1..9999. Immutable copies
// support concurrent reads. Formatting is redacted and serialization rejects.
type AnonymousUpgradeScope struct {
	// SourceVersion is the original guest identity version signed into the proof.
	SourceVersion uint64
	// SourceSessionID identifies the original authenticated guest session.
	SourceSessionID string
	// TargetSessionID identifies the original authenticated permanent-user session.
	TargetSessionID string
	// MergeDigest binds the exact original native merge selection.
	MergeDigest [32]byte
	// Remember selects the signed persistent rather than session-only profile.
	Remember bool
	// SourceExpiresAt bounds the proof by the original guest's absolute lifetime.
	SourceExpiresAt time.Time
}

// Format hides correlated guest, session and merge metadata.
func (AnonymousUpgradeScope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.AnonymousUpgradeScope(redacted)"))
}

// MarshalJSON rejects automatic export of original trusted scope custody.
func (AnonymousUpgradeScope) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MarshalText rejects automatic export of original trusted scope custody.
func (AnonymousUpgradeScope) MarshalText() ([]byte, error) { return nil, invalid() }

// PrepareAnonymousUpgradeConsumption reauthenticates an original signed proof
// for identity.anonymous.upgrade / identity.anonymous.upgrade.native-v1 v1.
// UserID and the user ActorID identify the permanent target; the distinct
// RecordID identifies the guest. Supply expected scope, originalEnvelope and
// replayKeyVersion from authenticated original native preparation, never HTTP
// assertions or current-key defaults. All five signed anonymous caveats,
// issuer, tenant, target, guest, purpose, audience and one-use bounds must match.
// Signed expiry cannot exceed the original guest expiry.
//
// This bounded read-only seam borrows concurrent proof custody and returns only
// the existing participant plan, preserving original replay identity, envelope
// fingerprint and exact signed expiry. It performs no signing, SQL, reservation,
// consumption, transfer or renewal. It is not target-credential proof: the native
// password ActionPrimarySource must separately authenticate the current target
// for this action. Native identity/session owners still fence current guest,
// target, sessions, merge, policy and expiry and consume atomically with all
// effects through the sole coordinator and existing capability participant.
//
// Invalid composition returns InvalidInput; foreign or expired proof returns
// Forbidden; verification failure or panic returns Unavailable. Earlier caller
// cancellation wins. Every failure returns a zero plan and redacted typed error.
func (i *Issuer) PrepareAnonymousUpgradeConsumption(ctx context.Context, binding identity.CommandBinding, proof capability.Proof, originalEnvelope [32]byte, replayKeyVersion uint32, expected AnonymousUpgradeScope) (out kernel.CapabilityPlan, err error) {
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || originalEnvelope == ([32]byte{}) || binding.ValidateFor(op) != nil || binding.ActorKind != authorization.SubjectUser || string(binding.ActorID) != string(binding.UserID) || binding.RecordID == string(binding.UserID) || expected.SourceVersion == 0 || !issuerText(expected.SourceSessionID) || !issuerText(expected.TargetSessionID) || expected.MergeDigest == ([32]byte{}) || expected.SourceExpiresAt.Location() != time.UTC || expected.SourceExpiresAt.Year() < 1 || expected.SourceExpiresAt.Year() > 9999 || expected.SourceExpiresAt.Nanosecond()%1000 != 0 || expected.SourceExpiresAt.UnixMicro() <= 0 {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = kernel.CapabilityPlan{}, issuerFailure(ctx)
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, capability.Purpose(op.OperationID))
	if err != nil {
		return out, err
	}
	p := grant.Payload()
	remember := "session"
	if expected.Remember {
		remember = "persistent"
	}
	if grant.EnvelopeDigest() != originalEnvelope || p.Issuer != i.issuer || p.Tenant != string(binding.TenantID) || p.Subject != string(binding.UserID) || p.Resource != binding.RecordID || p.Operation != op.OperationID || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != i.audience || len(p.Caveats) != 5 || p.Caveats["anonymous.source-version"] != strconv.FormatUint(expected.SourceVersion, 10) || p.Caveats["anonymous.source-session"] != expected.SourceSessionID || p.Caveats["anonymous.target-session"] != expected.TargetSessionID || p.Caveats["anonymous.merge-digest"] != base64.RawURLEncoding.EncodeToString(expected.MergeDigest[:]) || p.Caveats["anonymous.remember"] != remember || p.ExpiresAt.After(expected.SourceExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(binding, binding.UserID, grant, replayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if err = issuerContext(ctx); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	return out, nil
}
