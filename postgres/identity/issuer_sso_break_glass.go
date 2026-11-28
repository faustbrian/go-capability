package identitycapability

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const ssoBreakGlassIssueOperation = "identity.sso.break-glass.issue"
const ssoBreakGlassIssueSchema = "identity.sso.break-glass.issue.native-v1"
const ssoBreakGlassConsumePurpose capability.Purpose = "identity.sso.break-glass.consume"
const ssoBreakGlassAudience = "identity.sso.break-glass"
const ssoBreakGlassPolicyCaveat = "sso.break-glass.policy-version"
const ssoBreakGlassLifetime = 15 * time.Minute

// PrepareSSOBreakGlass signs one original recovery grant for the independently
// named recipient and exact organization. The trusted SSO owner supplies the
// current enforcement revision and whole-second UTC issuance time; that revision
// is distinct from binding.PolicyVersion, which selects authorization policy.
// The payload has a fixed purpose, audience and fifteen-minute lifetime. This
// bounded preparation grants no eligibility, policy access, consumption or
// delivery authority; retain its original custody across retries and recovery.
func (i *Issuer) PrepareSSOBreakGlass(ctx context.Context, binding identity.CommandBinding, policyVersion uint64, issuedAt time.Time) (PreparedIssuance, error) {
	if i == nil || i.audience != ssoBreakGlassAudience || !ssoBreakGlassBinding(binding) ||
		policyVersion == 0 || policyVersion == ^uint64(0) ||
		!ssoBreakGlassInstant(issuedAt) || !ssoBreakGlassInstant(issuedAt.Add(ssoBreakGlassLifetime)) {
		return PreparedIssuance{}, invalid()
	}
	payload := capability.Payload{
		Version: 1, Issuer: i.issuer, Audiences: []string{ssoBreakGlassAudience},
		Subject: string(binding.UserID), Tenant: string(binding.TenantID), Resource: binding.RecordID,
		Operation: string(ssoBreakGlassConsumePurpose), CorrelationID: binding.CorrelationID,
		IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(ssoBreakGlassLifetime), MaxUses: 1,
		Caveats: map[string]string{ssoBreakGlassPolicyCaveat: strconv.FormatUint(policyVersion, 10)},
	}
	return i.prepareSelectedPlan(ctx, binding, kernel.CapabilityIssuancePlan{}, []capability.Payload{payload}, false, true)
}

// Reserve both names, including mismatched pairs, so generic profiles cannot
// borrow the dedicated issue operation or disguise it under another schema.
func ssoBreakGlassSelected(b identity.CommandBinding) bool {
	return b.OperationID == ssoBreakGlassIssueOperation || b.SchemaID == ssoBreakGlassIssueSchema
}

func ssoBreakGlassBinding(b identity.CommandBinding) bool {
	op := identity.FeatureOperation{Owner: "sso", OperationID: ssoBreakGlassIssueOperation, SchemaID: ssoBreakGlassIssueSchema,
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser,
		VersionPolicy: identity.FeatureVersionSequentialOrUnchanged}
	return b.ValidateFor(op) == nil && b.ActorKind == authorization.SubjectUser && b.AnonymousFlowID == ""
}

func ssoBreakGlassSubject(b identity.CommandBinding, p kernel.CapabilityIssuancePlan) (string, bool) {
	return string(b.UserID), ssoBreakGlassBinding(b) && p.RegistrationUserID == "" && p.ResetRecipientUserID == "" &&
		p.MagicLinkRecipientUserID == "" && p.MFAContinuationUserID == ""
}

func ssoBreakGlassPurposeAllowed(b identity.CommandBinding, purpose capability.Purpose) bool {
	if purpose == ssoBreakGlassConsumePurpose {
		return ssoBreakGlassBinding(b)
	}
	return !ssoBreakGlassSelected(b)
}

func ssoBreakGlassInstant(instant time.Time) bool {
	return instant.Location() == time.UTC && instant.Nanosecond() == 0 && instant.Unix() > 0 && instant.Year() <= 9999
}

// Signed payload guards also run when encrypted original custody is restored
// and when a sealed Work rederives replay metadata, not just during preparation.
func ssoBreakGlassPayload(b identity.CommandBinding, p capability.Payload) bool {
	encoded := p.Caveats[ssoBreakGlassPolicyCaveat]
	version, err := strconv.ParseUint(encoded, 10, 64)
	return ssoBreakGlassBinding(b) && p.Version == 1 && p.Operation == string(ssoBreakGlassConsumePurpose) &&
		p.Subject == string(b.UserID) && p.Tenant == string(b.TenantID) && p.Resource == b.RecordID && p.CorrelationID == b.CorrelationID &&
		!p.Bearer && p.MaxUses == 1 && len(p.Audiences) == 1 && p.Audiences[0] == ssoBreakGlassAudience &&
		ssoBreakGlassInstant(p.IssuedAt) && ssoBreakGlassInstant(p.NotBefore) && p.NotBefore.Equal(p.IssuedAt) &&
		ssoBreakGlassInstant(p.ExpiresAt) && p.ExpiresAt.Equal(p.IssuedAt.Add(ssoBreakGlassLifetime)) &&
		len(p.Caveats) == 1 && err == nil && version != 0 && version != ^uint64(0) && strconv.FormatUint(version, 10) == encoded
}
