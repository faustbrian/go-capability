package identitycapability

import (
	"context"
	"encoding/hex"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PrepareMFAConsumption reauthenticates the original single-use MFA child for
// one closed anonymous factor-completion operation. recipient, continuation,
// scope, issuer, originalEnvelope and replayKeyVersion are trusted original
// continuation/issuance custody, not request-selected authority. The signed
// tenant, subject, canonical child ID, resource, closed profile, scope, issuer,
// audience and original envelope must match. Purpose remains identity.mfa.complete
// rather than being rewritten to the selected factor operation. Expiry and
// replay identity are unchanged, including across replay-key rotation.
//
// This bounded read-only seam neither authenticates a factor nor issues a
// session. It performs no SQL, signing, reservation, consumption, custody
// transfer, renewal or goroutine creation. The native owner must authenticate
// durable origin, original browser/primary/remember scope, allowed factor,
// current policy/account/factor authority and shared attempts. The sole
// coordinator and capability participant consume with replay/continuation and
// session effects atomically; this scalar plan is never permission to do so.
//
// Calls may overlap and borrow the proof's shared lifetime. PreparationTimeout
// and the earlier caller deadline bound verification. Invalid composition
// returns InvalidInput; invalid/foreign/expired proof returns Forbidden;
// unavailable verification or collaborator panic returns Unavailable. Context
// errors remain typed and redacted. Every failure returns a zero plan.
func (i *Issuer) PrepareMFAConsumption(ctx context.Context, b identity.CommandBinding, recipient identity.UserID, continuation identity.CommandID, scope [32]byte, issuer string, proof capability.Proof, originalEnvelope [32]byte, replayKeyVersion uint32) (out kernel.CapabilityPlan, err error) {
	method := ""
	switch b.OperationID {
	case "identity.mfa.totp-verify":
		method = "totp-verify"
	case "identity.mfa.otp-verify":
		method = "otp-verify"
	case "identity.mfa.recovery-use":
		method = "recovery-use"
	case "identity.mfa.security-key-assert-verify":
		method = "security-key-assert-verify"
	default:
		return out, invalid()
	}
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: "mfa-" + method, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if i == nil || i.service == nil || ctx == nil || i.keys[replayKeyVersion] == ([32]byte{}) || originalEnvelope == ([32]byte{}) || scope == ([32]byte{}) || !issuerText(issuer) || b.ValidateFor(op) != nil {
		return out, invalid()
	}
	if _, e := identity.ParseCommandID(string(continuation)); e != nil {
		return out, invalid()
	}
	if _, e := identity.ParseIdentifierID(string(recipient)); e != nil {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = kernel.CapabilityPlan{}, identity.UnavailableError{}
		}
	}()
	grant, err := i.verifyConsumptionProof(ctx, proof, "identity.mfa.complete")
	if err != nil {
		return out, err
	}
	p := grant.Payload()
	if grant.EnvelopeDigest() != originalEnvelope || !mfaIssuancePayload(p) || p.ID != string(continuation) || p.Tenant != string(b.TenantID) || p.Subject != string(recipient) || p.Issuer != issuer || p.Caveats["mfa.scope"] != hex.EncodeToString(scope[:]) || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != i.audience {
		return out, identity.ForbiddenError{}
	}
	out, err = i.grantPlan(b, recipient, grant, replayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if err = issuerContext(ctx); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	return out, nil
}
