package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// MFAMagicLinkParentBindings is historical original request/primary provenance.
// It contains no bearer, factor proof or current authorization. The owning
// magic-link adapter must reconstruct its entire original payload and call
// MatchPayload before using identifier or session metadata. The MFA workflow
// must still fence current authority and original browser custody atomically.
type MFAMagicLinkParentBindings struct {
	TenantID                           identity.TenantID
	UserID                             identity.UserID
	CapabilityID                       string
	RequestCommandID, PrimaryCommandID identity.CommandID
	ReplayKeyVersion                   uint32
	IssuedAt, NotBefore, ExpiresAt     time.Time
}

// MFAMagicLinkParent retains opaque canonical-payload custody from an exact
// consumed parent linked to an authenticated original child. It is immutable,
// copyable and safe for concurrent local comparisons; zero values deny.
// Inspection is not permission to complete MFA or issue a session. No raw
// primary credential is recovered, recreated, signed or retained.
type MFAMagicLinkParent struct {
	bindings              MFAMagicLinkParentBindings
	payload, supersession [32]byte
	issuer, audience      string
	limits                capability.Limits
	valid                 bool
}

// Bindings projects immutable historical routing/times, not decoded payload
// fields or current authority. A copied projection cannot manufacture custody.
func (p MFAMagicLinkParent) Bindings() (MFAMagicLinkParentBindings, error) {
	if !p.valid {
		return MFAMagicLinkParentBindings{}, identity.ForbiddenError{}
	}
	return p.bindings, nil
}

// MatchPayload requires byte-equivalent canonical reconstruction of the entire
// retained parent payload under the original bounded capability format. Extra,
// missing or changed caveats, subject, tenant, scope, request origin or times
// deny. This local comparison performs no IO, consumption, signing or renewal.
// Success authenticates historical metadata only; protected execution must
// repeat its current account/factor/browser/child authority checks.
func (p MFAMagicLinkParent) MatchPayload(v capability.Payload) error {
	deny := identity.ForbiddenError{}
	b := p.bindings
	if !p.valid || v.Version != 1 || v.Bearer || v.MaxUses != 1 || v.ID != b.CapabilityID || v.Tenant != string(b.TenantID) || v.Subject != string(b.UserID) || v.Operation != "identity.magic-link.consume" || v.CorrelationID != string(b.RequestCommandID) || v.Issuer != p.issuer || len(v.Audiences) != 1 || v.Audiences[0] != p.audience || !v.IssuedAt.Equal(b.IssuedAt) || !v.NotBefore.Equal(b.NotBefore) || !v.ExpiresAt.Equal(b.ExpiresAt) {
		return deny
	}
	if p.supersession != ([32]byte{}) {
		scope, err := MagicLinkScopeFromPayload(v)
		if err != nil || scope.digest != p.supersession || v.Caveats["magiclink.supersession"] != hex.EncodeToString(p.supersession[:]) {
			return deny
		}
	} else if _, selected := v.Caveats["magiclink.supersession"]; selected {
		return deny
	}
	wire, err := capability.CanonicalPayload(v, p.limits)
	defer clear(wire)
	if err != nil {
		return deny
	}
	digest := sha256.Sum256(wire)
	if !hmac.Equal(digest[:], p.payload[:]) {
		return deny
	}
	return nil
}

// ReadMFAMagicLinkParent verifies the original MFA child and resolves its exact
// already-consumed magic-link parent without accepting a reusable primary
// bearer. Parent ID/envelope/expiry must come from the authenticated stored
// continuation, not client fields. The parent's finalized consumer tuple must
// match the child's original issuance command/fingerprint/generation. Original
// request provenance, tenant, subject, signature times and exclusive lifetimes
// are preserved; superseded/missing/foreign records deny.
//
// The result owns no connection or transaction and grants no execution ticket.
// Signature/revocation verification and indexed primary reads share one issuer
// timeout and the earlier caller deadline. Pool/child custody are borrowed;
// immutable issuers permit concurrent calls. No callback, goroutine, signing,
// consumption, intent store or freshness renewal is created. Invalid composition
// returns InvalidInput; missing/foreign provenance returns Forbidden; unavailable
// storage/verification returns Unavailable. Cancellation remains typed. Every
// error returns zero custody and reveals no SQL, credential or correlated data.
func (i *Issuer) ReadMFAMagicLinkParent(ctx context.Context, pool *database.Pool, child capability.Proof, parentID string, parentEnvelope [32]byte, parentExpiry time.Time) (out MFAMagicLinkParent, err error) {
	if i == nil || i.service == nil || ctx == nil || pool == nil || pool.Raw() == nil || parentEnvelope == ([32]byte{}) || parentExpiry.IsZero() {
		return out, invalid()
	}
	if _, e := identity.ParseIdentifierID(parentID); e != nil {
		return out, invalid()
	}
	ctx, stop := context.WithTimeout(ctx, i.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if e := issuerContext(ctx); e != nil {
			err = e
		}
		if err != nil {
			out = MFAMagicLinkParent{}
		}
	}()
	grant, primary, _, _, err := i.readIssuanceOrigin(ctx, pool, child, "identity.mfa.complete", false, false)
	if err != nil {
		return out, err
	}
	v := grant.Payload()
	if !mfaIssuancePayload(v) || parentID == v.ID {
		return out, identity.ForbiddenError{}
	}
	wire, e := capability.CanonicalPayload(v, i.limits)
	if e != nil {
		return out, identity.ForbiddenError{}
	}
	childDigest := sha256.Sum256(wire)
	clear(wire)
	envelope := grant.EnvelopeDigest()
	var request string
	var replayVersion int64
	var issued, notBefore, expires time.Time
	var payload, scope []byte
	err = pool.Raw().QueryRow(ctx, `SELECT p.origin_command_id,p.replay_key_version,p.signed_issued_at,p.signed_not_before,p.expires_at,p.payload_digest,p.supersession_scope
FROM public.capability_identity_one_use c
JOIN public.capability_identity_one_use p ON p.tenant_id=c.tenant_id
 AND p.purpose='identity.magic-link.consume' AND p.capability_id=$4
 AND p.subject_id=c.subject_id AND p.command_id=c.origin_command_id
 AND p.command_fingerprint=c.origin_fingerprint AND p.generation=c.origin_generation
WHERE c.tenant_id=$1 AND c.purpose='identity.mfa.complete' AND c.capability_id=$2
 AND c.origin_command_id=$3 AND c.subject_id=$5 AND c.proof_fingerprint=$6
 AND c.payload_digest=$7 AND c.state IN ('issued','finalized')
 AND c.signed_issued_at=$8 AND c.signed_not_before=$8 AND c.expires_at=$9
 AND c.expires_at>clock_timestamp()
 AND p.proof_fingerprint=$10 AND p.expires_at=$11 AND p.expires_at>=c.expires_at
 AND p.expires_at>clock_timestamp() AND p.signed_issued_at<=c.signed_issued_at
 AND p.signed_not_before<=c.signed_issued_at
 AND p.state='finalized' AND p.uses=p.max_uses AND p.max_uses=1
 AND p.origin_command_id IS NOT NULL AND p.origin_command_id<>c.origin_command_id
 AND p.superseded_by_command_id IS NULL`, v.Tenant, v.ID, string(primary), parentID, v.Subject, envelope[:], childDigest[:], v.IssuedAt, v.ExpiresAt, parentEnvelope[:], parentExpiry).Scan(&request, &replayVersion, &issued, &notBefore, &expires, &payload, &scope)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = identity.ForbiddenError{}
		} else {
			err = identity.UnavailableError{}
		}
		return out, err
	}
	requestID, e := identity.ParseCommandID(request)
	if e != nil || replayVersion < 1 || replayVersion > math.MaxUint32 || len(payload) != 32 || len(scope) != 0 && len(scope) != 32 || issued.IsZero() || !expires.After(issued) || notBefore.Before(issued) || !expires.After(notBefore) {
		return out, identity.ForbiddenError{}
	}
	if i.keys[uint32(replayVersion)] == ([32]byte{}) {
		return out, identity.UnavailableError{}
	}
	out.bindings = MFAMagicLinkParentBindings{TenantID: identity.TenantID(v.Tenant), UserID: identity.UserID(v.Subject), CapabilityID: parentID, RequestCommandID: requestID, PrimaryCommandID: primary, ReplayKeyVersion: uint32(replayVersion), IssuedAt: issued, NotBefore: notBefore, ExpiresAt: expires}
	copy(out.payload[:], payload)
	copy(out.supersession[:], scope)
	if out.payload == ([32]byte{}) || len(scope) == 32 && out.supersession == ([32]byte{}) {
		return MFAMagicLinkParent{}, identity.ForbiddenError{}
	}
	out.issuer, out.audience, out.limits, out.valid = v.Issuer, i.audience, i.limits, true
	return out, nil
}

// Format prevents implicit disclosure of correlated parent custody.
func (MFAMagicLinkParent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identitycapability.MFAMagicLinkParent(redacted)"))
}

// MarshalJSON refuses implicit export of parent digest custody.
func (MFAMagicLinkParent) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText refuses implicit text/map-key export of parent custody.
func (MFAMagicLinkParent) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts parent provenance and canonical-payload custody.
func (MFAMagicLinkParent) LogValue() slog.Value {
	return slog.StringValue("identitycapability.MFAMagicLinkParent(redacted)")
}
