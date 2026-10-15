package identitycapability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ReadRegistrationOrigin authenticates a registration-profile proof with this
// issuer's configured signature, audience, time and revocation policy, then
// matches its exact persisted original issuance. It returns the authenticated
// grant, originating command ID and original replay-key version, never a raw
// bearer, current-key substitution or newly signed credential. Unpublished,
// legacy originless, foreign-envelope and mismatched evidence deny identically.
//
// This is a trusted native composition seam, not public scanner validation,
// session authority, a signup receipt or permission to consume. The origin
// owner must authenticate its original signup input and email intent. Confirm
// must still recheck current identity and capability state in the sole protected
// transaction. Later consuming/terminal state does not erase original provenance
// and is deliberately not interpreted here as usable authority or rollback.
//
// The primary pool and proof are borrowed; no transaction, custody transfer,
// reservation, mutation, callback or goroutine is created. Immutable issuers
// permit concurrent calls. PreparationTimeout and the earlier caller deadline
// bound crypto and the indexed primary read. Invalid composition returns
// InvalidInput, unavailable verification/storage returns Unavailable, and
// cancellation retains its typed classification. Errors never expose SQL,
// credentials or correlation metadata. Successful projections remain sensitive.
func (i *Issuer) ReadRegistrationOrigin(ctx context.Context, pool *database.Pool, proof capability.Proof) (capability.Grant, identity.CommandID, uint32, error) {
	g, c, v, _, err := i.readIssuanceOrigin(ctx, pool, proof, "identity.identifier.verify", false, true)
	return g, c, v, err
}

// ValidateRegistrationProof authenticates original registration provenance and
// requires an issued, unused proof whose exclusive expiry is after primary time
// in that same indexed read. No reservation, consumption, expiry renewal or
// mutation occurs. Reserved, finalized, released, expired and revoked proofs
// deny identically to absence. ReadRegistrationOrigin deliberately remains the
// separate historical reader, including after consumption.
//
// This trusted email composition seam returns sensitive original grant metadata,
// not a public scanner response, mailbox ownership or permission to execute.
// The email owner must bind original address/redirect and current account state
// before returning bounded public metadata. Confirmation must repeat admission
// and consume atomically; validation cannot hold authority across a later call.
// The borrowed pool/proof, finite budget, concurrency, redaction and zero-on-error
// semantics are the same as ReadRegistrationOrigin. No handles or goroutines are
// retained and cancelled calls return no sensitive projection.
func (i *Issuer) ValidateRegistrationProof(ctx context.Context, pool *database.Pool, proof capability.Proof) (capability.Grant, identity.CommandID, uint32, error) {
	g, c, v, _, err := i.readIssuanceOrigin(ctx, pool, proof, "identity.identifier.verify", true, true)
	return g, c, v, err
}

// ReadIssuanceOrigin authenticates a purpose-explicit original one-use proof and
// matches its complete persisted issuance provenance. Purpose is trusted
// composition, never a bearer-selected fallback. Historical terminal state may
// retain provenance but grants no usable authority; signature, audience, time
// and configured revocation policy still apply. Missing or mismatched origins
// deny. Original replay versions are returned without current-key substitution.
//
// This is a trusted adapter seam, not public inspection or workflow permission.
// The owning workflow must validate its closed purpose-specific payload, original
// encrypted intent, current account/factor/risk state and exact scope before
// any public response or protected consumption. No transaction, reservation,
// consumption, renewal, bearer transfer, callback or goroutine is created.
// Pool/proof are borrowed; the issuer timeout and earlier deadline bound crypto
// and one indexed primary read. Instances are concurrent-safe. Errors redact;
// every failed/cancelled call returns zero projections. Metadata is sensitive.
func (i *Issuer) ReadIssuanceOrigin(ctx context.Context, pool *database.Pool, proof capability.Proof, purpose capability.Purpose) (capability.Grant, identity.CommandID, uint32, error) {
	g, c, v, _, err := i.readIssuanceOrigin(ctx, pool, proof, purpose, false, false)
	return g, c, v, err
}

// ValidateIssuedProof additionally requires issued, unused state and exclusive
// primary expiry in the same indexed read. Repeated inspection is read-only:
// no reservation, consumption or execution ticket results. Reserved, terminal,
// expired or revoked proofs deny; the owning workflow must still recheck current
// eligibility and repeat admission during atomic completion. Ownership, bounds,
// cancellation, redaction and zero-on-error semantics match ReadIssuanceOrigin.
func (i *Issuer) ValidateIssuedProof(ctx context.Context, pool *database.Pool, proof capability.Proof, purpose capability.Purpose) (capability.Grant, identity.CommandID, uint32, error) {
	g, c, v, _, err := i.readIssuanceOrigin(ctx, pool, proof, purpose, true, false)
	return g, c, v, err
}

// ReadMagicLinkOrigin authenticates original magic-link provenance and its exact
// signed supersession scope in one indexed primary read. The additional flag
// reports retained invalidation, not command outcome or permission to consume.
// Reserved/terminal provenance remains readable for retries and recovery; legacy
// unselected records report false. Migration 003 is required. Missing, tampered
// or unavailable evidence returns zero projections including the flag. Proof and
// pool are borrowed; bounds and cancellation match ReadIssuanceOrigin. The
// workflow must still reconstruct browser scope, check current authority and
// repeat admission/one-use in the protected transaction. No freshness renews.
func (i *Issuer) ReadMagicLinkOrigin(ctx context.Context, pool *database.Pool, proof capability.Proof) (capability.Grant, identity.CommandID, uint32, bool, error) {
	return i.readIssuanceOrigin(ctx, pool, proof, "identity.magic-link.consume", false, false)
}

func (i *Issuer) readIssuanceOrigin(ctx context.Context, pool *database.Pool, proof capability.Proof, purpose capability.Purpose, requireIssued, registration bool) (grant capability.Grant, command identity.CommandID, replayVersion uint32, superseded bool, err error) {
	if i == nil || i.service == nil || ctx == nil || pool == nil || pool.Raw() == nil {
		return grant, command, replayVersion, false, invalid()
	}
	if _, purposeErr := capability.NewPurpose(string(purpose)); purposeErr != nil {
		return grant, command, replayVersion, false, invalid()
	}
	ctx, stop := context.WithTimeout(ctx, i.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if contextErr := issuerContext(ctx); contextErr != nil {
			err = contextErr
		}
		if err != nil {
			grant, command, replayVersion, superseded = capability.Grant{}, "", 0, false
		}
	}()
	if err = issuerContext(ctx); err != nil {
		return
	}
	grant, err = i.service.Verify(ctx, proof, purpose, i.audience)
	if err != nil {
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			err = identity.UnavailableError{}
		} else {
			err = identity.ForbiddenError{}
		}
		return
	}
	v := grant.Payload()
	if v.Version != 1 || v.Bearer || v.MaxUses != 1 || len(v.Audiences) != 1 || registration && !registrationOriginProfile(v) {
		err = identity.ForbiddenError{}
		return
	}
	var origin, generation, subject, signingID string
	var keyVersion int64
	var originFingerprint, storedPayload, replayDigest, envelope []byte
	var issued, notBefore, expires time.Time
	var uses int32
	columns := `origin_command_id,origin_generation::text,replay_key_version,origin_fingerprint,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,replay_digest,proof_fingerprint,expires_at,max_uses`
	active := `state='issued' AND uses=0 AND expires_at>clock_timestamp()`
	destinations := []any{&origin, &generation, &keyVersion, &originFingerprint, &subject, &issued, &notBefore, &signingID, &storedPayload, &replayDigest, &envelope, &expires, &uses}
	var storedScope []byte
	_, managedFamily := v.Caveats["email.supersession"]
	managedFamily = managedFamily && purpose == "identity.identifier.verify" && v.Caveats["email.profile"] == "management-v1"
	if purpose == "identity.magic-link.consume" || managedFamily {
		columns += `,supersession_scope,superseded_by_command_id IS NOT NULL`
		active += ` AND superseded_by_command_id IS NULL`
		destinations = append(destinations, &storedScope, &superseded)
	}
	query := `SELECT ` + columns + ` FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND origin_command_id IS NOT NULL AND (NOT $4::boolean OR (` + active + `))`
	err = pool.Raw().QueryRow(ctx, query, v.Tenant, v.Operation, v.ID, requireIssued).Scan(destinations...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = identity.ForbiddenError{}
		} else {
			err = identity.UnavailableError{}
		}
		return
	}
	command, err = identity.ParseCommandID(origin)
	g, generationErr := strconv.ParseUint(generation, 10, 64)
	if err != nil || generationErr != nil || g == 0 || keyVersion < 1 || keyVersion > math.MaxUint32 || len(originFingerprint) != 32 || [32]byte(originFingerprint) == ([32]byte{}) || subject != v.Subject || signingID != grant.Header().KeyID || !issued.Equal(v.IssuedAt) || !notBefore.Equal(v.NotBefore) || !expires.Equal(v.ExpiresAt) || uses != 1 {
		err = identity.ForbiddenError{}
		return
	}
	replayVersion = uint32(keyVersion)
	if i.keys[replayVersion] == ([32]byte{}) {
		err = identity.UnavailableError{}
		return
	}
	plan, planErr := i.grantPlan(identity.CommandBinding{TenantID: identity.TenantID(v.Tenant)}, identity.UserID(v.Subject), grant, replayVersion)
	canonical, canonicalErr := capability.CanonicalPayload(v, i.limits)
	digest := sha256.Sum256(canonical)
	clear(canonical)
	if planErr != nil || canonicalErr != nil || !hmac.Equal(storedPayload, digest[:]) || !hmac.Equal(replayDigest, plan.ReplayDigest[:]) || !hmac.Equal(envelope, plan.ProofFingerprint[:]) {
		err = identity.ForbiddenError{}
	}
	if purpose == "identity.magic-link.consume" {
		if encoded, selected := v.Caveats["magiclink.supersession"]; selected {
			scope, scopeErr := MagicLinkScopeFromPayload(v)
			if scopeErr != nil || v.CorrelationID != origin || encoded != hex.EncodeToString(scope.digest[:]) || !hmac.Equal(storedScope, scope.digest[:]) {
				err = identity.ForbiddenError{}
			}
		} else if len(storedScope) != 0 || superseded {
			err = identity.ForbiddenError{}
		}
	}
	if managedFamily {
		scope, scopeErr := ManagedEmailScopeFromPayload(v)
		if scopeErr != nil || v.CorrelationID != origin || !hmac.Equal(storedScope, scope.digest[:]) {
			err = identity.ForbiddenError{}
		}
	}
	return
}

func registrationOriginProfile(v capability.Payload) bool {
	intent, decodeErr := hex.DecodeString(v.Caveats["email.intent"])
	version, versionErr := strconv.ParseUint(v.Caveats["email.binding_key_version"], 10, 32)
	return len(v.Caveats) == 4 && v.Caveats["email.profile"] == "registration-v1" && v.Caveats["email.confirm_operation"] == "identity.email.verification-confirm" && decodeErr == nil && len(intent) == 32 && strings.ToLower(v.Caveats["email.intent"]) == v.Caveats["email.intent"] && versionErr == nil && version > 0 && strconv.FormatUint(version, 10) == v.Caveats["email.binding_key_version"]
}
