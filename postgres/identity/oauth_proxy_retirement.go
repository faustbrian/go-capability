package identitycapability

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RetireOAuthProxyOriginGrant revokes one unused native proxy grant in the
// exact registered retirement Apply. The OAuth owner must authenticate the
// source and supply the original issuance's non-bearer grant locator, not a
// request annotation or a newly verified or renewed credential. The adapter
// additionally matches persistent tenant, flow, purpose and issuing command.
// Known terminal rows are unchanged. Missing or mismatched provenance denies.
// Preserve all reservation evidence; no provider outcome or local commit is
// inferred. Propagate every error so the coordinator aborts the same Work.
func RetireOAuthProxyOriginGrant(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, grant kernel.CapabilityPlan) error {
	scope, err := w.OAuthProxyOriginRetirementScope(ctx, owner, command)
	if err != nil {
		return err
	}
	return retireOAuthProxyOriginGrant(ctx, scope, grant, func(ctx context.Context, sql string, args ...any) (string, error) {
		rows, err := w.Query(ctx, sql, args...)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		if !rows.Next() {
			return "", rows.Err()
		}
		var outcome string
		if err := rows.Scan(&outcome); err != nil {
			return "", err
		}
		if rows.Next() {
			return "", identity.UnavailableError{}
		}
		return outcome, rows.Err()
	})
}

func retireOAuthProxyOriginGrant(ctx context.Context, scope kernel.OAuthProxyOriginRetirementScope, grant kernel.CapabilityPlan, query func(context.Context, string, ...any) (string, error)) error {
	if ctx == nil || query == nil || !issuerText(string(scope.TenantID)) ||
		(scope.GrantPurpose != "identity.oauth.proxy-forward" && scope.GrantPurpose != "identity.oauth.callback") ||
		string(grant.Purpose) != scope.GrantPurpose || !issuerText(grant.CapabilityID) || grant.ReplayKeyVersion == 0 || grant.MaxUses != 1 ||
		grant.ReplayDigest == ([32]byte{}) || grant.ProofFingerprint == ([32]byte{}) || grant.ExpiresAt.IsZero() || grant.ExpiresAt.Nanosecond() != 0 ||
		grant.ExpiresAt.Year() < 1 || grant.ExpiresAt.Year() > 9999 {
		return invalid()
	}
	if err := issuerContext(ctx); err != nil {
		return err
	}
	if _, err := identity.ParseCommandID(string(scope.OriginCommandID)); err != nil {
		return invalid()
	}
	if _, err := identity.ParsePreAuthTransactionID(string(scope.FlowID)); err != nil {
		return invalid()
	}
	result, err := query(ctx, oauthProxyOriginRetirementSQL, string(scope.TenantID), scope.GrantPurpose, int64(grant.ReplayKeyVersion),
		grant.ReplayDigest[:], grant.CapabilityID, grant.ProofFingerprint[:], string(scope.OriginCommandID), string(scope.FlowID), grant.ExpiresAt.UTC())
	if err != nil {
		return err
	}
	if err := issuerContext(ctx); err != nil {
		return err
	}
	switch result {
	case "retired", "settled":
		return nil
	case "":
		return identity.ForbiddenError{}
	default:
		return identity.UnavailableError{}
	}
}

// Lock and classify exactly one existing row. A restart may find a terminal
// grant; a missing row is not proof of settlement. The update never clears
// ownership or command/generation evidence and does not require a live proof.
const oauthProxyOriginRetirementSQL = `WITH original AS MATERIALIZED (
 SELECT state,uses FROM public.capability_identity_one_use
 WHERE tenant_id=$1 AND purpose=$2 AND replay_key_version=$3 AND replay_digest=$4
 AND capability_id=$5 AND proof_fingerprint=$6 AND origin_command_id=$7 AND subject_id=$8 AND expires_at=$9 AND max_uses=1
 FOR UPDATE
), changed AS (
 UPDATE public.capability_identity_one_use c SET state='revoked' FROM original o
 WHERE c.tenant_id=$1 AND c.purpose=$2 AND c.replay_key_version=$3 AND c.replay_digest=$4
 AND o.uses=0 AND o.state IN ('issued','reserved') RETURNING c.state
)
SELECT 'retired' FROM changed
UNION ALL SELECT 'retired' FROM original WHERE state='revoked' AND uses=0
UNION ALL SELECT 'settled' FROM original WHERE (state='finalized' AND uses=1) OR (state IN ('released','expired') AND uses=0)`
