//go:build integration

package identitycapability

import (
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func TestConfirmOAuthProxyOriginGrantTerminalIntegration(t *testing.T) {
	conn := oauthProxyRetirementDatabase(t)
	for _, purpose := range []string{"identity.oauth.proxy-forward", "identity.oauth.callback"} {
		t.Run(purpose, func(t *testing.T) {
			for _, state := range []string{"issued", "reserved", "revoked", "finalized", "released", "expired"} {
				t.Run(state, func(t *testing.T) {
					tx := oauthProxyRetirementTransaction(t, conn)
					scope, grant := oauthProxyRetirementSeed(t, tx, purpose, state, "target")
					before := oauthProxyTerminalGrantSnapshot(t, tx, scope, grant)
					for range 2 {
						err := confirmOAuthProxyOriginGrantTerminal(t.Context(), scope, grant, oauthProxyRetirementQuery(tx))
						if state == "issued" || state == "reserved" {
							if err == nil {
								t.Fatal("observer acknowledged a grant that can still be used")
							}
						} else if err != nil {
							t.Fatal("observer did not acknowledge the exact terminal grant", err)
						}
						if after := oauthProxyTerminalGrantSnapshot(t, tx, scope, grant); after != before {
							t.Fatal("observer wrote the original grant or changed its reservation evidence")
						}
					}
				})
			}

			for _, mismatch := range []string{
				"missing-row", "tenant", "origin", "flow", "purpose", "grant-purpose",
				"replay-version", "capability", "proof", "expiry", "maximum", "missing-locator", "missing-scope",
			} {
				t.Run("deny "+mismatch, func(t *testing.T) {
					tx := oauthProxyRetirementTransaction(t, conn)
					scope, grant := oauthProxyRetirementSeed(t, tx, purpose, "revoked", "target")
					before := oauthProxyTerminalGrantSnapshot(t, tx, scope, grant)
					changedScope, changedGrant := scope, grant
					switch mismatch {
					case "missing-row":
						changedGrant.ReplayDigest[0] ^= 1
					case "tenant":
						changedScope.TenantID = "tenant-b"
					case "origin":
						changedScope.OriginCommandID = "BQUFBQUFBQUFBQUFBQUFBQ"
					case "flow":
						changedScope.FlowID = "BgYGBgYGBgYGBgYGBgYGBg"
					case "purpose":
						changedScope.GrantPurpose = "identity.oauth.callback"
						changedGrant.Purpose = "identity.oauth.callback"
						if purpose == "identity.oauth.callback" {
							changedScope.GrantPurpose = "identity.oauth.proxy-forward"
							changedGrant.Purpose = "identity.oauth.proxy-forward"
						}
					case "grant-purpose":
						changedGrant.Purpose = "identity.identifier.verify"
					case "replay-version":
						changedGrant.ReplayKeyVersion++
					case "capability":
						changedGrant.CapabilityID = "another-capability"
					case "proof":
						changedGrant.ProofFingerprint[0] ^= 1
					case "expiry":
						changedGrant.ExpiresAt = changedGrant.ExpiresAt.Add(time.Second)
					case "maximum":
						changedGrant.MaxUses = 2
					case "missing-locator":
						changedGrant = kernel.CapabilityPlan{}
					case "missing-scope":
						changedScope = kernel.OAuthProxyOriginRetirementScope{}
					}
					if err := confirmOAuthProxyOriginGrantTerminal(t.Context(), changedScope, changedGrant, oauthProxyRetirementQuery(tx)); err == nil {
						t.Fatal("observer acknowledged missing or mismatched original grant provenance")
					}
					if after := oauthProxyTerminalGrantSnapshot(t, tx, scope, grant); after != before {
						t.Fatal("denied observation wrote the retained original grant")
					}
				})
			}
		})
	}
}

type oauthProxyTerminalGrantRow struct {
	retained oauthProxyRetirementRow
	tuple    string
}

func oauthProxyTerminalGrantSnapshot(t *testing.T, tx pgx.Tx, scope kernel.OAuthProxyOriginRetirementScope, grant kernel.CapabilityPlan) oauthProxyTerminalGrantRow {
	t.Helper()
	row := oauthProxyTerminalGrantRow{retained: oauthProxyRetirementSnapshot(t, tx, scope, grant)}
	// Retain physical identity too: an UPDATE to identical values is still a write.
	if err := tx.QueryRow(t.Context(), `SELECT ctid::text FROM public.capability_identity_one_use
 WHERE tenant_id=$1 AND purpose=$2 AND replay_key_version=$3 AND replay_digest=$4`,
		string(scope.TenantID), grant.Purpose, grant.ReplayKeyVersion, grant.ReplayDigest[:]).Scan(&row.tuple); err != nil {
		t.Fatal("read the original grant's physical row identity", err)
	}
	return row
}
