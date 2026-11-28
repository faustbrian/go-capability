//go:build integration && queryperformance

package identitycapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Synthetic native grants measure the exact nonlocking terminal probe, not
// authenticated grant lookup, retirement, drain recovery or production latency.
func TestOAuthProxyOriginTerminalGrantQueryStaysPointBounded(t *testing.T) {
	conn := oauthProxyRetirementDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	issued := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
	expiry, expired := issued.Add(3*time.Hour), issued.Add(time.Hour)
	if _, err := conn.Exec(ctx, `INSERT INTO public.capability_identity_one_use(
 tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,state,uses,
 command_id,command_fingerprint,generation,origin_command_id,origin_fingerprint,origin_generation,subject_id,
 signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-a' ELSE 'sparse-'||((n-16001)/100)::text END,
 CASE WHEN (n/6)%2=0 THEN 'identity.oauth.proxy-forward' ELSE 'identity.oauth.callback' END,
 3,sha256(convert_to(n::text,'UTF8')),'load-'||n,decode(repeat('02',32),'hex'),
 CASE WHEN n%6=4 THEN $2::timestamptz ELSE $1::timestamptz END,1,
 (ARRAY['issued','reserved','finalized','released','expired','revoked'])[n%6+1],CASE WHEN n%6=2 THEN 1 ELSE 0 END,
 CASE WHEN n%6=0 THEN NULL ELSE 'BAQEBAQEBAQEBAQEBAQEBA' END,
 CASE WHEN n%6=0 THEN NULL ELSE decode(repeat('03',32),'hex') END,
 CASE WHEN n%6=0 THEN NULL ELSE 9 END,
 'AQEBAQEBAQEBAQEBAQEBAQ',decode(repeat('04',32),'hex'),5,'AgICAgICAgICAgICAgICAg',
 $3::timestamptz,$3::timestamptz,'fixture-key',decode(repeat('05',32),'hex'),$3::timestamptz
 FROM generate_series(1,20000) n`, expiry, expired, issued); err != nil {
		t.Fatal("seed 20k skewed native grants with both proxy purposes and six legal states", err)
	}
	if _, err := conn.Exec(ctx, `ANALYZE public.capability_identity_one_use`); err != nil {
		t.Fatal(err)
	}
	var total, dense, tenants int
	var engine, columns, indexes string
	var heapBytes, indexBytes int64
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||udt_schema||'.'||udt_name,', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema='public' AND table_name='capability_identity_one_use'),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='public' AND tablename='capability_identity_one_use')`).
		Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect actual native grant columns/indexes", err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-a'),count(DISTINCT tenant_id),
 pg_relation_size('public.capability_identity_one_use'),pg_indexes_size('public.capability_identity_one_use')
 FROM public.capability_identity_one_use`).Scan(&total, &dense, &tenants, &heapBytes, &indexBytes); err != nil || total != 20000 || dense != 16000 || tenants != 41 {
		t.Fatal("terminal grant fixture volume/skew differs", total, dense, tenants, err)
	}
	t.Logf("PostgreSQL %s; columns=%s; indexes=%s; 20k native grants, 16k dense tenant, 40 sparse tenants of 100; both purposes in all six legal states; heap_bytes=%d index_bytes=%d; isolated sequential warm connection, no competing load", engine, columns, indexes, heapBytes, indexBytes)
	argsFor := func(t *testing.T, tenant, purpose string, number int) []any {
		t.Helper()
		expires := expiry
		if number%6 == 4 {
			expires = expired
		}
		scope := kernel.OAuthProxyOriginRetirementScope{TenantID: identity.TenantID(tenant), GrantPurpose: purpose,
			OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", FlowID: "AgICAgICAgICAgICAgICAg"}
		grant := kernel.CapabilityPlan{Purpose: capability.Purpose(purpose), ReplayKeyVersion: 3,
			ReplayDigest: sha256.Sum256([]byte(strconv.Itoa(number))), CapabilityID: "load-" + strconv.Itoa(number), ExpiresAt: expires, MaxUses: 1}
		for n := range grant.ProofFingerprint {
			grant.ProofFingerprint[n] = 2
		}
		var args []any
		if err := confirmOAuthProxyOriginGrantTerminal(ctx, scope, grant, func(_ context.Context, statement string, actual ...any) (string, error) {
			if statement != oauthProxyOriginTerminalGrantSQL {
				t.Fatal("terminal adapter selected a different statement")
			}
			args = slices.Clone(actual)
			return "settled", nil
		}); err != nil || len(args) != 9 {
			t.Fatal("capture the actual terminal adapter SQL and Work bindings", err)
		}
		return args
	}
	measure := func(t *testing.T, args []any, want string) {
		t.Helper()
		bindings := make([]string, len(args))
		for n, arg := range args {
			bindings[n] = fmt.Sprintf("$%d=%T", n+1, arg)
		}
		t.Logf("exact terminal SELECT=%s; native Work-compatible binding types=%s; one PK/unique exact-match candidate, then terminal-state/provenance filters", oauthProxyOriginTerminalGrantSQL, strings.Join(bindings, ", "))
		var raw []byte
		if err := conn.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+oauthProxyOriginTerminalGrantSQL, args...).Scan(&raw); err != nil {
			t.Fatal("explain exact terminal-only probe", err)
		}
		var plans []struct{ Plan oauthProxyRetirementQueryPlan }
		if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
			t.Fatal("decode terminal-only plan", err)
		}
		p := plans[0].Plan
		if (p.Kind != "Index Scan" && p.Kind != "Index Only Scan") || p.Relation != "capability_identity_one_use" ||
			p.Loops != 1 || p.Rows+p.Filtered > 1 || !p.pointBounded() || len(p.Plans) != 0 {
			t.Fatalf("terminal probe is no longer a nonlocking one-candidate SELECT: %s", raw)
		}
		oauthProxyRetirementMeasureQuery(t, ctx, conn, oauthProxyOriginTerminalGrantSQL, args, want)
	}
	for _, scope := range []struct {
		name, tenant string
		first        int
	}{
		{"dense", "tenant-a", 1}, {"sparse", "sparse-0", 16001},
	} {
		for purposeIndex, purpose := range []string{"identity.oauth.proxy-forward", "identity.oauth.callback"} {
			for stateIndex, state := range []string{"issued", "reserved", "finalized", "released", "expired", "revoked"} {
				t.Run(scope.name+"/"+purpose+"/"+state, func(t *testing.T) {
					number := 0
					for candidate := scope.first; candidate < scope.first+12; candidate++ {
						if candidate%6 == stateIndex && (candidate/6)%2 == purposeIndex {
							number = candidate
							break
						}
					}
					if number == 0 {
						t.Fatal("no representative state/purpose in the selected tenant")
					}
					want := "settled"
					if state == "revoked" {
						want = "retired"
					}
					if state == "issued" || state == "reserved" {
						want = ""
					}
					measure(t, argsFor(t, scope.tenant, purpose, number), want)
				})
			}
		}
	}
	for _, tenant := range []string{"tenant-a", "sparse-0"} {
		t.Run(tenant+"/missing", func(t *testing.T) {
			measure(t, argsFor(t, tenant, "identity.oauth.proxy-forward", 30001), "")
		})
	}
	for parameter, name := range []string{"tenant", "purpose", "replay-version", "replay-digest", "capability", "proof", "origin", "flow", "expiry"} {
		t.Run("exact-revoked-mismatch/"+name, func(t *testing.T) {
			args := slices.Clone(argsFor(t, "tenant-a", "identity.oauth.proxy-forward", 5))
			switch parameter {
			case 0:
				args[parameter] = "foreign-tenant"
			case 1:
				args[parameter] = "identity.oauth.callback"
			case 2:
				args[parameter] = int64(4)
			case 3, 5:
				args[parameter] = bytes.Repeat([]byte{99}, 32)
			case 4:
				args[parameter] = "another-capability"
			case 6, 7:
				args[parameter] = "BQUFBQUFBQUFBQUFBQUFBQ"
			case 8:
				args[parameter] = expiry.Add(time.Second)
			}
			measure(t, args, "")
		})
	}
	var untouched bool
	if err := conn.QueryRow(ctx, `SELECT count(*)=20000 AND bool_and(
 state=(ARRAY['issued','reserved','finalized','released','expired','revoked'])[(substring(capability_id FROM 6)::integer)%6+1]
 AND uses=CASE WHEN (substring(capability_id FROM 6)::integer)%6=2 THEN 1 ELSE 0 END)
 FROM public.capability_identity_one_use`).Scan(&untouched); err != nil || !untouched {
		t.Fatal("terminal-only SELECT changed native grant state/use history", err)
	}
	t.Log("All samples are read-only point probes; reused retirement helper reports conservative rollback/WAL caveats, not actual writes here. No lock wait, authenticated lookup, complete Work, commit, drain or production-performance claim.")
}
