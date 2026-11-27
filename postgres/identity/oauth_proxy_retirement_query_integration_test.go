//go:build integration && queryperformance

package identitycapability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func TestOAuthProxyOriginRetirementQueryStaysPointBounded(t *testing.T) {
	conn := oauthProxyRetirementDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if _, err := conn.Exec(ctx, `INSERT INTO public.capability_identity_one_use(
 tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,state,uses,
 command_id,command_fingerprint,generation,origin_command_id,origin_fingerprint,origin_generation,subject_id,
 signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at)
 SELECT CASE WHEN n<=24000 THEN 'tenant-a' ELSE 'sparse-'||((n-24001)/100)::text END,
 CASE WHEN n%2=0 THEN 'identity.oauth.proxy-forward' ELSE 'identity.oauth.callback' END,
 3,sha256(convert_to(n::text,'UTF8')),'load-'||n::text,decode(repeat('02',32),'hex'),
 date_trunc('second',clock_timestamp())+CASE WHEN n%6=4 THEN interval '-1 hour' ELSE interval '1 hour' END,1,
 (ARRAY['issued','reserved','finalized','released','expired','revoked'])[n%6+1],CASE WHEN n%6=2 THEN 1 ELSE 0 END,
 CASE WHEN n%6=0 THEN NULL ELSE 'BAQEBAQEBAQEBAQEBAQEBA' END,
 CASE WHEN n%6=0 THEN NULL ELSE decode(repeat('03',32),'hex') END,
 CASE WHEN n%6=0 THEN NULL ELSE 9 END,
 'AQEBAQEBAQEBAQEBAQEBAQ',decode(repeat('04',32),'hex'),5,'AgICAgICAgICAgICAgICAg',
 date_trunc('second',clock_timestamp())-interval '2 hours',date_trunc('second',clock_timestamp())-interval '2 hours',
 'fixture-key',decode(repeat('05',32),'hex'),date_trunc('second',clock_timestamp())-interval '2 hours'
 FROM generate_series(1,30000) n`); err != nil {
		t.Fatal("seed representative original grants with dense and sparse tenants", err)
	}
	if _, err := conn.Exec(ctx, `ANALYZE public.capability_identity_one_use`); err != nil {
		t.Fatal(err)
	}
	var total, dense, tenants, smallest, largest int
	var engine string
	var heapBytes, indexBytes int64
	if err := conn.QueryRow(ctx, `SELECT version()`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-a'),count(DISTINCT tenant_id),
 pg_relation_size('public.capability_identity_one_use'),pg_indexes_size('public.capability_identity_one_use')
 FROM public.capability_identity_one_use`).Scan(&total, &dense, &tenants, &heapBytes, &indexBytes); err != nil || total != 30000 || dense != 24000 || tenants != 61 {
		t.Fatal("representative grant volume or tenant skew differs", total, dense, tenants, err)
	}
	if err := conn.QueryRow(ctx, `SELECT min(n),max(n) FROM
 (SELECT count(*) n FROM public.capability_identity_one_use WHERE tenant_id<>'tenant-a' GROUP BY tenant_id) sparse`).Scan(&smallest, &largest); err != nil || smallest != 100 || largest != 100 {
		t.Fatal("representative sparse tenant partition differs", smallest, largest, err)
	}
	t.Logf("engine=%s rows=%d dense_rows=%d sparse_tenants=60 rows_each=100 heap_bytes=%d index_bytes=%d; six legal states, common origin/flow, one connection, sequential warm samples; no production, cold-cache or contention claim",
		engine, total, dense, heapBytes, indexBytes)
	for _, sql := range []string{
		`SELECT column_name||'='||udt_schema||'.'||udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='capability_identity_one_use' ORDER BY ordinal_position`,
		`SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND tablename='capability_identity_one_use' ORDER BY indexname`,
	} {
		rows, err := conn.Query(ctx, sql)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var metadata string
			if err := rows.Scan(&metadata); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			t.Log(metadata)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	for _, selection := range []struct {
		name          string
		index         int
		tenant        string
		result        string
		foreignOrigin bool
	}{
		{"dense-issued", 6, "tenant-a", "retired", false},
		{"dense-reserved", 7, "tenant-a", "retired", false},
		{"dense-finalized", 8, "tenant-a", "settled", false},
		{"dense-released", 9, "tenant-a", "settled", false},
		{"sparse-issued", 24006, "sparse-0", "retired", false},
		{"sparse-reserved", 24007, "sparse-0", "retired", false},
		{"dense-miss", 30001, "tenant-a", "", false},
		{"sparse-miss", 30001, "sparse-0", "", false},
		{"foreign-origin", 7, "tenant-a", "", true},
	} {
		t.Run(selection.name, func(t *testing.T) {
			purpose := "identity.oauth.proxy-forward"
			if selection.index%2 != 0 {
				purpose = "identity.oauth.callback"
			}
			var expiry time.Time
			if err := conn.QueryRow(ctx, `SELECT expires_at FROM public.capability_identity_one_use WHERE capability_id='load-7' AND purpose='identity.oauth.callback'`).Scan(&expiry); err != nil {
				t.Fatal(err)
			}
			scope := kernel.OAuthProxyOriginRetirementScope{
				TenantID: "tenant-a", OriginCommandID: "AQEBAQEBAQEBAQEBAQEBAQ", FlowID: "AgICAgICAgICAgICAgICAg",
				GrantPurpose: purpose, SourceCommandID: "AwMDAwMDAwMDAwMDAwMDAw", SourceVersion: 7,
			}
			scope.TenantID = identity.TenantID(selection.tenant)
			if selection.foreignOrigin {
				scope.OriginCommandID = "BQUFBQUFBQUFBQUFBQUFBQ"
			}
			grant := kernel.CapabilityPlan{Purpose: capability.Purpose(purpose), CapabilityID: "load-" + strconv.Itoa(selection.index),
				ReplayKeyVersion: 3, ReplayDigest: sha256.Sum256([]byte(strconv.Itoa(selection.index))), ProofFingerprint: [32]byte{}, ExpiresAt: expiry, MaxUses: 1}
			for index := range grant.ProofFingerprint {
				grant.ProofFingerprint[index] = 2
			}
			if selection.result != "" {
				if err := conn.QueryRow(ctx, `SELECT expires_at FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3`, selection.tenant, purpose, grant.CapabilityID).Scan(&grant.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			}
			var statement string
			var args []any
			if err := retireOAuthProxyOriginGrant(ctx, scope, grant, func(_ context.Context, sql string, actual ...any) (string, error) {
				statement, args = sql, append([]any(nil), actual...)
				return "settled", nil
			}); err != nil || statement != oauthProxyOriginRetirementSQL || len(args) != 9 {
				t.Fatal("could not capture the real retirement statement and typed bindings", err)
			}
			var types []string
			for index, arg := range args {
				types = append(types, fmt.Sprintf("$%d=%T", index+1, arg))
			}
			t.Logf("native SQL=%s; actual binding types=%s", statement, strings.Join(types, ", "))
			oauthProxyRetirementMeasureQuery(t, ctx, conn, statement, args, selection.result)
		})
	}
	var untouched bool
	if err := conn.QueryRow(ctx, `SELECT count(*)=30000 AND bool_and(state=(ARRAY['issued','reserved','finalized','released','expired','revoked'])[(substring(capability_id FROM 6)::integer)%6+1])
 FROM public.capability_identity_one_use`).Scan(&untouched); err != nil || !untouched {
		t.Fatal("rolled-back measurements retained a grant transition", err)
	}
}

func oauthProxyRetirementMeasureQuery(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string, args []any, want string) {
	t.Helper()
	var samples []time.Duration
	for sample := range 14 {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("rollback retirement query sample", err)
				}
			}()
			if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal(err)
			}
			if sample == 0 {
				var raw []byte
				if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+sql, args...).Scan(&raw); err != nil {
					t.Fatal("explain the real exact-PK retirement query", err)
				}
				var plans []struct{ Plan oauthProxyRetirementQueryPlan }
				if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 || !plans[0].Plan.pointBounded() {
					t.Fatalf("retirement query lost its exact-PK work bound: %v\n%s", err, raw)
				}
				t.Logf("default-planner instrumented execution=%s", raw)
				return
			}
			started := time.Now()
			var got string
			err := tx.QueryRow(ctx, sql, args...).Scan(&got)
			elapsed := time.Since(started)
			if want == "" {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("missing or mismatched exact grant was acknowledged", err)
				}
			} else if err != nil || got != want {
				t.Fatal("retirement query returned a different legal transition classification", got, err)
			}
			if sample > 1 {
				samples = append(samples, elapsed)
			}
		}()
	}
	slices.Sort(samples)
	t.Logf("warm_samples=%d round_trip_median=%s range=%s..%s; typed scan included, BEGIN/setup/ROLLBACK excluded; writes rolled back, local WAL/dead tuples possible; no commit/full-operation/production claim",
		len(samples), samples[len(samples)/2], samples[0], samples[len(samples)-1])
}

type oauthProxyRetirementQueryPlan struct {
	Kind      string                          `json:"Node Type"`
	Relation  string                          `json:"Relation Name"`
	Index     string                          `json:"Index Name"`
	Condition string                          `json:"Index Cond"`
	Rows      float64                         `json:"Actual Rows"`
	Loops     float64                         `json:"Actual Loops"`
	Filtered  float64                         `json:"Rows Removed by Filter"`
	Plans     []oauthProxyRetirementQueryPlan `json:"Plans"`
}

func (p oauthProxyRetirementQueryPlan) pointBounded() bool {
	if p.Rows*p.Loops > 1 || p.Filtered*p.Loops > 1 {
		return false
	}
	if p.Relation == "capability_identity_one_use" && p.Kind != "ModifyTable" {
		primary := p.Index == "capability_identity_one_use_pkey" && strings.Contains(p.Condition, "replay_key_version") && strings.Contains(p.Condition, "replay_digest")
		uniqueCapability := p.Index == "capability_identity_one_use_tenant_id_purpose_capability_id_key" && strings.Contains(p.Condition, "capability_id")
		if p.Loops > 0 && (p.Kind != "Index Scan" && p.Kind != "Index Only Scan" || !primary && !uniqueCapability ||
			!strings.Contains(p.Condition, "tenant_id") || !strings.Contains(p.Condition, "purpose")) {
			return false
		}
	}
	for _, child := range p.Plans {
		if !child.pointBounded() {
			return false
		}
	}
	return true
}
