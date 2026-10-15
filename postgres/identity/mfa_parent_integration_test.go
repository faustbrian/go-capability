//go:build integration

package identitycapability_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Parent issuance is the fixture's retained signed record; the original child
// and consumed parent tuple were produced together by the real coordinator.
// This is provenance, not factor validation or a public login journey.
func testMFAMagicLinkParent(t *testing.T, ctx context.Context, pool *database.Pool, issuer *issuerpg.Issuer, prepared issuerpg.PreparedIssuance, payload capability.Payload, plan kernel.CapabilityPlan, request, primary identity.CommandID) {
	t.Helper()
	var proof capability.Proof
	if err := prepared.TransferForDelivery(ctx, 0, func(_ context.Context, token []byte) error {
		var err error
		proof, err = capability.ParseProof(string(token), capability.DefaultLimits())
		return err
	}); err != nil {
		t.Fatal("original child delivery custody unavailable", err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	var before, after string
	snapshot := func(dest *string) {
		t.Helper()
		if err := pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(c) ORDER BY purpose,capability_id)::text FROM public.capability_identity_one_use c WHERE tenant_id=$1`, payload.Tenant).Scan(dest); err != nil {
			t.Fatal("owned provenance snapshot unavailable", err)
		}
	}
	snapshot(&before)
	for n := 0; n < 3; n++ {
		parent, err := issuer.ReadMFAMagicLinkParent(ctx, pool, proof, plan.CapabilityID, plan.ProofFingerprint, plan.ExpiresAt)
		if err != nil {
			t.Fatal("authenticated child lost consumed parent provenance", err)
		}
		bindings, err := parent.Bindings()
		if err != nil || bindings.RequestCommandID != request || bindings.PrimaryCommandID != primary || bindings.CapabilityID != payload.ID || !bindings.IssuedAt.Equal(payload.IssuedAt) || !bindings.ExpiresAt.Equal(payload.ExpiresAt) || parent.MatchPayload(payload) != nil {
			t.Fatal("parent provenance changed original request/primary/times/payload", err)
		}
		if _, err := json.Marshal(parent); err == nil {
			t.Fatal("parent custody implicitly serialized")
		}
		for _, mutate := range []func(*capability.Payload){
			func(p *capability.Payload) { p.CorrelationID = string(primary) },
			func(p *capability.Payload) { p.Subject = "foreign" },
			func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
			func(p *capability.Payload) { p.Caveats = map[string]string{"magiclink.identifier": "foreign"} },
			func(p *capability.Payload) { p.Issuer = "https://foreign.test" },
		} {
			changed := payload
			mutate(&changed)
			if parent.MatchPayload(changed) == nil {
				t.Fatal("reconstructed payload escaped canonical parent digest")
			}
		}
	}
	snapshot(&after)
	if before != after {
		t.Fatal("parent inspection consumed, renewed or changed retained custody")
	}
	deny := func(ctx context.Context, id string, digest [32]byte, expiry time.Time) {
		t.Helper()
		parent, err := issuer.ReadMFAMagicLinkParent(ctx, pool, proof, id, digest, expiry)
		if err == nil || parent != (issuerpg.MFAMagicLinkParent{}) {
			t.Fatal("foreign/cancelled parent read retained custody")
		}
	}
	deny(ctx, "foreign", plan.ProofFingerprint, plan.ExpiresAt)
	deny(ctx, plan.CapabilityID, [32]byte{9}, plan.ExpiresAt)
	deny(ctx, plan.CapabilityID, plan.ProofFingerprint, plan.ExpiresAt.Add(time.Second))
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	deny(cancelled, plan.CapabilityID, plan.ProofFingerprint, plan.ExpiresAt)
	for _, mutation := range []struct{ name, update, restore string }{
		{"foreign consumer", "command_id=origin_command_id", "command_id=$2"},
		{"foreign fingerprint", "command_fingerprint=decode(repeat('09',32),'hex')", "command_fingerprint=(SELECT origin_fingerprint FROM public.capability_identity_one_use WHERE origin_command_id=$2 AND purpose='identity.mfa.complete')"},
		{"foreign generation", "generation=generation+1", "generation=(SELECT origin_generation FROM public.capability_identity_one_use WHERE origin_command_id=$2 AND purpose='identity.mfa.complete')"},
		{"foreign subject", "subject_id='foreign'", "subject_id=$2"},
		{"released parent", "state='released',uses=0", "state='finalized',uses=1"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			second := string(primary)
			if mutation.name == "foreign subject" {
				second = payload.Subject
			}
			defer func() {
				args := []any{plan.CapabilityID}
				if mutation.name != "released parent" {
					args = append(args, second)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET `+mutation.restore+` WHERE capability_id=$1 AND purpose='identity.magic-link.consume'`, args...); err != nil {
					t.Error("owned parent restoration failed", err)
				}
			}()
			if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET `+mutation.update+` WHERE capability_id=$1 AND purpose='identity.magic-link.consume'`, plan.CapabilityID); err != nil {
				t.Fatal("owned parent mutation failed", err)
			}
			deny(ctx, plan.CapabilityID, plan.ProofFingerprint, plan.ExpiresAt)
		})
	}
	// A digest is not decoded metadata. Corrupting it may leave routing custody
	// readable, but cannot authenticate the owner's original reconstruction.
	if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET payload_digest=decode(repeat('09',32),'hex') WHERE capability_id=$1 AND purpose='identity.magic-link.consume'`, plan.CapabilityID); err != nil {
		t.Fatal("owned digest corruption failed", err)
	}
	parent, err := issuer.ReadMFAMagicLinkParent(ctx, pool, proof, plan.CapabilityID, plan.ProofFingerprint, plan.ExpiresAt)
	if err != nil || parent.MatchPayload(payload) == nil {
		t.Fatal("corrupt parent digest authenticated reconstructed metadata", err)
	}
	// The owner table is required; no cached or child-only metadata fallback.
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.capability_identity_one_use RENAME TO mfa_parent_unavailable`); err != nil {
		t.Fatal("owned unavailable fixture failed", err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.mfa_parent_unavailable RENAME TO capability_identity_one_use`); err != nil {
			t.Error("owned authority restoration failed", err)
		}
	}()
	deny(ctx, plan.CapabilityID, plan.ProofFingerprint, plan.ExpiresAt)
}
