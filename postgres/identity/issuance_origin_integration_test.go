//go:build integration

package identitycapability_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

func assertIssuanceOriginDenied(t *testing.T, i *issuerpg.Issuer, ctx context.Context, pool *database.Pool, proof capability.Proof, purpose capability.Purpose, issued bool) {
	t.Helper()
	call := i.ReadIssuanceOrigin
	if issued {
		call = i.ValidateIssuedProof
	}
	g, command, version, err := call(ctx, pool, proof, purpose)
	if err == nil || g.EnvelopeDigest() != ([32]byte{}) || command != "" || version != 0 {
		t.Fatal("denied issuance origin retained sensitive projection")
	}
}

// This tests actual signed reset-purpose issuance provenance, not account,
// factor, callback authorization or the complete password-reset workflow.
func testResetIssuanceOrigin(t *testing.T, ctx context.Context, pool *database.Pool, i *issuerpg.Issuer, proof capability.Proof, id identity.CommandID, plan kernel.CapabilityPlan) {
	t.Helper()
	purpose := capability.Purpose("identity.password.reset-complete")
	for n := 0; n < 3; n++ {
		for _, call := range []func(context.Context, *database.Pool, capability.Proof, capability.Purpose) (capability.Grant, identity.CommandID, uint32, error){i.ReadIssuanceOrigin, i.ValidateIssuedProof} {
			g, origin, version, err := call(ctx, pool, proof, purpose)
			if err != nil || origin != id || version != 1 || g.EnvelopeDigest() != plan.ProofFingerprint || g.Payload().Operation != string(purpose) || g.Payload().CorrelationID != string(id) {
				t.Fatal("original reset issuance changed", err)
			}
		}
	}
	var state string
	var uses int
	if err := pool.Raw().QueryRow(ctx, `SELECT state,uses FROM public.capability_identity_one_use WHERE capability_id=$1`, plan.CapabilityID).Scan(&state, &uses); err != nil || state != "issued" || uses != 0 {
		t.Fatal("inspection consumed or reserved reset", err)
	}
	for _, p := range []capability.Purpose{"identity.identifier.verify", "", "invalid\npurpose"} {
		for _, issued := range []bool{false, true} {
			assertIssuanceOriginDenied(t, i, ctx, pool, proof, p, issued)
		}
	}
	for _, issued := range []bool{false, true} {
		assertIssuanceOriginDenied(t, i, ctx, pool, capability.Proof{}, purpose, issued)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, issued := range []bool{false, true} {
		assertIssuanceOriginDenied(t, i, cancelled, pool, proof, purpose, issued)
	}
	// Closed registration readers must not become generic reset readers.
	for _, call := range []func(context.Context, *database.Pool, capability.Proof) (capability.Grant, identity.CommandID, uint32, error){i.ReadRegistrationOrigin, i.ValidateRegistrationProof} {
		g, command, version, err := call(ctx, pool, proof)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || g.EnvelopeDigest() != ([32]byte{}) || command != "" || version != 0 {
			t.Fatal("reset reinterpreted as registration")
		}
	}
	for _, column := range []string{"payload_digest", "replay_digest", "proof_fingerprint"} {
		t.Run("tampered-"+column, func(t *testing.T) {
			var original []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM public.capability_identity_one_use WHERE capability_id=$1`, plan.CapabilityID).Scan(&original); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET `+column+`=$1 WHERE capability_id=$2`, original, plan.CapabilityID); err != nil {
					t.Error("owned fixture restoration", err)
				}
			}()
			if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET `+column+`=$1 WHERE capability_id=$2`, bytes.Repeat([]byte{9}, 32), plan.CapabilityID); err != nil {
				t.Fatal(err)
			}
			for _, issued := range []bool{false, true} {
				assertIssuanceOriginDenied(t, i, ctx, pool, proof, purpose, issued)
			}
		})
	}
	for _, terminal := range []string{"reserved", "finalized", "released", "expired", "revoked"} {
		t.Run(terminal, func(t *testing.T) {
			defer func() {
				if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state='issued',uses=0,command_id=NULL,command_fingerprint=NULL,generation=NULL WHERE capability_id=$1`, plan.CapabilityID); err != nil {
					t.Error("owned state restoration", err)
				}
			}()
			uses := 0
			if terminal == "finalized" {
				uses = 1
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state=$2,uses=$3,command_id=$4,command_fingerprint=$5,generation=1 WHERE capability_id=$1`, plan.CapabilityID, terminal, uses, string(id), bytes.Repeat([]byte{8}, 32)); err != nil {
				t.Fatal(err)
			}
			assertIssuanceOriginDenied(t, i, ctx, pool, proof, purpose, true)
			g, origin, version, err := i.ReadIssuanceOrigin(ctx, pool, proof, purpose)
			if err != nil || origin != id || version != 1 || g.EnvelopeDigest() != plan.ProofFingerprint {
				t.Fatal("terminal state erased original provenance", err)
			}
		})
	}
}
