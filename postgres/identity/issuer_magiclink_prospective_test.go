package identitycapability

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestProspectiveIssuerRetainsExplicitSelectedLimits(t *testing.T) {
	_, config, binding, payload := issuerFixture(t)
	b := magicLinkIssuerBinding(binding)
	payload.Subject, payload.Operation, payload.Resource = "prospective-user", "identity.magic-link.consume", "identity.magiclink/prospective-email"
	payload.Caveats = map[string]string{"magiclink.prospective": "1", "magiclink.intent": "signup-if-allowed", "magiclink.creation-digest": strings.Repeat("a", 64), "magiclink.email-policy-version": "3", "magiclink.identifier": "prospective-email", "magiclink.canonical-email": "prospective@example.test", "magiclink.identifier-version": "1", "magiclink.verification-version": "1", "magiclink.identifier-authority-version": "1", "magiclink.user-authority-version": "1", "magiclink.credential-authority-version": "1"}
	for n := len(payload.Caveats); n < 18; n++ {
		payload.Caveats[fmt.Sprintf("original-flow-%d", n)] = "bound"
	}
	i, _ := NewIssuer(config)
	if _, err := i.PrepareMagicLinkProspectiveRecipient(t.Context(), b, "prospective-user", payload); err == nil {
		t.Fatal("default selected policy expanded implicitly")
	}
	config.Crypto.Limits.MaxCaveats = 18
	i, err := NewIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	p, err := i.PrepareMagicLinkProspectiveRecipient(t.Context(), b, "prospective-user", payload)
	if err != nil {
		t.Fatal("explicit selected profile rejected after signing", err)
	}
	plan, _ := p.Plan()
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(t.Context(), p, 1, nil)
	if err != nil {
		t.Fatal("selected limits lost at checkpoint", err)
	}
	defer clear(wire)
	restored, err := codec.RestorePreparation(t.Context(), b, 1, plan, wire)
	if err != nil || restored.state == nil || len(restored.state.grants[0].Payload().Caveats) != 18 {
		t.Fatal("selected limits lost on restoration", err)
	}
	config.Crypto.Limits.MaxCaveats = 16
	narrow, _ := NewIssuer(config)
	narrowCodec, _ := preparationFixture(t, narrow, config)
	if _, err := narrowCodec.RestorePreparation(t.Context(), b, 1, plan, wire); err == nil {
		t.Fatal("narrow current verification policy bypassed")
	}
}

func TestMagicLinkProspectiveIssuerPreservesOriginalCustody(t *testing.T) {
	i, config, binding, payload := issuerFixture(t)
	native, ok := any(i).(interface {
		PrepareMagicLinkProspectiveRecipient(context.Context, identity.CommandBinding, identity.UserID, capability.Payload) (PreparedIssuance, error)
	})
	if !ok {
		t.Fatal("prospective issuer-owned custody unavailable")
	}
	b := magicLinkIssuerBinding(binding)
	payload.Subject, payload.Operation, payload.Resource = "prospective-user", "identity.magic-link.consume", "identity.magiclink/prospective-email"
	payload.Caveats = map[string]string{"magiclink.prospective": "1", "magiclink.intent": "signup-if-allowed", "magiclink.creation-digest": strings.Repeat("a", 64), "magiclink.email-policy-version": "3", "magiclink.identifier": "prospective-email", "magiclink.canonical-email": "prospective@example.test", "magiclink.identifier-version": "1", "magiclink.verification-version": "1", "magiclink.identifier-authority-version": "1", "magiclink.user-authority-version": "1", "magiclink.credential-authority-version": "1"}
	prepared, err := native.PrepareMagicLinkProspectiveRecipient(context.Background(), b, "prospective-user", payload)
	if err != nil {
		t.Fatal("prospective issuance", err)
	}
	plan, err := prepared.Plan()
	if err != nil || plan.MagicLinkRecipientUserID != "prospective-user" || prepared.state.binding != b {
		t.Fatal("changed prospective declaration", err)
	}
	codec, _ := preparationFixture(t, i, config)
	wire, err := codec.CheckpointPreparation(context.Background(), prepared, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := codec.RestorePreparation(context.Background(), b, 7, plan, wire)
	if err != nil || restored.state == nil || restored.state.grants[0].Payload().Caveats["magiclink.creation-digest"] != payload.Caveats["magiclink.creation-digest"] || restored.state.grants[0].EnvelopeDigest() != plan.Grants[0].ProofFingerprint {
		t.Fatal("restored prospective custody changed", err)
	}
	if _, err := i.PrepareMagicLinkRecipient(context.Background(), b, "prospective-user", payload); err == nil {
		t.Fatal("existing-recipient entry accepted prospective profile")
	}
	for _, key := range []string{"magiclink.prospective", "magiclink.intent", "magiclink.creation-digest", "magiclink.email-policy-version", "magiclink.identifier", "magiclink.canonical-email", "magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
		changed := payload
		changed.Caveats = make(map[string]string, len(payload.Caveats))
		for k, v := range payload.Caveats {
			changed.Caveats[k] = v
		}
		changed.Caveats[key] = ""
		if out, err := native.PrepareMagicLinkProspectiveRecipient(context.Background(), b, "prospective-user", changed); err == nil || out.state != nil {
			t.Fatal("incomplete prospective profile signed", key)
		}
	}
}

func TestMagicLinkProspectiveRejectsOversizedFieldsBeforeParsing(t *testing.T) {
	i, _, binding, _ := issuerFixture(t)
	for name, field := range map[string]string{
		"magiclink.creation-digest":      strings.Repeat("a", 128<<10),
		"magiclink.email-policy-version": strings.Repeat("0", 128<<10) + "3",
	} {
		t.Run(name, func(t *testing.T) {
			p := supersessionPayload()
			p.Caveats["magiclink.prospective"] = "1"
			p.Caveats["magiclink.intent"] = "signup-if-allowed"
			p.Caveats["magiclink.creation-digest"] = strings.Repeat("a", 64)
			p.Caveats["magiclink.email-policy-version"] = "3"
			for _, key := range []string{"magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
				p.Caveats[key] = "1"
			}
			p.Caveats[name] = field
			if allocations := testing.AllocsPerRun(1, func() {
				if prospectiveMagicLinkProfile(p) {
					t.Fatal("oversized profile admitted")
				}
			}); allocations != 0 {
				t.Fatal("oversized field allocated before rejection", allocations)
			}
			if out, err := i.PrepareMagicLinkProspectiveRecipient(t.Context(), magicLinkIssuerBinding(binding), identity.UserID(p.Subject), p); err == nil || out.state != nil {
				t.Fatal("oversized issuance admitted")
			}
			if out, err := MagicLinkScopeFromPayload(p); err == nil || out.Digest() != ([32]byte{}) {
				t.Fatal("oversized scope projected")
			}
		})
	}
}
