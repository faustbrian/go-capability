package identitycapability

import (
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func supersessionPayload() capability.Payload {
	return capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: "user", Tenant: "tenant", Resource: "identity.magiclink/email-id", Operation: "identity.magic-link.consume", MaxUses: 1, Caveats: map[string]string{
		"magiclink.identifier": "email-id", "magiclink.canonical-email": "user@example.test", "magiclink.callback": "https://identity.example.test/callback", "magiclink.intent": "signin-only", "magiclink.flow": "abcdefghijklmnopqrstuv", "magiclink.flow-binding": strings.Repeat("1", 64), "magiclink.profile": strings.Repeat("2", 64),
	}}
}

func TestMagicLinkScopeUsesCanonicalSignupIntent(t *testing.T) {
	login, err := MagicLinkScopeFromPayload(supersessionPayload())
	if err != nil {
		t.Fatal(err)
	}
	p := supersessionPayload()
	p.Caveats["magiclink.intent"] = "signup-if-allowed"
	signup, err := MagicLinkScopeFromPayload(p)
	if err != nil || signup.Digest() == ([32]byte{}) || signup.Digest() == login.Digest() {
		t.Fatal("canonical signup intent rejected or collapsed into signin", err)
	}
	p.Caveats["magiclink.intent"] = "signup-or-signin"
	if out, err := MagicLinkScopeFromPayload(p); err == nil || out.Digest() != ([32]byte{}) {
		t.Fatal("noncontractual signup alias acquired a scope")
	}
}

func TestMagicLinkProspectiveScopeBindsCreationPolicy(t *testing.T) {
	p := supersessionPayload()
	p.Caveats["magiclink.intent"] = "signup-if-allowed"
	before, err := MagicLinkScopeFromPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Caveats["magiclink.prospective"] = "1"
	p.Caveats["magiclink.creation-digest"] = strings.Repeat("a", 64)
	p.Caveats["magiclink.email-policy-version"] = "3"
	for _, key := range []string{"magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
		p.Caveats[key] = "1"
	}
	scope, err := MagicLinkScopeFromPayload(p)
	if err != nil || scope.Digest() == before.Digest() {
		t.Fatal("prospective creation policy omitted from scope", err)
	}
	p.Caveats["magiclink.email-policy-version"] = "4"
	changed, err := MagicLinkScopeFromPayload(p)
	if err != nil || changed.Digest() == scope.Digest() {
		t.Fatal("changed creation policy borrowed scope", err)
	}
	p.Caveats["magiclink.prospective"] = "0"
	if _, err := MagicLinkScopeFromPayload(p); err == nil {
		t.Fatal("unsupported prospective marker accepted")
	}
}

func TestProspectiveResendSupersedesDifferentPreparedCreation(t *testing.T) {
	p := supersessionPayload()
	p.Caveats["magiclink.intent"], p.Caveats["magiclink.prospective"] = "signup-if-allowed", "1"
	p.Caveats["magiclink.creation-digest"] = strings.Repeat("a", 64)
	p.Caveats["magiclink.email-policy-version"] = "3"
	for _, key := range []string{"magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
		p.Caveats[key] = "1"
	}
	first, err := MagicLinkScopeFromPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Subject, p.Resource, p.Caveats["magiclink.identifier"] = "new-prospective-user", "identity.magiclink/new-prospective-identifier", "new-prospective-identifier"
	p.Caveats["magiclink.creation-digest"] = strings.Repeat("b", 64)
	second, err := MagicLinkScopeFromPayload(p)
	if err != nil || first.Digest() != second.Digest() {
		t.Fatal("replacement escaped original mailbox/browser/policy supersession family", err)
	}
	for _, key := range []string{"magiclink.canonical-email", "magiclink.callback", "magiclink.flow", "magiclink.flow-binding", "magiclink.profile", "magiclink.email-policy-version"} {
		original := p.Caveats[key]
		switch key {
		case "magiclink.flow":
			p.Caveats[key] = "vutsrqponmlkjihgfedcba"
		case "magiclink.flow-binding", "magiclink.profile":
			p.Caveats[key] = strings.Repeat("3", 64)
		case "magiclink.email-policy-version":
			p.Caveats[key] = "4"
		default:
			p.Caveats[key] = original + "different"
		}
		foreign, err := MagicLinkScopeFromPayload(p)
		if err != nil || foreign.Digest() == first.Digest() {
			t.Fatal("foreign original scope borrowed signup supersession", key, err)
		}
		p.Caveats[key] = original
	}
	p.Caveats["magiclink.creation-digest"] = "invalid"
	if _, err := MagicLinkScopeFromPayload(p); err == nil {
		t.Fatal("family projection stopped validating full prospective creation structure")
	}
}

func TestMagicLinkSupersessionScopePreservesExactOriginalFlow(t *testing.T) {
	p := supersessionPayload()
	s, err := MagicLinkScopeFromPayload(p)
	if err != nil || s.Digest() == ([32]byte{}) {
		t.Fatal("valid scope rejected", err)
	}
	p.ID, p.CorrelationID = "another-token", "another-command"
	p.IssuedAt, p.ExpiresAt = time.Now(), time.Now().Add(time.Minute)
	p.Caveats["magiclink.factor-version"] = "2"
	resend, err := MagicLinkScopeFromPayload(p)
	if err != nil || resend.Digest() != s.Digest() {
		t.Fatal("resend changed stable scope", err)
	}
	for _, mutate := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Issuer = "https://foreign.example.test" },
		func(p *capability.Payload) { p.Audiences[0] = "foreign" },
		func(p *capability.Payload) { p.Tenant = "foreign" },
		func(p *capability.Payload) { p.Subject = "foreign" },
	} {
		changed := supersessionPayload()
		mutate(&changed)
		other, err := MagicLinkScopeFromPayload(changed)
		if err != nil || other.Digest() == s.Digest() {
			t.Fatal("foreign authority scope collapsed", err)
		}
	}
	for _, key := range []string{"magiclink.identifier", "magiclink.canonical-email", "magiclink.callback", "magiclink.intent", "magiclink.flow", "magiclink.flow-binding", "magiclink.profile"} {
		changed := supersessionPayload()
		if key == "magiclink.identifier" {
			changed.Resource = "identity.magiclink/another"
			changed.Caveats[key] = "another"
		} else if key == "magiclink.intent" {
			changed.Caveats[key] = "signup-if-allowed"
		} else if key == "magiclink.flow-binding" || key == "magiclink.profile" {
			changed.Caveats[key] = strings.Repeat("3", 64)
		} else {
			changed.Caveats[key] = "x" + changed.Caveats[key][1:]
		}
		other, err := MagicLinkScopeFromPayload(changed)
		if err == nil && other.Digest() == s.Digest() {
			t.Fatal("foreign scope collapsed", key)
		}
	}
	for _, mutate := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Version = 2 },
		func(p *capability.Payload) { p.Caveats = nil },
		func(p *capability.Payload) { p.Caveats["magiclink.flow"] = strings.Repeat("!", 22) },
		func(p *capability.Payload) { p.Bearer = true },
		func(p *capability.Payload) { p.MaxUses = 2 },
		func(p *capability.Payload) { p.Audiences = append(p.Audiences, "foreign") },
		func(p *capability.Payload) { p.Tenant = "" },
		func(p *capability.Payload) { p.Operation = "identity.password.reset-complete" },
		func(p *capability.Payload) { p.Caveats["magiclink.flow-binding"] = strings.Repeat("1", 65) },
		func(p *capability.Payload) { p.Caveats["magiclink.profile"] = strings.Repeat("A", 64) },
		func(p *capability.Payload) { p.Caveats["magiclink.callback"] = strings.Repeat("x", 4097) },
		func(p *capability.Payload) { p.Resource = "foreign" },
	} {
		changed := supersessionPayload()
		mutate(&changed)
		out, err := MagicLinkScopeFromPayload(changed)
		if err == nil || out.Digest() != ([32]byte{}) {
			t.Fatal("invalid scope exposed digest")
		}
	}
}

func FuzzMagicLinkSupersessionScope(f *testing.F) {
	f.Add("magiclink.intent", "signup-if-allowed")
	f.Add("magiclink.intent", "signup-or-signin")
	f.Add("magiclink.callback", "https://identity.example.test/callback")
	f.Add("magiclink.flow", strings.Repeat("!", 22))
	f.Add("magiclink.profile", strings.Repeat("A", 64))
	f.Add("magiclink.canonical-email", "\xff")
	f.Fuzz(func(t *testing.T, key, value string) {
		if len(key) > 128 || len(value) > 8192 {
			t.Skip()
		}
		p := supersessionPayload()
		p.Caveats[key] = value
		a, err := MagicLinkScopeFromPayload(p)
		b, again := MagicLinkScopeFromPayload(p)
		if (err == nil) != (again == nil) || a.Digest() != b.Digest() {
			t.Fatal("non-deterministic scope")
		}
		if err != nil && a.Digest() != ([32]byte{}) {
			t.Fatal("failed projection exposed scope")
		}
	})
}
