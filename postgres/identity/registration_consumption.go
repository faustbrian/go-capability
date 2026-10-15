package identitycapability

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PrepareRegistrationVerificationConsumption reauthenticates the exact original
// anonymous signup proof for a current native email confirmation binding. The
// action is identity.email.verification-confirm, schema is
// identity.email.verification-confirm.native-v1 version 1, and RecordID is the
// signed identifier. Tenant and UserID must equal the signed target. The
// envelope must come from the authenticated original intent, not an alternate
// signature, and replayKeyVersion from original durable issuance, never an
// active-key default. No session caveats or rewritten proof are introduced.
//
// Configured signature, audience, time and revocation policy apply. The original
// identity.identifier.verify purpose, expiry, envelope and replay identity are
// preserved. The owning email workflow must first authorize the full original
// mailbox/redirect/version commitment. This metadata alone is not that proof,
// current identity/session authority, a usable grant or a command receipt.
// The sole Coordinator must still match durable issuance, fence current account
// and identifier state and consume atomically with the protected mutation.
//
// No SQL, reservation, signing, custody transfer, consumption or goroutine runs.
// Calls are concurrent-safe and bounded by PreparationTimeout and earlier
// deadlines. Invalid composition is InvalidInput; invalid proof/profile is
// Forbidden; verification failure/panic is Unavailable. Cancellation remains
// typed and redacted. Every failure returns a zero plan; no raw bearer escapes.
func (i *Issuer) PrepareRegistrationVerificationConsumption(ctx context.Context, binding identity.CommandBinding, proof capability.Proof, envelope [32]byte, replayKeyVersion uint32) (kernel.CapabilityPlan, error) {
	operation := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if envelope == ([32]byte{}) || binding.ValidateFor(operation) != nil {
		return kernel.CapabilityPlan{}, invalid()
	}
	return i.prepareConsumptionProfile(ctx, binding, envelope, proof, replayKeyVersion, "registration-v1")
}

func registrationConsumptionProfile(v capability.Payload) bool {
	return emailConsumptionProfile(v, "registration-v1")
}

// Supersession is an explicit fifth management caveat. Signup retains its
// original four-caveat grammar and cannot borrow management authority.
func emailConsumptionProfile(v capability.Payload, profile string) bool {
	return emailConsumptionAction(v, profile, "identity.email.verification-confirm")
}

func emailConsumptionAction(v capability.Payload, profile, action string) bool {
	if action != "identity.email.verification-confirm" && (profile != "management-v1" || action != "identity.email.change-confirm") || !emailPayloadShape(v, profile) || v.Caveats["email.confirm_operation"] != action {
		return false
	}
	if _, selected := v.Caveats["email.supersession"]; selected {
		_, err := ManagedEmailScopeFromPayload(v)
		return err == nil
	}
	return true
}

func emailPayloadShape(v capability.Payload, profile string) bool {
	if profile != "registration-v1" && profile != "management-v1" {
		return false
	}
	_, selected := v.Caveats["email.supersession"]
	count := 4
	if selected {
		if profile != "management-v1" || len(v.Caveats["email.supersession"]) != 64 {
			return false
		}
		count++
	}
	confirm := v.Caveats["email.confirm_operation"]
	if v.Version != 1 || len(v.Caveats) != count || v.Caveats["email.profile"] != profile || (confirm != "identity.email.verification-confirm" && (profile != "management-v1" || confirm != "identity.email.change-confirm")) || len(v.Caveats["email.intent"]) != 64 || len(v.Caveats["email.binding_key_version"]) == 0 || len(v.Caveats["email.binding_key_version"]) > 10 {
		return false
	}
	intent, err := hex.DecodeString(v.Caveats["email.intent"])
	version, versionErr := strconv.ParseUint(v.Caveats["email.binding_key_version"], 10, 32)
	return err == nil && len(intent) == 32 && strings.ToLower(v.Caveats["email.intent"]) == v.Caveats["email.intent"] && versionErr == nil && version > 0 && strconv.FormatUint(version, 10) == v.Caveats["email.binding_key_version"]
}
