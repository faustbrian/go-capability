package identitycapability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

const issuancePreparationHeader = "ICIP1"
const maximumIssuancePreparation = 512 << 10

// PreparationVerificationKey pins local signing-verification material and key
// lifecycle policy. Exactly one of HMAC or Ed25519 must be populated.
type PreparationVerificationKey struct {
	// ID identifies original signing material under the codec's trusted issuer.
	ID string
	// HMAC supplies a nonzero 32..512-byte secret key instead of Ed25519 material.
	// Construction copies it; the key must differ from replay and envelope keys.
	HMAC []byte
	// Ed25519 supplies a 32-byte public verification key instead of HMAC material.
	Ed25519 []byte
	// Disabled denies verification with this key in the constructed codec.
	Disabled bool
	// Revoked marks this retained key as revoked for original-envelope verification.
	Revoked bool
	// NotBefore optionally limits the key's earliest accepted verification time.
	NotBefore time.Time
	// NotAfter optionally limits the key's latest accepted verification time.
	NotAfter time.Time
}

// IssuancePreparationConfig selects local encrypted custody and verification.
// Retain referenced keys for the original journal's entire recovery lifetime.
type IssuancePreparationConfig struct {
	// Deployment binds encrypted preparation to one trusted deployment identifier.
	Deployment string
	// ActiveEnvelopeKey names the retained envelope key used for new checkpoints.
	ActiveEnvelopeKey string
	// EnvelopeKeys holds 1..32 nonzero 32-byte encryption keys, copied on construction.
	// Keep referenced keys until the original journal no longer requires recovery.
	EnvelopeKeys map[string][]byte
	// VerificationKeys retains 1..32 local policies for authenticating original grants.
	VerificationKeys []PreparationVerificationKey
	// Clock provides current trusted time locally and must support concurrent calls.
	Clock func() time.Time
}

// IssuancePreparationCodec owns no journal, SQL connection or remote provider.
// Restored custody permits staging only, never another bearer transfer.
type IssuancePreparationCodec struct {
	issuer       *Issuer
	deployment   string
	active       string
	envelopes    *secretenvelope.Service
	verification *capability.KeySet
	clock        func() time.Time
}

// NewIssuancePreparationCodec snapshots bounded local cryptographic policy.
func NewIssuancePreparationCodec(i *Issuer, c IssuancePreparationConfig) (*IssuancePreparationCodec, error) {
	if i == nil || i.service == nil || !issuerText(c.Deployment) || !issuerText(c.ActiveEnvelopeKey) || c.Clock == nil || len(c.EnvelopeKeys) < 1 || len(c.EnvelopeKeys) > 32 || len(c.VerificationKeys) < 1 || len(c.VerificationKeys) > 32 {
		return nil, invalid()
	}
	for id, key := range c.EnvelopeKeys {
		if !issuerText(id) || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
			return nil, invalid()
		}
		for _, replay := range i.keys {
			if bytes.Equal(key, replay[:]) {
				return nil, invalid()
			}
		}
		for _, verification := range c.VerificationKeys {
			if bytes.Equal(key, verification.HMAC) {
				return nil, invalid()
			}
		}
	}
	if _, ok := c.EnvelopeKeys[c.ActiveEnvelopeKey]; !ok {
		return nil, invalid()
	}
	provider, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		return nil, invalid()
	}
	envelopes, err := secretenvelope.NewService(provider)
	if err != nil {
		return nil, invalid()
	}
	keys := make([]capability.Key, 0, len(c.VerificationKeys))
	for _, key := range c.VerificationKeys {
		var verifier capability.Verifier
		if len(key.HMAC) >= 32 && len(key.HMAC) <= 512 && len(key.Ed25519) == 0 && !bytes.Equal(key.HMAC, make([]byte, len(key.HMAC))) {
			for _, replay := range i.keys {
				if bytes.Equal(key.HMAC, replay[:]) {
					return nil, invalid()
				}
			}
			verifier, err = capability.NewHMACSHA256Verifier(key.HMAC)
		} else if len(key.HMAC) == 0 && len(key.Ed25519) == ed25519.PublicKeySize {
			verifier, err = capability.NewEd25519Verifier(ed25519.PublicKey(key.Ed25519))
		} else {
			return nil, invalid()
		}
		if err != nil {
			return nil, invalid()
		}
		keys = append(keys, capability.Key{Issuer: i.issuer, ID: key.ID, Verifier: verifier, Disabled: key.Disabled, Revoked: key.Revoked, NotBefore: key.NotBefore, NotAfter: key.NotAfter})
	}
	verification, err := capability.NewKeySet(keys)
	if err != nil {
		return nil, invalid()
	}
	return &IssuancePreparationCodec{issuer: i, deployment: c.Deployment, active: c.ActiveEnvelopeKey, envelopes: envelopes, verification: verification, clock: c.Clock}, nil
}

// CheckpointPreparation irreversibly transfers every original proof to local
// encrypted journal custody and optionally to synchronous delivery encryption.
// The callback borrows bytes for its call only, must honor cancellation and
// must not send or reveal before commit. Failure invalidates the entire batch.
// Call this instead of TransferForDelivery; do not checkpoint transferred proofs.
func (c *IssuancePreparationCodec) CheckpointPreparation(ctx context.Context, p PreparedIssuance, generation uint64, encrypt func(context.Context, uint16, []byte) error) (wire []byte, err error) {
	if c == nil || c.envelopes == nil || ctx == nil || p.state == nil || p.state.owner != c.issuer || p.state.preparationFailed || generation == 0 {
		return nil, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, c.issuer.timeout)
	defer cancel()
	if err = issuerContext(ctx); err != nil {
		return nil, err
	}
	s := p.state
	if s.checkpointStarted {
		if s.checkpointGeneration != generation || s.checkpointOwner != c || len(s.checkpointWire) == 0 {
			return nil, invalid()
		}
		return append([]byte(nil), s.checkpointWire...), nil
	}
	aad, err := c.preparationContext(s.binding, generation, s.plan)
	if err != nil || len(s.proofs) != len(s.plan.Grants) {
		return nil, invalid()
	}
	s.checkpointStarted = true
	s.checkpointGeneration = generation
	s.checkpointOwner = c
	// One bounded allocation prevents abandoned backing arrays containing
	// plaintext when append grows the batch; the entire buffer is cleared.
	plain := make([]byte, 2, 2+len(s.proofs)*(8+capability.DefaultLimits().MaxTokenBytes))
	binary.BigEndian.PutUint16(plain, uint16(len(s.proofs)))
	defer func() {
		clear(plain)
		if recover() != nil {
			err = identity.UnavailableError{}
			wire = nil
		}
		if err != nil {
			s.preparationFailed = true
			for _, proof := range s.proofs {
				_ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			}
		}
	}()
	for index, proof := range s.proofs {
		err = proof.Transfer(ctx, func(ctx context.Context, token []byte) error {
			if len(token) == 0 || len(token) > capability.DefaultLimits().MaxTokenBytes {
				return invalid()
			}
			grant, e := c.verify(ctx, token, s.binding, s.plan, index)
			if e != nil || grant.EnvelopeDigest() != s.grants[index].EnvelopeDigest() {
				return invalid()
			}
			plain = binary.BigEndian.AppendUint32(plain, s.plan.Grants[index].ReplayKeyVersion)
			plain = binary.BigEndian.AppendUint32(plain, uint32(len(token)))
			plain = append(plain, token...)
			if encrypt != nil {
				return encrypt(ctx, uint16(index), token)
			}
			return nil
		})
		if err != nil {
			return nil, issuerFailure(ctx)
		}
	}
	envelope, e := c.envelopes.Encrypt(ctx, secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: c.active, Context: aad})
	if e != nil {
		return nil, issuerFailure(ctx)
	}
	encoded, e := envelope.MarshalBinary()
	if e != nil || len(encoded)+len(issuancePreparationHeader) > maximumIssuancePreparation {
		return nil, invalid()
	}
	if err = issuerContext(ctx); err != nil {
		return nil, err
	}
	wire = append([]byte(issuancePreparationHeader), encoded...)
	s.checkpointWire = append([]byte(nil), wire...)
	return wire, nil
}

// RestorePreparation authenticates the original encrypted checkpoint, binding,
// generation and plan using local retained keys. It performs no SQL, network,
// signing, entropy acquisition, delivery or consumption. Expired grants fail
// closed; current transaction authority remains the coordinator's concern.
func (c *IssuancePreparationCodec) RestorePreparation(ctx context.Context, b identity.CommandBinding, generation uint64, plan identitypostgres.CapabilityIssuancePlan, wire []byte) (out PreparedIssuance, err error) {
	if c == nil || c.envelopes == nil || ctx == nil || generation == 0 || len(wire) <= len(issuancePreparationHeader) || len(wire) > maximumIssuancePreparation || string(wire[:len(issuancePreparationHeader)]) != issuancePreparationHeader {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, c.issuer.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out = PreparedIssuance{}
			err = identity.UnavailableError{}
		}
	}()
	if err = issuerContext(ctx); err != nil {
		return out, err
	}
	aad, e := c.preparationContext(b, generation, plan)
	if e != nil {
		return out, invalid()
	}
	envelope, e := secretenvelope.ParseEnvelope(wire[len(issuancePreparationHeader):])
	if e != nil {
		return out, invalid()
	}
	plain, e := c.envelopes.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	if e != nil {
		return out, issuerFailure(ctx)
	}
	defer clear(plain)
	if len(plain) < 2 || len(plain) > maximumIssuancePreparation || int(binary.BigEndian.Uint16(plain)) != len(plan.Grants) {
		return out, invalid()
	}
	remaining := plain[2:]
	p := &preparedIssuance{owner: c.issuer, binding: b, plan: plan, checkpointStarted: true, checkpointGeneration: generation, checkpointOwner: c, checkpointWire: append([]byte(nil), wire...)}
	p.plan.Grants = append([]identitypostgres.CapabilityPlan(nil), plan.Grants...)
	for index, metadata := range plan.Grants {
		if len(remaining) < 8 || binary.BigEndian.Uint32(remaining) != metadata.ReplayKeyVersion {
			return out, invalid()
		}
		length := uint64(binary.BigEndian.Uint32(remaining[4:]))
		remaining = remaining[8:]
		if length == 0 || length > uint64(capability.DefaultLimits().MaxTokenBytes) || length > uint64(len(remaining)) {
			return out, invalid()
		}
		grant, e := c.verify(ctx, remaining[:int(length)], b, plan, index)
		if e != nil {
			return out, issuerFailure(ctx)
		}
		p.grants = append(p.grants, grant)
		remaining = remaining[int(length):]
	}
	if len(remaining) != 0 {
		return out, invalid()
	}
	if err = issuerContext(ctx); err != nil {
		return out, err
	}
	return PreparedIssuance{state: p}, nil
}

func (c *IssuancePreparationCodec) verify(ctx context.Context, token []byte, b identity.CommandBinding, plan identitypostgres.CapabilityIssuancePlan, index int) (capability.Grant, error) {
	grant, err := capability.Verify(ctx, string(token), c.verification, capability.VerifyOptions{Issuer: c.issuer.issuer, Now: c.clock(), Limits: c.issuer.limits})
	if err != nil {
		return capability.Grant{}, invalid()
	}
	subject, valid := issuerPlanSubject(b, plan)
	if !valid {
		return capability.Grant{}, invalid()
	}
	metadata, err := c.issuer.grantPlan(b, subject, grant, plan.Grants[index].ReplayKeyVersion)
	if err != nil || metadata != plan.Grants[index] {
		return capability.Grant{}, invalid()
	}
	return grant, nil
}

func (c *IssuancePreparationCodec) preparationContext(b identity.CommandBinding, generation uint64, plan identitypostgres.CapabilityIssuancePlan) (secretenvelope.Context, error) {
	if err := c.issuer.ValidateCapabilityIssuance(b, plan); err != nil {
		return secretenvelope.Context{}, invalid()
	}
	// Bound every input before serializing. The full binding and immutable plan
	// enter AAD, including fields not used to select the prospective subject.
	encoded := make([]byte, 0, 4096)
	for _, field := range []string{string(b.CommandID), string(b.TenantID), string(b.UserID), string(b.AnonymousFlowID), string(b.ActorID), string(b.ActorKind), string(b.OperationID), string(b.PolicyID), string(b.SchemaID), string(b.CorrelationID), string(b.RecordID), string(b.LinkMode), string(plan.RegistrationUserID), plan.Contributor.Owner, plan.Contributor.ContractID} {
		if len(field) > 256 {
			return secretenvelope.Context{}, invalid()
		}
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
		encoded = append(encoded, field...)
	}
	for _, version := range []uint64{uint64(b.PolicyVersion), uint64(b.SchemaVersion), uint64(plan.Contributor.Version)} {
		encoded = binary.BigEndian.AppendUint64(encoded, version)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(plan.Grants)))
	for _, grant := range plan.Grants {
		for _, field := range []string{grant.CapabilityID, string(grant.Purpose)} {
			if len(field) > 256 {
				return secretenvelope.Context{}, invalid()
			}
			encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
			encoded = append(encoded, field...)
		}
		encoded = binary.BigEndian.AppendUint32(encoded, grant.ReplayKeyVersion)
		encoded = append(encoded, grant.ReplayDigest[:]...)
		encoded = append(encoded, grant.ProofFingerprint[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(grant.ExpiresAt.Unix()))
		encoded = binary.BigEndian.AppendUint32(encoded, grant.MaxUses)
	}
	// Append only for the new profile so historical ordinary/signup AAD stays
	// byte-identical. The tagged selection prevents retargeting encrypted custody.
	if plan.ResetRecipientUserID != "" {
		for _, field := range []string{"reset-recipient-v1", string(plan.ResetRecipientUserID)} {
			encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
			encoded = append(encoded, field...)
		}
	}
	if plan.MagicLinkRecipientUserID != "" {
		for _, field := range []string{"magic-link-recipient-v1", string(plan.MagicLinkRecipientUserID)} {
			encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
			encoded = append(encoded, field...)
		}
	}
	if plan.MFAContinuationUserID != "" {
		for _, field := range []string{"mfa-continuation-v1", string(plan.MFAContinuationUserID)} {
			encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
			encoded = append(encoded, field...)
		}
	}
	digest := sha256.Sum256(encoded)
	return secretenvelope.NewContext(map[string]string{"profile": "identity-capability-preparation-v1", "deployment": c.deployment, "audience": c.issuer.audience, "generation": strconv.FormatUint(generation, 10), "binding-and-plan": hex.EncodeToString(digest[:])})
}

// Format hides verification key material and lifecycle metadata.
func (PreparationVerificationKey) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }

// MarshalJSON rejects implicit verification-key export.
func (PreparationVerificationKey) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MarshalText rejects implicit verification-key export.
func (PreparationVerificationKey) MarshalText() ([]byte, error) { return nil, invalid() }

// LogValue redacts verification key material and lifecycle metadata.
func (PreparationVerificationKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Format hides envelope and verification configuration.
func (IssuancePreparationConfig) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }

// MarshalJSON rejects implicit custody-configuration export.
func (IssuancePreparationConfig) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MarshalText rejects implicit custody-configuration export.
func (IssuancePreparationConfig) MarshalText() ([]byte, error) { return nil, invalid() }

// LogValue redacts envelope and verification configuration.
func (IssuancePreparationConfig) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Format hides codec keys and deployment configuration.
func (*IssuancePreparationCodec) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }

// MarshalJSON rejects implicit codec export.
func (*IssuancePreparationCodec) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MarshalText rejects implicit codec export.
func (*IssuancePreparationCodec) MarshalText() ([]byte, error) { return nil, invalid() }

// LogValue redacts codec keys and deployment configuration.
func (*IssuancePreparationCodec) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
