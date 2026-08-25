// Package valkey provides atomic bounded-use consumption through one Valkey
// EVAL operation. Client libraries adapt their result type to Evaler.
package valkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/faustbrian/go-capability"
)

const consumeScript = `
local now = redis.call('TIME')
local now_ms = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
local maximum = tonumber(ARGV[1])
local expires_at = tonumber(ARGV[2])
if expires_at <= now_ms then
    return {'expired', '0', '0'}
end

local current = redis.call('HMGET', KEYS[1], 'uses', 'max_uses', 'expires_at')
if current[1] then
    local uses = tonumber(current[1])
    local stored_maximum = tonumber(current[2])
    local stored_expiry = tonumber(current[3])
    if stored_maximum ~= maximum or stored_expiry ~= expires_at then
        return {'conflict', '0', '0'}
    end
    if uses >= maximum then
        return {'exhausted', '0', '0'}
    end
    uses = uses + 1
    redis.call('HSET', KEYS[1], 'uses', uses)
    return {'consumed', tostring(uses), tostring(maximum - uses)}
end

redis.call('HSET', KEYS[1], 'uses', 1, 'max_uses', maximum, 'expires_at', expires_at)
redis.call('PEXPIREAT', KEYS[1], expires_at)
return {'consumed', '1', tostring(maximum - 1)}
`

// Evaler executes one script with every accessed key declared in keys and
// normalizes the RESP array reply to strings. Implementations must preserve
// context cancellation and must not retry writes after unknown outcomes.
type Evaler interface {
	Eval(context.Context, string, []string, ...string) ([]string, error)
}

// Options configures Valkey key ownership.
type Options struct {
	Client    Evaler
	KeyPrefix string
}

// ConsumptionStore atomically consumes bounded capabilities in Valkey.
type ConsumptionStore struct {
	client Evaler
	prefix string
}

// NewConsumptionStore validates a client and fixed key prefix.
func NewConsumptionStore(options Options) (*ConsumptionStore, error) {
	if options.Client == nil || !validPrefix(options.KeyPrefix) {
		return nil, capability.ErrInvalidConfiguration
	}
	return &ConsumptionStore{client: options.Client, prefix: options.KeyPrefix}, nil
}

// Consume executes one constant script against one declared, digest-derived key.
func (store *ConsumptionStore) Consume(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
	if err := validateRequest(ctx, request); err != nil {
		return capability.ConsumptionResult{}, err
	}
	digest := sha256.Sum256([]byte(request.CapabilityID))
	key := store.prefix + hex.EncodeToString(digest[:])
	response, err := store.client.Eval(
		ctx, consumeScript, []string{key},
		strconv.FormatUint(uint64(request.MaxUses), 10),
		strconv.FormatInt(request.ExpiresAt.UnixMilli(), 10),
	)
	if err != nil {
		return capability.ConsumptionResult{}, err
	}
	if len(response) != 3 {
		return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
	}
	switch response[0] {
	case "conflict":
		return capability.ConsumptionResult{}, capability.ErrReplayConflict
	case "exhausted", "expired":
		return capability.ConsumptionResult{}, capability.ErrReplayExhausted
	case "consumed":
		use, useErr := strconv.ParseUint(response[1], 10, 32)
		remaining, remainingErr := strconv.ParseUint(response[2], 10, 32)
		if useErr != nil {
			return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
		}
		if remainingErr != nil {
			return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
		}
		if use == 0 {
			return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
		}
		if use > uint64(request.MaxUses) {
			return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
		}
		if use+remaining != uint64(request.MaxUses) {
			return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
		}
		return capability.ConsumptionResult{Use: uint32(use), Remaining: uint32(remaining)}, nil
	default:
		return capability.ConsumptionResult{}, capability.ErrAdapterProtocol
	}
}

func validateRequest(ctx context.Context, request capability.Consumption) error {
	if ctx == nil || request.CapabilityID == "" || len(request.CapabilityID) > 256 ||
		!utf8.ValidString(request.CapabilityID) || request.MaxUses == 0 ||
		request.ExpiresAt.IsZero() || request.ExpiresAt.UnixMilli() <= 0 {
		return capability.ErrInvalidConfiguration
	}
	return ctx.Err()
}

func validPrefix(prefix string) bool {
	if prefix == "" || len(prefix) > 64 || !utf8.ValidString(prefix) ||
		strings.ContainsAny(prefix, "{}") {
		return false
	}
	for _, character := range prefix {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}
