package valkey_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	capvalkey "github.com/faustbrian/go-capability/v2/valkey"
)

type admissionEvaler struct {
	*fakeEvaler
	calls int
}

func (client *admissionEvaler) Eval(ctx context.Context, script string, keys []string, arguments ...string) ([]string, error) {
	client.calls++
	return client.fakeEvaler.Eval(ctx, script, keys, arguments...)
}

func TestIssuerAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		issuer string
		valid  bool
	}{
		{"ascii255", strings.Repeat("a", 255), true},
		{"ascii256", strings.Repeat("a", 256), true},
		{"ascii257", strings.Repeat("a", 257), false},
		{"utf8bytes256", strings.Repeat("é", 128), true},
		{"utf8bytes257", strings.Repeat("é", 128) + "a", false},
		{"empty", "", false},
		{"invalidUTF8", string([]byte{0xff}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Run("constructor", func(t *testing.T) {
				client := &admissionEvaler{fakeEvaler: newFakeEvaler()}
				store, err := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: "boundary:", LegacyIssuer: test.issuer})
				if test.valid {
					if err != nil || store == nil {
						t.Fatalf("accepted legacy issuer: %v", err)
					}
				} else if !errors.Is(err, capability.ErrInvalidConfiguration) || store != nil {
					t.Fatalf("rejected legacy issuer: store=%v, error=%v", store, err)
				}
				if client.calls != 0 || len(client.state) != 0 {
					t.Fatal("constructor performed persistence work")
				}
			})
			t.Run("consume", func(t *testing.T) {
				client := &admissionEvaler{fakeEvaler: newFakeEvaler()}
				store, err := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: "boundary:", LegacyIssuer: "ordinary-issuer"})
				if err != nil {
					t.Fatal(err)
				}
				request := capability.Consumption{Issuer: test.issuer, CapabilityID: "id", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}
				result, err := store.Consume(context.Background(), request)
				if !test.valid {
					if !errors.Is(err, capability.ErrInvalidConfiguration) || result != (capability.ConsumptionResult{}) {
						t.Fatalf("rejected issuer: result=%#v, error=%v", result, err)
					}
					if client.calls != 0 || len(client.state) != 0 {
						t.Fatal("invalid issuer reached Eval")
					}
					return
				}
				if err != nil || result != (capability.ConsumptionResult{Use: 1, Remaining: 1}) || client.calls != 1 || len(client.state) != 1 {
					t.Fatalf("accepted issuer: result=%#v, error=%v", result, err)
				}
			})
		})
	}
}

func TestBoundaryIssuerPreservesLegacyQuotaAndExactNamespace(t *testing.T) {
	client := &admissionEvaler{fakeEvaler: newFakeEvaler()}
	legacyIssuer := strings.Repeat("é", 128)
	otherIssuer := strings.Repeat("à", 128)
	store, err := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: "boundary:", LegacyIssuer: legacyIssuer})
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	legacyDigest := sha256.Sum256([]byte("id"))
	legacyKey := "boundary:" + hex.EncodeToString(legacyDigest[:])
	otherDigest := sha256.Sum256([]byte("capability-consumption-v2\x00256:" + otherIssuer + "2:id"))
	otherKey := "boundary:v2:" + hex.EncodeToString(otherDigest[:])
	client.state[legacyKey] = [3]int64{1, 2, expiry.UnixMilli()}
	for _, test := range []struct {
		issuer, key string
		want        capability.ConsumptionResult
	}{
		{legacyIssuer, legacyKey, capability.ConsumptionResult{Use: 2}},
		{otherIssuer, otherKey, capability.ConsumptionResult{Use: 1, Remaining: 1}},
	} {
		request := capability.Consumption{Issuer: test.issuer, CapabilityID: "id", MaxUses: 2, ExpiresAt: expiry}
		result, err := store.Consume(context.Background(), request)
		if err != nil || result != test.want || client.lastKey != test.key {
			t.Fatalf("boundary namespace: result=%#v, error=%v", result, err)
		}
		before := client.state[test.key]
		for _, conflict := range []capability.Consumption{
			{Issuer: test.issuer, CapabilityID: "id", MaxUses: 3, ExpiresAt: expiry},
			{Issuer: test.issuer, CapabilityID: "id", MaxUses: 2, ExpiresAt: expiry.Add(time.Minute)},
		} {
			result, err := store.Consume(context.Background(), conflict)
			if !errors.Is(err, capability.ErrReplayConflict) || result != (capability.ConsumptionResult{}) || client.state[test.key] != before {
				t.Fatal("conflict consumed or changed boundary quota")
			}
		}
	}
	result, err := store.Consume(context.Background(), capability.Consumption{Issuer: legacyIssuer, CapabilityID: "id", MaxUses: 2, ExpiresAt: expiry})
	if !errors.Is(err, capability.ErrReplayExhausted) || result != (capability.ConsumptionResult{}) || client.state[legacyKey][0] != 2 || client.state[otherKey][0] != 1 || len(client.state) != 2 {
		t.Fatal("boundary ownership reset or merged quota")
	}
}
