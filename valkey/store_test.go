package valkey_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	capvalkey "github.com/faustbrian/go-capability/valkey"
)

func TestStoreConsumesAtomicallyThroughOneDeclaredValkeyKey(t *testing.T) {
	client := newFakeEvaler()
	store, err := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: "cap-use:"})
	if err != nil {
		t.Fatalf("NewConsumptionStore() error = %v", err)
	}
	request := capability.Consumption{CapabilityID: "cap-1", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	const contenders = 24
	var accepted atomic.Int64
	var exhausted atomic.Int64
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			_, consumeErr := store.Consume(context.Background(), request)
			switch {
			case consumeErr == nil:
				accepted.Add(1)
			case errors.Is(consumeErr, capability.ErrReplayExhausted):
				exhausted.Add(1)
			default:
				t.Errorf("Consume() error = %v", consumeErr)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || exhausted.Load() != contenders-1 {
		t.Fatalf("accepted = %d, exhausted = %d", accepted.Load(), exhausted.Load())
	}
	if client.lastKey == "cap-use:cap-1" || len(client.lastKey) != len("cap-use:")+64 {
		t.Fatalf("declared key = %q", client.lastKey)
	}
}

func TestStoreMapsConflictOutageAndMalformedResponses(t *testing.T) {
	client := newFakeEvaler()
	store, _ := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: "cap-use:"})
	request := capability.Consumption{CapabilityID: "cap-2", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := store.Consume(context.Background(), request); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	conflict := request
	conflict.MaxUses = 3
	if _, err := store.Consume(context.Background(), conflict); !errors.Is(err, capability.ErrReplayConflict) {
		t.Fatalf("Consume(conflict) error = %v", err)
	}
	client.failure = errors.New("connection lost")
	if _, err := store.Consume(context.Background(), request); !errors.Is(err, client.failure) {
		t.Fatalf("Consume(outage) error = %v", err)
	}
	client.failure = nil
	client.response = []string{"unexpected"}
	if _, err := store.Consume(context.Background(), request); !errors.Is(err, capability.ErrAdapterProtocol) {
		t.Fatalf("Consume(malformed response) error = %v", err)
	}
}

func TestStoreValidatesConfigurationRequestsAndEveryResponseState(t *testing.T) {
	client := newFakeEvaler()
	for name, options := range map[string]capvalkey.Options{
		"nil client":      {KeyPrefix: "cap:"},
		"empty prefix":    {Client: client},
		"cluster braces":  {Client: client, KeyPrefix: "cap:{slot}"},
		"control":         {Client: client, KeyPrefix: "cap:\n"},
		"space boundary":  {Client: client, KeyPrefix: " "},
		"delete boundary": {Client: client, KeyPrefix: string(rune(0x7f))},
		"non ascii":       {Client: client, KeyPrefix: "cäp:"},
		"oversized":       {Client: client, KeyPrefix: string(make([]byte, 65))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := capvalkey.NewConsumptionStore(options); !errors.Is(err, capability.ErrInvalidConfiguration) {
				t.Fatalf("NewConsumptionStore() error = %v", err)
			}
		})
	}
	for name, prefix := range map[string]string{
		"64 bytes":      strings.Repeat("a", 64),
		"lowest ASCII":  "!",
		"highest ASCII": "~",
	} {
		t.Run("valid prefix "+name, func(t *testing.T) {
			if _, err := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: prefix}); err != nil {
				t.Fatalf("NewConsumptionStore() error = %v", err)
			}
		})
	}
	store, _ := capvalkey.NewConsumptionStore(capvalkey.Options{Client: client, KeyPrefix: "cap:"})
	valid := capability.Consumption{CapabilityID: "cap", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, test := range map[string]struct {
		ctx     context.Context
		request capability.Consumption
	}{
		"nil context":     {request: valid},
		"canceled":        {ctx: ctx, request: valid},
		"empty ID":        {ctx: context.Background(), request: capability.Consumption{MaxUses: 1, ExpiresAt: valid.ExpiresAt}},
		"zero uses":       {ctx: context.Background(), request: capability.Consumption{CapabilityID: "cap", ExpiresAt: valid.ExpiresAt}},
		"zero expiry":     {ctx: context.Background(), request: capability.Consumption{CapabilityID: "cap", MaxUses: 1}},
		"negative expiry": {ctx: context.Background(), request: capability.Consumption{CapabilityID: "cap", MaxUses: 1, ExpiresAt: time.Unix(-1, 0)}},
		"epoch expiry":    {ctx: context.Background(), request: capability.Consumption{CapabilityID: "cap", MaxUses: 1, ExpiresAt: time.UnixMilli(0)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Consume(test.ctx, test.request); err == nil {
				t.Fatal("Consume() error = nil")
			}
		})
	}
	exactBoundary := valid
	exactBoundary.CapabilityID = string(make([]byte, 256))
	if result, err := store.Consume(context.Background(), exactBoundary); err != nil || result.Use != 1 || result.Remaining != 1 {
		t.Fatalf("Consume(256-byte ID) = %#v, %v", result, err)
	}
	exactBoundary = valid
	exactBoundary.ExpiresAt = time.UnixMilli(1)
	client.response = []string{"consumed", "1", "1"}
	if result, err := store.Consume(context.Background(), exactBoundary); err != nil || result.Use != 1 || result.Remaining != 1 {
		t.Fatalf("Consume(positive epoch boundary) = %#v, %v", result, err)
	}
	client.response = nil
	for name, response := range map[string][]string{
		"expired":       {"expired", "0", "0"},
		"exhausted":     {"exhausted", "0", "0"},
		"unknown":       {"other", "0", "0"},
		"bad use":       {"consumed", "x", "0"},
		"bad remaining": {"consumed", "1", "x"},
		"zero use":      {"consumed", "0", "2"},
		"too many":      {"consumed", "3", "0"},
		"bad sum":       {"consumed", "1", "0"},
	} {
		t.Run(name, func(t *testing.T) {
			client.response = response
			_, err := store.Consume(context.Background(), valid)
			if name == "expired" || name == "exhausted" {
				if !errors.Is(err, capability.ErrReplayExhausted) {
					t.Fatalf("Consume() error = %v", err)
				}
				return
			}
			if !errors.Is(err, capability.ErrAdapterProtocol) {
				t.Fatalf("Consume() error = %v", err)
			}
		})
	}
}

type fakeEvaler struct {
	mu       sync.Mutex
	state    map[string][3]int64
	lastKey  string
	failure  error
	response []string
}

func newFakeEvaler() *fakeEvaler { return &fakeEvaler{state: make(map[string][3]int64)} }

func (client *fakeEvaler) Eval(_ context.Context, _ string, keys []string, arguments ...string) ([]string, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.failure != nil {
		return nil, client.failure
	}
	if client.response != nil {
		return client.response, nil
	}
	client.lastKey = keys[0]
	maximum, _ := strconv.ParseInt(arguments[0], 10, 64)
	expires, _ := strconv.ParseInt(arguments[1], 10, 64)
	record, found := client.state[keys[0]]
	if found && (record[1] != maximum || record[2] != expires) {
		return []string{"conflict", "0", "0"}, nil
	}
	if !found {
		record = [3]int64{0, maximum, expires}
	}
	if record[0] >= maximum {
		return []string{"exhausted", "0", "0"}, nil
	}
	record[0]++
	client.state[keys[0]] = record
	return []string{"consumed", strconv.FormatInt(record[0], 10), strconv.FormatInt(maximum-record[0], 10)}, nil
}
