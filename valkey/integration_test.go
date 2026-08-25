//go:build integration

package valkey_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	capabilityvalkey "github.com/faustbrian/go-capability/valkey"
	valkeygo "github.com/valkey-io/valkey-go"
)

func TestValkeyConsumptionSurvivesClientRecreation(t *testing.T) {
	address := os.Getenv("VALKEY_ADDR")
	if address == "" {
		t.Fatal("VALKEY_ADDR is required")
	}
	first := openValkey(t, address)
	prefix := "capability-integration:"
	id := "integration-" + time.Now().UTC().Format("20060102150405.000000000")
	digest := sha256.Sum256([]byte(id))
	key := prefix + hex.EncodeToString(digest[:])
	t.Cleanup(func() {
		client, openErr := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: []string{address}})
		if openErr != nil {
			t.Errorf("cleanup valkey.NewClient() error = %v", openErr)
			return
		}
		defer client.Close()
		if err := client.Do(context.Background(), client.B().Del().Key(key).Build()).Error(); err != nil {
			t.Errorf("cleanup error = %v", err)
		}
	})
	store, err := capabilityvalkey.NewConsumptionStore(capabilityvalkey.Options{
		Client: valkeyEvaler{client: first}, KeyPrefix: prefix,
	})
	if err != nil {
		t.Fatalf("NewConsumptionStore() error = %v", err)
	}
	request := capability.Consumption{CapabilityID: id, MaxUses: 1, ExpiresAt: time.Now().Add(time.Minute).UTC()}
	if result, err := store.Consume(t.Context(), request); err != nil || result.Use != 1 {
		t.Fatalf("Consume(first) = %#v, %v", result, err)
	}
	first.Close()

	second := openValkey(t, address)
	defer second.Close()
	store, err = capabilityvalkey.NewConsumptionStore(capabilityvalkey.Options{
		Client: valkeyEvaler{client: second}, KeyPrefix: prefix,
	})
	if err != nil {
		t.Fatalf("NewConsumptionStore(recreated) error = %v", err)
	}
	if _, err := store.Consume(t.Context(), request); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatalf("Consume(after client recreation) error = %v", err)
	}
}

func TestValkeyConsumptionSurvivesCallerProcessExit(t *testing.T) {
	address := os.Getenv("VALKEY_ADDR")
	if address == "" {
		t.Fatal("VALKEY_ADDR is required")
	}
	prefix := "capability-process-integration:"
	id := os.Getenv("CAPABILITY_PROCESS_ID")
	if os.Getenv("CAPABILITY_VALKEY_PROCESS_CHILD") == "1" {
		client := openValkey(t, address)
		store, err := capabilityvalkey.NewConsumptionStore(capabilityvalkey.Options{
			Client: valkeyEvaler{client: client}, KeyPrefix: prefix,
		})
		if err != nil {
			t.Fatalf("NewConsumptionStore(child) error = %v", err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, os.Getenv("CAPABILITY_PROCESS_EXPIRY"))
		if err != nil {
			t.Fatalf("Parse(child expiry) error = %v", err)
		}
		request := capability.Consumption{CapabilityID: id, MaxUses: 1, ExpiresAt: expiresAt}
		if result, err := store.Consume(t.Context(), request); err != nil || result.Use != 1 {
			t.Fatalf("Consume(child) = %#v, %v", result, err)
		}
		os.Exit(23)
	}

	id = "process-" + time.Now().UTC().Format("20060102150405.000000000")
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond)
	digest := sha256.Sum256([]byte(id))
	key := prefix + hex.EncodeToString(digest[:])
	t.Cleanup(func() {
		client, openErr := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: []string{address}})
		if openErr != nil {
			t.Errorf("cleanup valkey.NewClient() error = %v", openErr)
			return
		}
		defer client.Close()
		if err := client.Do(context.Background(), client.B().Del().Key(key).Build()).Error(); err != nil {
			t.Errorf("cleanup error = %v", err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable() error = %v", err)
	}
	childContext, cancelChild := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelChild()
	command := exec.CommandContext(childContext, executable,
		"-test.run=^TestValkeyConsumptionSurvivesCallerProcessExit$", "-test.timeout=10s")
	command.Env = append(os.Environ(), "CAPABILITY_VALKEY_PROCESS_CHILD=1", "CAPABILITY_PROCESS_ID="+id, "CAPABILITY_PROCESS_EXPIRY="+expiresAt.Format(time.RFC3339Nano))
	if err := command.Run(); err == nil {
		t.Fatal("child process exited successfully")
	} else if childContext.Err() != nil {
		t.Fatalf("child process context = %v", childContext.Err())
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
		t.Fatalf("child process exit = %v", err)
	}
	client := openValkey(t, address)
	defer client.Close()
	store, err := capabilityvalkey.NewConsumptionStore(capabilityvalkey.Options{
		Client: valkeyEvaler{client: client}, KeyPrefix: prefix,
	})
	if err != nil {
		t.Fatalf("NewConsumptionStore(parent) error = %v", err)
	}
	request := capability.Consumption{CapabilityID: id, MaxUses: 1, ExpiresAt: expiresAt}
	if _, err := store.Consume(t.Context(), request); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatalf("Consume(after process exit) error = %v", err)
	}
}

type valkeyEvaler struct{ client valkeygo.Client }

func (adapter valkeyEvaler) Eval(ctx context.Context, script string, keys []string, arguments ...string) ([]string, error) {
	command := adapter.client.B().Eval().Script(script).Numkeys(int64(len(keys))).Key(keys...).Arg(arguments...).Build()
	messages, err := adapter.client.Do(ctx, command).ToArray()
	if err != nil {
		return nil, err
	}
	result := make([]string, len(messages))
	for index := range messages {
		result[index], err = messages[index].ToString()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func openValkey(t *testing.T, address string) valkeygo.Client {
	t.Helper()
	client, err := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: []string{address}})
	if err != nil {
		t.Fatalf("valkey.NewClient() error = %v", err)
	}
	if err := client.Do(t.Context(), client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		t.Fatalf("PING error = %v", err)
	}
	return client
}
