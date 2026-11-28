package identitycapability

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestConfirmOAuthProxyOriginGrantTerminalRequiresExactWork(t *testing.T) {
	if err := ConfirmOAuthProxyOriginGrantTerminal(t.Context(), kernel.Work{}, nil, identity.Command{}, kernel.CapabilityPlan{}); err == nil {
		t.Fatal("unprepared Work established a terminal proxy grant")
	}
}
