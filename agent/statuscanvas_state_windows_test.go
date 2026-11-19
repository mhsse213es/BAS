//go:build windows

package main

import (
	"strings"
	"testing"

	"audspect/agent/statusclient"
)

// A machine the server has retired must not look healthy. It used to fall through to "Idle", green, "Agent healthy
// and connected" while the console showed it retired.
func TestRetiredAgentIsNotShownAsHealthy(t *testing.T) {
	s := statusclient.StatusResponse{ServerConnected: true, State: "retired"}
	if got := stateLabel(s); got != "Retired" {
		t.Errorf("label = %q, want Retired", got)
	}
	if stateColor(s) != colDanger {
		t.Error("a retired agent must not use the success colour")
	}
	d := stateDescription(s)
	if strings.Contains(d, "healthy") || !strings.Contains(strings.ToLower(d), "reinstall") {
		t.Errorf("description = %q, want a message that says it was removed and how to bring it back", d)
	}
}

func TestOrdinaryStatesKeepTheirWording(t *testing.T) {
	healthy := statusclient.StatusResponse{ServerConnected: true, State: "active"}
	if stateLabel(healthy) != "Active" || !strings.Contains(stateDescription(healthy), "healthy and connected") {
		t.Errorf("active agent: %q / %q", stateLabel(healthy), stateDescription(healthy))
	}
	if stateLabel(statusclient.StatusResponse{ServerConnected: false}) != "Disconnected" {
		t.Error("a disconnected agent must still say Disconnected")
	}
}
