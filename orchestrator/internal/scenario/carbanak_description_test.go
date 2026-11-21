package scenario

import (
	"os"
	"strings"
	"testing"
)

// The Carbanak chain's description must match what Stage 8 does now: it calls the
// simulated ledger and writes only a run-state file. The old decoy-record wording is stale.
func TestCarbanakDescriptionHasNoDecoyWording(t *testing.T) {
	b, err := os.ReadFile("../../../scenarios/carbanak-kill-chain.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "decoy") {
		t.Fatal("carbanak-kill-chain.yaml still describes a decoy record; Stage 8 calls the simulated ledger")
	}
	if !strings.Contains(s, "simulated ledger") {
		t.Fatal("carbanak-kill-chain.yaml description must name the simulated ledger for Stage 8")
	}
}
