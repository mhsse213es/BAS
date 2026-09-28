package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCommandEnvelope_UnmarshalsOrchestratorWireShape locks in that the
// agent's verification-side type accepts exactly what
// orchestrator/internal/models.CommandEnvelope's json tags produce --
// these are deliberately two separate Go types (different modules) that
// must nonetheless agree on wire shape; this test is that agreement's
// pin, independent of any live orchestrator.
func TestCommandEnvelope_UnmarshalsOrchestratorWireShape(t *testing.T) {
	wire := `{
		"version": 1,
		"commandId": "cmd-1",
		"commandType": "command_scenario",
		"agentId": "abc123deadbeef01",
		"runId": "run-1",
		"issuedAt": "2026-09-28T00:00:00Z",
		"expiresAt": "2026-09-28T00:01:00Z",
		"nonce": "nonce-1",
		"payload": {"runId":"run-1"},
		"signature": "AQID"
	}`
	var env CommandEnvelope
	if err := json.Unmarshal([]byte(wire), &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.CommandID != "cmd-1" || env.CommandType != "command_scenario" || env.AgentID != "abc123deadbeef01" {
		t.Errorf("unexpected envelope: %+v", env)
	}
	if env.IssuedAt.IsZero() || env.ExpiresAt.IsZero() {
		t.Error("IssuedAt/ExpiresAt did not parse")
	}
	if len(env.Signature) != 3 {
		t.Errorf("Signature = %v (len %d), want 3 bytes decoded from base64", env.Signature, len(env.Signature))
	}
}

func TestCommandEnvelope_CanonicalJSONMatchesOrchestratorShape(t *testing.T) {
	env := CommandEnvelope{
		Version:     1,
		CommandID:   "cmd-1",
		CommandType: "command_scenario",
		AgentID:     "abc123deadbeef01",
		IssuedAt:    time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 9, 28, 0, 1, 0, 0, time.UTC),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"runId":"run-1"}`),
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var probe map[string]interface{}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("CanonicalJSON output invalid JSON: %v", err)
	}
	if _, present := probe["signature"]; present {
		t.Error("CanonicalJSON must exclude signature")
	}
}
