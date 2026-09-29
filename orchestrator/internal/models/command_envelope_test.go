package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCommandEnvelope_CanonicalJSONExcludesSignature locks in the canonical-
// serialization property the signing scheme depends on: CanonicalJSON must
// never include the Signature field itself (it can't sign its own output),
// and must produce byte-identical output for byte-identical field values
// (Go's encoding/json field order is deterministic for a fixed struct, so
// this needs no separate canonicalization step).
func TestCommandEnvelope_CanonicalJSONExcludesSignature(t *testing.T) {
	env := CommandEnvelope{
		Version:     1,
		CommandID:   "cmd-1",
		CommandType: "command_scenario",
		AgentID:     "abc123deadbeef01",
		RunID:       "run-1",
		IssuedAt:    time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 9, 28, 0, 1, 0, 0, time.UTC),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"foo":"bar"}`),
		Signature:   []byte("must-not-appear-in-canonical-form"),
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(b) == "" {
		t.Fatal("CanonicalJSON returned empty output")
	}
	var roundtrip map[string]interface{}
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatalf("CanonicalJSON output is not valid JSON: %v", err)
	}
	if _, present := roundtrip["signature"]; present {
		t.Error("CanonicalJSON output must not include the signature field")
	}
	if roundtrip["commandId"] != "cmd-1" {
		t.Errorf("commandId = %v, want cmd-1", roundtrip["commandId"])
	}

	b2, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON (second call): %v", err)
	}
	if string(b) != string(b2) {
		t.Error("CanonicalJSON is not deterministic across repeated calls on the same value")
	}
}

// TestCommandEnvelope_OptionalFieldsOmittedWhenEmpty confirms ScenarioID/
// StepID/RunID/Mode/Policy are genuinely optional in the wire format --
// command_cancel/pause/resume don't necessarily have a scenario context.
func TestCommandEnvelope_OptionalFieldsOmittedWhenEmpty(t *testing.T) {
	env := CommandEnvelope{
		Version:     1,
		CommandID:   "cmd-2",
		CommandType: "command_cancel",
		AgentID:     "abc123deadbeef01",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(60 * time.Second),
		Nonce:       "nonce-2",
		Payload:     json.RawMessage(`{}`),
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var roundtrip map[string]interface{}
	json.Unmarshal(b, &roundtrip)
	for _, field := range []string{"runId", "scenarioId", "stepId", "mode", "policy"} {
		if _, present := roundtrip[field]; present {
			t.Errorf("expected %q to be omitted when empty, got: %v", field, roundtrip[field])
		}
	}
}

func TestCommandEnvelope_CanonicalJSONIncludesExecutionClassAggregate(t *testing.T) {
	env := CommandEnvelope{
		Version: CommandEnvelopeVersion, CommandID: "c1", CommandType: "command_scenario",
		AgentID: "a1", IssuedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC), Nonce: "n1",
		Payload:           json.RawMessage(`{}`),
		ExecutionClass:    "destructive",
		DestructiveAction: "vss_delete",
		BlastRadius:       "Deletes VSS shadow copies.",
	}
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !strings.Contains(string(canon), `"executionClass":"destructive"`) {
		t.Errorf("canonical JSON missing executionClass: %s", canon)
	}
	if !strings.Contains(string(canon), `"destructiveAction":"vss_delete"`) {
		t.Errorf("canonical JSON missing destructiveAction: %s", canon)
	}
}
