package api

import (
	"testing"
	"time"
)

func TestAgentCursor_EncodeDecodeRoundTrip(t *testing.T) {
	original := agentCursor{
		Snapshot:   time.Date(2026, 8, 31, 17, 0, 0, 123000000, time.UTC),
		LastUpdate: time.Date(2026, 8, 31, 16, 59, 58, 1000000, time.UTC),
		AgentID:    "loadgen-000042",
	}
	encoded := encodeAgentCursor(original)
	if encoded == "" {
		t.Fatal("encodeAgentCursor returned empty string")
	}
	decoded, err := decodeAgentCursor(encoded)
	if err != nil {
		t.Fatalf("decodeAgentCursor: %v", err)
	}
	if !decoded.Snapshot.Equal(original.Snapshot) {
		t.Errorf("Snapshot = %v, want %v", decoded.Snapshot, original.Snapshot)
	}
	if !decoded.LastUpdate.Equal(original.LastUpdate) {
		t.Errorf("LastUpdate = %v, want %v", decoded.LastUpdate, original.LastUpdate)
	}
	if decoded.AgentID != original.AgentID {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, original.AgentID)
	}
}

func TestDecodeAgentCursor_RejectsGarbage(t *testing.T) {
	if _, err := decodeAgentCursor("not-valid-base64!!!"); err == nil {
		t.Fatal("expected an error decoding garbage input, got nil")
	}
	// Valid base64, but not valid JSON underneath.
	if _, err := decodeAgentCursor("bm90LWpzb24="); err == nil {
		t.Fatal("expected an error decoding valid-base64-but-not-JSON input, got nil")
	}
}
