package deployconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testdata/golden.json is copied byte-for-byte from
// orchestrator/internal/deployconfig/testdata/golden.json, which the
// orchestrator regenerates exactly in its own test. If the wire format drifts
// on either side, one of the two tests fails.
func TestVerifiesTheOrchestratorGoldenEnvelope(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Envelope    string `json:"envelope"`
		Fingerprint string `json:"fingerprint"`
		Now         string `json:"now"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, g.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify([]byte(g.Envelope), g.Fingerprint, now)
	if err != nil {
		t.Fatalf("the agent rejected the orchestrator's golden envelope: %v", err)
	}
	if got.ServerURL != "https://bas.example.com:9443" || got.EnrollPort != "9444" || got.CARootPEM != "" {
		t.Fatalf("unexpected config: %+v", got)
	}
	// And the wrong fingerprint must still fail on the real artifact.
	if _, err := Verify([]byte(g.Envelope), "00"+g.Fingerprint[2:], now); err == nil {
		t.Fatal("a different fingerprint must be rejected")
	}
}
