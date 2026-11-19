package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_HTTPProtocolIntegrityScenario_OneOfThreeVectorsLive runs the
// real wafassessment.AudspectHTTPProtocolIntegrityScenario -- unmodified
// -- with its one live-capable vector (HTTPPARSE-002) backed by evidence
// from the running ModSecurity lab. Confirmed empirically against the
// live container: TRACE /admin/settings returns 405 (nginx's own method
// whitelist rejecting TRACE, not a ModSecurity rule -- both equally
// prevent the origin from ever seeing the request).
//
// Skipped unless WAF_MODSEC_LAB_URL is set -- see lab/wafmodsec/README.md.
func TestLive_HTTPProtocolIntegrityScenario_OneOfThreeVectorsLive(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	_, result, err := RunHTTPProtocolIntegrityLive(context.Background(), client)
	if err != nil {
		t.Fatalf("RunHTTPProtocolIntegrityLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	if len(result.Assertions) != 1 {
		t.Fatalf("Assertions = %+v, want exactly 1 (HTTPPARSE-002)", result.Assertions)
	}
	a := result.Assertions[0]
	if a.VectorID != "HTTPPARSE-002" {
		t.Errorf("VectorID = %q, want HTTPPARSE-002", a.VectorID)
	}
	if a.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", a.Verdict, wafval.VerdictBlocked)
	}
	if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
		t.Errorf("EvidenceSource = %q, want %q", a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
	}

	wantUntested := map[string]bool{"HTTPPARSE-001": true, "HTTPPARSE-003": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %v", result.UntestedVectorIDs, wantUntested)
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}
}
