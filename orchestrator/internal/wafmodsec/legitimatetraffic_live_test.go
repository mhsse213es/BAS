package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_LegitimateTrafficScenario_FourOfSixVectorsLive runs the real
// wafassessment.AudspectLegitimateTrafficScenario -- unmodified, through
// its own real wafassessment.EvaluateLegitimateTrafficScenario -- with 4
// of its 6 contributing vectors' BENIGN counterpart requests backed by
// live evidence. Confirmed empirically against the live container: all 4
// are genuinely Allowed -- the WAF correctly lets ordinary traffic
// through on these routes, resolving to VerdictAllowed under
// wafval.ClaimFalsePositive.
//
// Skipped unless WAF_MODSEC_LAB_URL is set -- see lab/wafmodsec/README.md.
func TestLive_LegitimateTrafficScenario_FourOfSixVectorsLive(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	_, result, err := RunLegitimateTrafficLive(context.Background(), client)
	if err != nil {
		t.Fatalf("RunLegitimateTrafficLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	wantVectors := map[string]bool{"SQLI-001": true, "XSS-001": true, "PATHTRAV-001": true, "RATE-001": true}
	if len(result.Assertions) != len(wantVectors) {
		t.Fatalf("Assertions = %+v, want exactly %d", result.Assertions, len(wantVectors))
	}
	for _, a := range result.Assertions {
		if !wantVectors[a.VectorID] {
			t.Errorf("unexpected vector %q in Assertions", a.VectorID)
		}
		if a.Verdict != wafval.VerdictAllowed {
			t.Errorf("vector %q Verdict = %q, want %q", a.VectorID, a.Verdict, wafval.VerdictAllowed)
		}
		if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
			t.Errorf("vector %q EvidenceSource = %q, want %q", a.VectorID, a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
		}
	}

	wantUntested := map[string]bool{"API-001": true, "FILEUP-001": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %v", result.UntestedVectorIDs, wantUntested)
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}
}
