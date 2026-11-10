package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_APIProtectionScenario_TwoOfEightVectorsLive runs the real
// wafassessment.AudspectAPIProtectionScenario -- unmodified -- with 2 of
// its 8 contributing vectors backed by live evidence, one from each of
// its two source catalogs (wafcatalog's API-003, wafapiflow's
// APIFLOW-005). Confirmed empirically against the live container: both
// are genuinely Allowed -- CRS has no business-logic awareness of
// excessive-field-exposure or bulk-export-limit abuse, a content-oblivious
// generic WAF's honest, expected limitation, not a bug in the adapter.
// Both resolve to VerdictInconclusive, never Missed, since wafmodsec never
// asserts DetectionMatched/NotMatched.
//
// Skipped unless WAF_MODSEC_LAB_URL is set -- see lab/wafmodsec/README.md.
func TestLive_APIProtectionScenario_TwoOfEightVectorsLive(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	_, result, err := RunAPIProtectionLive(context.Background(), client)
	if err != nil {
		t.Fatalf("RunAPIProtectionLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	wantVectors := map[string]bool{"API-003": true, "APIFLOW-005": true}
	if len(result.Assertions) != len(wantVectors) {
		t.Fatalf("Assertions = %+v, want exactly %d", result.Assertions, len(wantVectors))
	}
	for _, a := range result.Assertions {
		if !wantVectors[a.VectorID] {
			t.Errorf("unexpected vector %q in Assertions", a.VectorID)
		}
		if a.Verdict != wafval.VerdictInconclusive {
			t.Errorf("vector %q Verdict = %q, want %q", a.VectorID, a.Verdict, wafval.VerdictInconclusive)
		}
		if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
			t.Errorf("vector %q EvidenceSource = %q, want %q", a.VectorID, a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
		}
	}

	wantUntested := map[string]bool{"API-001": true, "API-002": true, "APIFLOW-001": true, "APIFLOW-002": true, "APIFLOW-003": true, "APIFLOW-004": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %d entries", result.UntestedVectorIDs, len(wantUntested))
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}
}
