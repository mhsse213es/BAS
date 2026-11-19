package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_RoutingCacheIntegrityScenario_TwoOfThreeVectorsLive runs the
// real wafassessment.AudspectRoutingCacheIntegrityScenario -- unmodified
// -- with 2 of its 3 contributing vectors backed by live evidence.
// Confirmed empirically against the live container: CACHE-003 (parameter
// cloaking with a reflected <script> payload) is genuinely Blocked --
// CRS's generic XSS rule fires on the payload content, independent of
// any cache-key awareness. CACHE-002 (a static-looking .css suffix on a
// dynamic path) is genuinely Allowed -- CRS has no cache-layer awareness
// at all, so it never blocks this, an honest negative result, not a bug
// in the adapter -- which resolves to VerdictInconclusive, not Missed,
// since wafmodsec never asserts DetectionMatched/NotMatched.
//
// Skipped unless WAF_MODSEC_LAB_URL is set -- see lab/wafmodsec/README.md.
func TestLive_RoutingCacheIntegrityScenario_TwoOfThreeVectorsLive(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	_, result, err := RunRoutingCacheIntegrityLive(context.Background(), client)
	if err != nil {
		t.Fatalf("RunRoutingCacheIntegrityLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	wantVerdict := map[string]wafval.Verdict{
		"CACHE-002": wafval.VerdictInconclusive,
		"CACHE-003": wafval.VerdictBlocked,
	}
	if len(result.Assertions) != len(wantVerdict) {
		t.Fatalf("Assertions = %+v, want exactly %d", result.Assertions, len(wantVerdict))
	}
	for _, a := range result.Assertions {
		want, ok := wantVerdict[a.VectorID]
		if !ok {
			t.Errorf("unexpected vector %q in Assertions", a.VectorID)
			continue
		}
		if a.Verdict != want {
			t.Errorf("vector %q Verdict = %q, want %q", a.VectorID, a.Verdict, want)
		}
		if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
			t.Errorf("vector %q EvidenceSource = %q, want %q", a.VectorID, a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
		}
	}

	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "CACHE-001" {
		t.Errorf("UntestedVectorIDs = %v, want exactly [CACHE-001]", result.UntestedVectorIDs)
	}
}
