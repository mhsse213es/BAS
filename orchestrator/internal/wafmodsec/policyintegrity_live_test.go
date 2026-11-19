package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_PolicyIntegrityScenario_OneOfSixVectorsLive runs the real
// wafassessment.AudspectPolicyIntegrityScenario -- unmodified -- with 1 of
// its 6 contributing policy-gap scenarios backed by a genuine two-leg
// baseline-vs-weakened comparison against TWO real, separately configured
// WAF containers (see lab/wafmodsec/docker-compose.yml's "waf-weakened"
// service): GAP-001 (detection-only mode). Curl-confirmed against both real
// containers: the baseline (:8888, MODSEC_RULE_ENGINE=On) blocks POLICY-001's
// payload (403); the weakened instance (:8889, MODSEC_RULE_ENGINE=
// DetectionOnly) lets the identical payload reach origin (200). The overall
// verdict resolves Inconclusive, not Missed/DetectedButAllowed -- the same
// disclosed limitation as every other live-wired vector in this package:
// wafmodsec never parses the audit log, so an allowed-through weakened leg
// can never assert a resolved Detection axis.
//
// Skipped unless BOTH WAF_MODSEC_LAB_URL and WAF_MODSEC_WEAKENED_LAB_URL are
// set -- see lab/wafmodsec/README.md.
func TestLive_PolicyIntegrityScenario_OneOfSixVectorsLive(t *testing.T) {
	baselineURL := os.Getenv("WAF_MODSEC_LAB_URL")
	weakenedURL := os.Getenv("WAF_MODSEC_WEAKENED_LAB_URL")
	if baselineURL == "" || weakenedURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL and WAF_MODSEC_WEAKENED_LAB_URL not both set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set both URLs to run it")
	}

	baselineClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baselineURL})
	weakenedClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: weakenedURL})
	_, result, err := RunPolicyIntegrityLive(context.Background(), baselineClient, weakenedClient)
	if err != nil {
		t.Fatalf("RunPolicyIntegrityLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	if len(result.Assertions) != 1 {
		t.Fatalf("Assertions = %+v, want exactly 1", result.Assertions)
	}
	a := result.Assertions[0]
	if a.VectorID != "GAP-001" {
		t.Errorf("VectorID = %q, want GAP-001", a.VectorID)
	}
	if a.Verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", a.Verdict, wafval.VerdictInconclusive)
	}
	if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
		t.Errorf("EvidenceSource = %q, want %q", a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
	}

	wantUntested := map[string]bool{"GAP-002": true, "GAP-003": true, "GAP-004": true, "GAP-005": true, "GAP-006": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %d entries", result.UntestedVectorIDs, len(wantUntested))
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}
}
