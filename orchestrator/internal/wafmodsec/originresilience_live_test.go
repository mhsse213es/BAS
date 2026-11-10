package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/waforigin"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_OriginResilienceScenario_ThreeOfFiveVectorsLive runs the real
// wafassessment.AudspectOriginResilienceScenario -- unmodified -- with 3
// of its 5 contributing scenarios backed by real probes against the
// lab's real containers:
//   - WAFORIGIN-001: SQLI-001 via /search (baseline, blocked) vs the
//     real, undocumented /legacy-search route (bypass, modsecurity off).
//   - WAFORIGIN-002: XSS-001 via the WAF edge (baseline, blocked) vs
//     directly against origin's own separately-published host port
//     (bypass, no WAF at all).
//   - WAFORIGIN-005: PATHTRAV-001 driven independently against "waf"
//     and "waf-weakened" (the same two containers policy-integrity
//     already uses) as two cross-node-consistency "nodes".
//
// WAFORIGIN-001/002's bypass legs both reach origin without being
// blocked, which this package's bridge (never parses the audit log) can
// only resolve to Inconclusive, not Missed/DetectedButAllowed -- the
// same disclosed limitation as every other live-wired vector in this
// session. WAFORIGIN-005 genuinely resolves ConsistencyDrift (not
// Inconclusive): both nodes' results pass waforigin's own
// Confidence>=Medium trustworthiness filter, and node-a (blocked) and
// node-b (reaches origin, Inconclusive) are real, different verdicts --
// a true cross-node disagreement, which registers as the scenario's
// overall ScenarioFail via the non-offsetting rule.
//
// Skipped unless WAF_MODSEC_LAB_URL, WAF_MODSEC_ORIGIN_DIRECT_URL, and
// WAF_MODSEC_WEAKENED_LAB_URL are all set -- see lab/wafmodsec/README.md.
func TestLive_OriginResilienceScenario_ThreeOfFiveVectorsLive(t *testing.T) {
	labURL := os.Getenv("WAF_MODSEC_LAB_URL")
	directURL := os.Getenv("WAF_MODSEC_ORIGIN_DIRECT_URL")
	weakenedURL := os.Getenv("WAF_MODSEC_WEAKENED_LAB_URL")
	if labURL == "" || directURL == "" || weakenedURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL, WAF_MODSEC_ORIGIN_DIRECT_URL, and WAF_MODSEC_WEAKENED_LAB_URL not all set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set all three to run it")
	}

	baselineClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: labURL})
	directClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: directURL})
	weakenedClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: weakenedURL})
	_, result, err := RunOriginResilienceLive(context.Background(), baselineClient, directClient, weakenedClient)
	if err != nil {
		t.Fatalf("RunOriginResilienceLive: %v", err)
	}

	// A real cross-node disagreement (WAFORIGIN-005) forces ScenarioFail
	// outright via the non-offsetting rule -- stronger than Incomplete,
	// not weaker: a real finding, not a gap in coverage.
	if result.Outcome != wafassessment.ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioFail)
	}
	if len(result.Assertions) != 3 {
		t.Fatalf("Assertions = %+v, want exactly 3", result.Assertions)
	}
	for _, a := range result.Assertions {
		if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
			t.Errorf("%s: EvidenceSource = %q, want %q", a.VectorID, a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
		}
		switch a.VectorID {
		case "WAFORIGIN-001", "WAFORIGIN-002":
			if a.Verdict != wafval.VerdictInconclusive {
				t.Errorf("%s verdict = %q, want %q", a.VectorID, a.Verdict, wafval.VerdictInconclusive)
			}
		case "WAFORIGIN-005":
			if string(a.Verdict) != string(waforigin.ConsistencyDrift) {
				t.Errorf("WAFORIGIN-005 verdict = %q, want %q", a.Verdict, waforigin.ConsistencyDrift)
			}
		default:
			t.Errorf("unexpected vector ID %q", a.VectorID)
		}
	}

	wantUntested := map[string]bool{"WAFORIGIN-003": true, "WAFORIGIN-004": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %d entries", result.UntestedVectorIDs, len(wantUntested))
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}
}
