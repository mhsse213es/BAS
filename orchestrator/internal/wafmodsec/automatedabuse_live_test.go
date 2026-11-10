package wafmodsec

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_AutomatedAbuseScenario_OneOfSixVectorsLive runs the real
// wafassessment.AudspectAutomatedAbuseScenario -- unmodified -- with 1 of
// its 6 contributing vectors backed by real, aggregate live evidence:
// RATE-001, driven as a genuine bounded burst against the lab's own real
// nginx `limit_req` rate limiter (see lab/wafmodsec/docker-compose.yml and
// nginx/00-limit-req-zone.conf), not a single request. Confirmed
// empirically against the live container (curl burst test): a burst of 10
// rapid requests to /api/quote returns some 200s then 503s once the
// declared limit is exceeded -- a real, deterministic enforcement finding,
// resolving VerdictBlocked.
//
// Skipped unless WAF_MODSEC_LAB_URL is set -- see lab/wafmodsec/README.md.
func TestLive_AutomatedAbuseScenario_OneOfSixVectorsLive(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	_, result, err := RunAutomatedAbuseLive(context.Background(), client)
	if err != nil {
		t.Fatalf("RunAutomatedAbuseLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	if len(result.Assertions) != 1 {
		t.Fatalf("Assertions = %+v, want exactly 1", result.Assertions)
	}
	a := result.Assertions[0]
	if a.VectorID != "RATE-001" {
		t.Errorf("VectorID = %q, want RATE-001", a.VectorID)
	}
	if a.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", a.Verdict, wafval.VerdictBlocked)
	}
	if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
		t.Errorf("EvidenceSource = %q, want %q", a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
	}

	wantUntested := map[string]bool{"RATE-002": true, "BOTABUSE-001": true, "BOTABUSE-002": true, "BOTABUSE-003": true, "BOTABUSE-004": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %d entries", result.UntestedVectorIDs, len(wantUntested))
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}

	// Test-isolation only, not a production concern: this burst leaves the
	// lab's real nginx leaky-bucket zone (lab/wafmodsec/nginx/00-limit-req-zone.conf,
	// rate=2r/s) well over capacity. Any other live test that happens to run
	// moments later and shares the same client IP + /api/quote (e.g.
	// legitimate-traffic's RATE-001 benign leg) would otherwise see a
	// leftover 503 from THIS burst, not a real finding of its own -- caught
	// as exactly that failure before this wait was added. Give the bucket
	// time to fully drain before returning.
	time.Sleep(3 * time.Second)
}
