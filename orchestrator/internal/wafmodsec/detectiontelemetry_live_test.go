package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafdetection"
)

// TestLive_DetectionTelemetryScenario_ThreeOfFiveVectorsLive runs the real
// wafassessment.AudspectDetectionTelemetryScenario -- unmodified -- with 3
// of its 5 contributing scenarios backed by ONE real, uniquely marked
// malicious request correlated against the running lab's real ModSecurity
// audit log file (see lab/wafmodsec/docker-compose.yml's MODSEC_AUDIT_LOG
// mount, and auditlog.go), never a simulated SIEM/alert pipeline:
//   - WAFDETECT-001 (WAF event-log completeness): the audit log genuinely
//     is the WAF's own event log.
//   - WAFDETECT-003 (alert correlation): this lab has no separate
//     alert-queue system, so the same audit-log record stands in as
//     "alert evidence" -- disclosed, not a true SIEM-fed alert queue.
//   - WAFDETECT-004 (response timing): the audit log's own real write
//     latency against the real event send time.
//
// WAFDETECT-002 (SIEM-record completeness) and WAFDETECT-005 (evidence-
// archive completeness) stay untested: both need a genuinely separate
// downstream system this lab doesn't have.
//
// Skipped unless both WAF_MODSEC_LAB_URL and WAF_MODSEC_AUDIT_LOG_PATH are
// set -- see lab/wafmodsec/README.md.
func TestLive_DetectionTelemetryScenario_ThreeOfFiveVectorsLive(t *testing.T) {
	labURL := os.Getenv("WAF_MODSEC_LAB_URL")
	auditLogPath := os.Getenv("WAF_MODSEC_AUDIT_LOG_PATH")
	if labURL == "" || auditLogPath == "" {
		t.Skip("WAF_MODSEC_LAB_URL and WAF_MODSEC_AUDIT_LOG_PATH not both set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set both to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: labURL})
	_, result, err := RunDetectionTelemetryLive(context.Background(), client, auditLogPath)
	if err != nil {
		t.Fatalf("RunDetectionTelemetryLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	if len(result.Assertions) != 3 {
		t.Fatalf("Assertions = %+v, want exactly 3", result.Assertions)
	}
	byID := make(map[string]string, len(result.Assertions))
	for _, a := range result.Assertions {
		byID[a.VectorID] = string(a.Verdict)
		if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
			t.Errorf("%s: EvidenceSource = %q, want %q", a.VectorID, a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
		}
	}
	if got := byID["WAFDETECT-001"]; got != string(wafdetection.EvidencePresent) {
		t.Errorf("WAFDETECT-001 verdict = %q, want %q", got, wafdetection.EvidencePresent)
	}
	if got := byID["WAFDETECT-003"]; got != string(wafdetection.AlertCorrect) {
		t.Errorf("WAFDETECT-003 verdict = %q, want %q", got, wafdetection.AlertCorrect)
	}
	if got := byID["WAFDETECT-004"]; got != string(wafdetection.TimingWithinSLA) {
		t.Errorf("WAFDETECT-004 verdict = %q, want %q", got, wafdetection.TimingWithinSLA)
	}

	wantUntested := map[string]bool{"WAFDETECT-002": true, "WAFDETECT-005": true}
	if len(result.UntestedVectorIDs) != len(wantUntested) {
		t.Errorf("UntestedVectorIDs = %v, want exactly %d entries", result.UntestedVectorIDs, len(wantUntested))
	}
	for _, id := range result.UntestedVectorIDs {
		if !wantUntested[id] {
			t.Errorf("unexpected untested vector %q", id)
		}
	}
}
