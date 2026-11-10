package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// DetectionTelemetryLiveVectorIDs is 3 of
// AudspectDetectionTelemetryScenario's 5 contributing scenarios, each
// resolved from ONE real correlated probe against the lab's real
// ModSecurity audit log (see auditlog.go) rather than a simulated SIEM:
//   - WAFDETECT-001 (WAF event-log completeness): the audit log
//     genuinely IS the WAF's own event log -- no scope stretch.
//   - WAFDETECT-003 (alert correlation): this lab has no separate
//     alert-queue system, so the same audit-log record stands in as
//     "alert evidence" -- disclosed, not a true SIEM-fed alert queue.
//   - WAFDETECT-004 (response timing): the audit log's own real write
//     latency against the real event send time.
//
// WAFDETECT-002 (SIEM-record completeness) and WAFDETECT-005 (evidence-
// archive completeness) stay unwired: both need a genuinely separate
// downstream system (a SIEM ingest pipeline, long-term archival storage)
// that reading the WAF's own log file, however real, cannot stand in for.
var DetectionTelemetryLiveVectorIDs = []string{"WAFDETECT-001", "WAFDETECT-003", "WAFDETECT-004"}

// auditLogPollInterval/auditLogPollTimeout bound how long
// BuildDetectionTelemetryLiveFixtures waits for ModSecurity to flush its
// audit log entry to disk after the blocking response is already
// received -- in practice the write is synchronous with the request
// (confirmed empirically against the real container), so this is a
// safety margin, not the expected path.
const (
	auditLogPollInterval = 100 * time.Millisecond
	auditLogPollTimeout  = 3 * time.Second
)

// detectionTelemetryProbeTemplate reuses SQLI-001's real, already-proven
// malicious shape (a UNION-based SQL injection in /search's q parameter),
// with a unique marker appended so the resulting audit log entry can be
// correlated back to this exact request -- not a new attack shape, a
// correlator riding along on one already confirmed to be blocked.
func detectionTelemetryProbeTemplate(marker string) wafcatalog.RequestTemplate {
	return wafcatalog.RequestTemplate{
		Method:          "GET",
		Path:            "/search",
		PayloadLocation: "query:q",
		Payload:         "' UNION SELECT NULL-- " + marker,
		Description:     "detection-telemetry correlation probe",
	}
}

// BuildDetectionTelemetryLiveFixtures drives one real, uniquely marked
// malicious request through client and correlates it against the real
// ModSecurity audit log file at auditLogPath (lab/wafmodsec's
// MODSEC_AUDIT_LOG mount -- see docker-compose.yml's own doc comment).
func BuildDetectionTelemetryLiveFixtures(ctx context.Context, client *modsecwaf.Client, auditLogPath string) (map[string]wafassessment.DetectionFixture, error) {
	marker := fmt.Sprintf("dettel-%d", time.Now().UnixNano())
	// Floored to the audit log's own second-only precision -- see
	// auditlog.go's AuditLogEntry doc comment for why comparing a
	// sub-second time.Now() against it directly would manufacture a
	// false "alert precedes its own event" ordering on roughly half of
	// all real runs.
	eventObservedAt := time.Now().UTC().Truncate(time.Second)

	resp, err := client.Send(ctx, detectionTelemetryProbeTemplate(marker))
	if err != nil {
		return nil, fmt.Errorf("driving detection-telemetry probe live: %w", err)
	}

	key := wafval.CorrelationKey{TestExecutionID: marker, RequestID: marker}
	results := BuildCollectionResults(resp, key, time.Now())
	underlying := wafval.EvaluateClaim(wafval.Expectation{Claim: wafval.ClaimPrevention, PolicyVerified: false}, results, key).Verdict

	var entry AuditLogEntry
	found := false
	deadline := time.Now().Add(auditLogPollTimeout)
	for {
		entry, found, err = FindAuditLogEntry(auditLogPath, marker)
		if err != nil {
			return nil, fmt.Errorf("reading audit log %q: %w", auditLogPath, err)
		}
		if found || time.Now().After(deadline) {
			break
		}
		time.Sleep(auditLogPollInterval)
	}

	evidence := wafval.CollectionResult{Coverage: wafval.CoverageSearchIncomplete}
	var alertObservedAt time.Time
	if found {
		evidence = wafval.CollectionResult{
			Coverage: wafval.CoverageFound,
			Observations: []wafval.Observation{{
				EvidenceKind: wafval.EvidenceObserved,
				EventID:      entry.UniqueID,
				ObservedAt:   entry.TimeStamp,
			}},
		}
		alertObservedAt = entry.TimeStamp
	}

	return map[string]wafassessment.DetectionFixture{
		"WAFDETECT-001": {CompletenessEvidence: evidence, EvidenceSource: wafassessment.EvidenceSourceLiveExecution},
		"WAFDETECT-003": {UnderlyingVerdict: underlying, AlertEvidence: evidence, EvidenceSource: wafassessment.EvidenceSourceLiveExecution},
		"WAFDETECT-004": {EventObservedAt: eventObservedAt, AlertObservedAt: alertObservedAt, EvidenceSource: wafassessment.EvidenceSourceLiveExecution},
	}, nil
}

// RunDetectionTelemetryLive loads the real detection-telemetry scenario,
// builds its live fixtures against the real audit log, and evaluates
// them through the real, unmodified
// wafassessment.EvaluateDetectionTelemetryScenario.
func RunDetectionTelemetryLive(ctx context.Context, client *modsecwaf.Client, auditLogPath string) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectDetectionTelemetryScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading detection-telemetry scenario: %w", err)
	}
	fixtures, err := BuildDetectionTelemetryLiveFixtures(ctx, client, auditLogPath)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	result, err := wafassessment.EvaluateDetectionTelemetryScenario(scenario, fixtures)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
