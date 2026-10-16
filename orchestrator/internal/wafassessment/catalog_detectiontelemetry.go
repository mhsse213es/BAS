package wafassessment

import (
	"time"

	"github.com/audspect/bas/internal/wafval"
)

// AudspectDetectionTelemetryScenario returns Audspect's real, current
// seed "Detection, Telemetry and Incident Evidence" scenario: all 5
// real wafdetection scenarios (WAFDETECT-001/002/005 completeness,
// WAFDETECT-003 alert correlation, WAFDETECT-004 response timing).
// Unlike every other scenario in this package, this one validates the
// evidence pipeline's own trustworthiness rather than whether an
// attack was blocked -- it references no wafcatalog vector and has no
// catalog-derived severity.
func AudspectDetectionTelemetryScenario() (EnterpriseScenario, error) {
	return NewEnterpriseScenario(
		"WAFSCENARIO-DETECTION-TELEMETRY",
		"Detection, Telemetry and Incident Evidence",
		"evaluate whether the WAF's own evidence pipeline is trustworthy -- WAF-event and SIEM-record completeness, evidence survival to long-term archival, correct alert correlation, and alert response timing against a declared SLA -- independent of whether any given attack was blocked",
		[]string{"WAFDETECT-001", "WAFDETECT-002", "WAFDETECT-003", "WAFDETECT-004", "WAFDETECT-005"},
		"target's WAF event log, SIEM ingestion, alert queue, and evidence archive are all independently inspectable for the same correlated test execution",
		"a wafval.CollectionResult or timestamp pair per contributing scenario, matched to its real evaluation shape, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 08",
	)
}

func collectionResultPresent() wafval.CollectionResult {
	return wafval.CollectionResult{
		Coverage:     wafval.CoverageFound,
		Observations: []wafval.Observation{{EvidenceKind: wafval.EvidenceObserved}},
	}
}

// AudspectDetectionTelemetryFixtures returns Audspect's real, current
// seed fixture set for the detection-telemetry scenario --
// deliberately NOT a uniform pass. WAFDETECT-002 (SIEM-record
// completeness) is seeded with an incomplete search, a deliberate
// simulated evidence-pipeline gap, so the scenario genuinely resolves
// to ScenarioFail. WAFDETECT-005 (evidence-archive completeness) is
// deliberately absent (untested).
func AudspectDetectionTelemetryFixtures() map[string]DetectionFixture {
	eventAt := time.Now().UTC()
	return map[string]DetectionFixture{
		"WAFDETECT-001": {CompletenessEvidence: collectionResultPresent()},
		"WAFDETECT-002": {CompletenessEvidence: wafval.CollectionResult{Coverage: wafval.CoverageSearchIncomplete}},
		"WAFDETECT-003": {UnderlyingVerdict: wafval.VerdictBlocked, AlertEvidence: collectionResultPresent()},
		"WAFDETECT-004": {EventObservedAt: eventAt, AlertObservedAt: eventAt.Add(2 * time.Minute)},
	}
}
