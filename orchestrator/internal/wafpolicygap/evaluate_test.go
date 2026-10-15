package wafpolicygap

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func mustVectorByID(t *testing.T, id string) wafcatalog.AttackVector {
	t.Helper()
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %q not found in AudspectWAFAttackCatalog", id)
	return wafcatalog.AttackVector{}
}

func mustGAP001(t *testing.T) PolicyGapScenario {
	t.Helper()
	s, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001",
		"OWASP CRS default anomaly-scoring mode, rule set enabled",
		"the matching rule for this payload was switched to detection-only (log, no block)",
		"manually authored")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario: %v", err)
	}
	return s
}

func mustGAP005(t *testing.T) PolicyGapScenario {
	t.Helper()
	s, err := NewPolicyGapScenario("GAP-005", WeaknessUnprotectedRoute, "SSRF-001",
		"declared policy: every API route sits behind the WAF",
		"this route was never added to the WAF's protected hostname/path set",
		"manually authored")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario: %v", err)
	}
	return s
}

// Review Focus: calling EvaluatePairedScenario on a single-leg weakness
// must return an error, not silently evaluate the wrong shape.
func TestEvaluatePairedScenario_SingleLegScenario_ReturnsError(t *testing.T) {
	scenario := mustGAP005(t) // WeaknessUnprotectedRoute, not paired
	vector := mustVectorByID(t, "SSRF-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, _, err := EvaluatePairedScenario(scenario, vector, "pb", nil, key, nil, key, true)
	if err == nil {
		t.Fatal("want error for a single-leg scenario passed to EvaluatePairedScenario, got nil")
	}
}

// Review Focus: calling EvaluateCoverageGapScenario on a paired weakness
// must return an error, not silently evaluate the wrong shape.
func TestEvaluateCoverageGapScenario_PairedScenario_ReturnsError(t *testing.T) {
	scenario := mustGAP001(t) // WeaknessDetectionOnlyMode, paired
	vector := mustVectorByID(t, "POLICY-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, err := EvaluateCoverageGapScenario(scenario, vector, "pb", nil, key)
	if err == nil {
		t.Fatal("want error for a paired scenario passed to EvaluateCoverageGapScenario, got nil")
	}
}

// Review Focus: a vector whose ID doesn't match scenario.AttackVectorID is
// a caller bug and must be rejected.
func TestEvaluatePairedScenario_VectorIDMismatch_ReturnsError(t *testing.T) {
	scenario := mustGAP001(t) // references POLICY-001
	wrongVector := mustVectorByID(t, "SQLI-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, _, err := EvaluatePairedScenario(scenario, wrongVector, "pb", nil, key, nil, key, true)
	if err == nil {
		t.Fatal("want error when vector.ID does not match scenario.AttackVectorID, got nil")
	}
}

func TestEvaluateCoverageGapScenario_VectorIDMismatch_ReturnsError(t *testing.T) {
	scenario := mustGAP005(t) // references SSRF-001
	wrongVector := mustVectorByID(t, "SQLI-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, err := EvaluateCoverageGapScenario(scenario, wrongVector, "pb", nil, key)
	if err == nil {
		t.Fatal("want error when vector.ID does not match scenario.AttackVectorID, got nil")
	}
}

// TestEvaluatePairedScenario_GAP001_ConfirmedDifferentiation_YieldsMissed
// proves spec §10 acceptance gate item 6: a detection-only misconfiguration,
// confirmed in force, reads as a genuine policy-attributed Missed.
func TestEvaluatePairedScenario_GAP001_ConfirmedDifferentiation_YieldsMissed(t *testing.T) {
	scenario := mustGAP001(t)
	vector := mustVectorByID(t, "POLICY-001")
	now := time.Now()
	window := wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	baselineKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	weakenedKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	baselineEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "b1", RequestID: "r1", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	weakenedEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "w1", RequestID: "r2", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}

	verdict, reason, err := EvaluatePairedScenario(scenario, vector, "owasp-crs-default", baselineEvidence, baselineKey, weakenedEvidence, weakenedKey, true)
	if err != nil {
		t.Fatalf("EvaluatePairedScenario: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
	if reason == "" {
		t.Error("want a non-empty policy-attribution reason")
	}
}

// TestEvaluatePairedScenario_GAP001_UnconfirmedDifferentiation_YieldsInconclusive
// proves spec §10 acceptance gate item 7, and is the Review Focus item for
// this task: an unconfirmed policy change must never read as a real gap,
// even though the two legs visibly differ.
func TestEvaluatePairedScenario_GAP001_UnconfirmedDifferentiation_YieldsInconclusive(t *testing.T) {
	scenario := mustGAP001(t)
	vector := mustVectorByID(t, "POLICY-001")
	now := time.Now()
	window := wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	baselineKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	weakenedKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	baselineEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "b1", RequestID: "r1", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	weakenedEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "w1", RequestID: "r2", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}

	verdict, _, err := EvaluatePairedScenario(scenario, vector, "owasp-crs-default", baselineEvidence, baselineKey, weakenedEvidence, weakenedKey, false)
	if err != nil {
		t.Fatalf("EvaluatePairedScenario: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- an unconfirmed policy differentiation must never read as a real gap", verdict, wafval.VerdictInconclusive)
	}
}

// TestEvaluateCoverageGapScenario_GAP005_NoWAFCoverage_YieldsInconclusive
// proves spec §10 acceptance gate item 8: a route with no WAF evidence at
// all is an Inconclusive finding, never a false "missed".
func TestEvaluateCoverageGapScenario_GAP005_NoWAFCoverage_YieldsInconclusive(t *testing.T) {
	scenario := mustGAP005(t)
	vector := mustVectorByID(t, "SSRF-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	evidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismOriginApp, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismOriginApp, EventID: "o1", RequestID: "r1", ObservedAt: now, Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginReceived, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result, err := EvaluateCoverageGapScenario(scenario, vector, "owasp-crs-default", evidence, key)
	if err != nil {
		t.Fatalf("EvaluateCoverageGapScenario: %v", err)
	}
	if result.Verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- no WAF-engine evidence at all means the route's coverage cannot be assessed, not that the attack was missed", result.Verdict, wafval.VerdictInconclusive)
	}
	if result.Completeness != wafval.CompletenessInsufficient {
		t.Errorf("Completeness = %q, want %q", result.Completeness, wafval.CompletenessInsufficient)
	}
}
