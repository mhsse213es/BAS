package avefficacy

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func testVector(t *testing.T, claim avval.ClaimType) avcatalog.Vector {
	t.Helper()
	v, err := avcatalog.NewVector(
		"AV-EFF-TEST-001", 1, avcatalog.FamilyScriptFileless, "test vector", avcatalog.SeverityHigh,
		[]avcatalog.Platform{avcatalog.PlatformWindowsWorkstation}, []avcatalog.RequiredCapability{avcatalog.CapabilityBehavioralNGAV},
		"preconditions", claim,
		avcatalog.ExecutionTemplate{Executor: "powershell", Command: "Write-Output test", Description: "d"},
		nil, "no counterpart needed for this test",
		"delete marker", "", avcatalog.StandardsMapping{ATTACKTechniques: []string{"T1059.001"}}, "test-authored",
	)
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	return v
}

func observedBlocked(controlSource avval.ControlSource, eventID string) avval.CollectionResult {
	return avval.CollectionResult{ControlSource: controlSource, Coverage: avval.CoverageFound, Observations: []avval.Observation{
		{ControlSource: controlSource, EventID: eventID, Prevention: avval.PreventionBlocked, EvidenceKind: avval.EvidenceObserved},
	}}
}

func observedMissed(controlSource avval.ControlSource, eventID string) avval.CollectionResult {
	return avval.CollectionResult{ControlSource: controlSource, Coverage: avval.CoverageSearchedVerifiedNone, Observations: []avval.Observation{
		{ControlSource: controlSource, EventID: eventID, Prevention: avval.PreventionAllowed, Detection: avval.DetectionNotObservedInWindow, EvidenceKind: avval.EvidenceObserved},
	}}
}

func TestEvaluateVector_Blocked_VerifiedProtection(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")}}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Finding != avval.FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q (reason: %s)", outcome.Finding, avval.FindingVerifiedProtection, outcome.FindingReason)
	}
	if outcome.Response != avval.ResponseNotApplicable {
		t.Errorf("Response = %q, want %q", outcome.Response, avval.ResponseNotApplicable)
	}
	if outcome.Telemetry != avval.TelemetryComplete {
		t.Errorf("Telemetry = %q, want %q", outcome.Telemetry, avval.TelemetryComplete)
	}
	if outcome.Configuration != "" {
		t.Errorf("Configuration = %q, want empty (not applicable)", outcome.Configuration)
	}
}

// Review Focus: contradictory evidence across control sources must resolve
// Inconclusive, never a fabricated gap.
func TestEvaluateVector_ContradictoryEvidence_Inconclusive(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{PreventionEvidence: []avval.CollectionResult{
		observedBlocked(avval.ControlSourceAVEngine, "e1"),
		{ControlSource: avval.ControlSourceEDR, Coverage: avval.CoverageFound, Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceEDR, EventID: "e2", Prevention: avval.PreventionAllowed, EvidenceKind: avval.EvidenceObserved},
		}},
	}}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Finding != avval.FindingInconclusive {
		t.Errorf("Finding = %q, want %q (reason: %s)", outcome.Finding, avval.FindingInconclusive, outcome.FindingReason)
	}
}

// Review Focus: partial telemetry coverage must be reported distinctly
// from the Finding -- a vector can resolve VerifiedProtection while its
// telemetry pipeline is still only Partial.
func TestEvaluateVector_PartialTelemetry_ReportedIndependently(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{PreventionEvidence: []avval.CollectionResult{
		observedBlocked(avval.ControlSourceAVEngine, "e1"),
		{ControlSource: avval.ControlSourceEDR, Coverage: avval.CoverageSearchIncomplete},
	}}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Finding != avval.FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q", outcome.Finding, avval.FindingVerifiedProtection)
	}
	if outcome.Telemetry != avval.TelemetryPartial {
		t.Errorf("Telemetry = %q, want %q", outcome.Telemetry, avval.TelemetryPartial)
	}
}

// Review Focus: an SLA breach is reported but never fabricates a gap --
// Finding stays VerifiedProtection even when detection arrived late.
func TestEvaluateVector_DelayedDetection_SLABreachedButFindingUnaffected(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	executedAt := time.Now().Add(-time.Hour)
	fixture := VectorFixture{
		PreventionEvidence: []avval.CollectionResult{
			{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
				{ControlSource: avval.ControlSourceAVEngine, EventID: "e1", Prevention: avval.PreventionAllowed, Detection: avval.DetectionDetected, ObservedAt: executedAt.Add(30 * time.Minute), EvidenceKind: avval.EvidenceObserved},
			}},
		},
		TestExecutedAt: executedAt,
		DetectionSLA:   5 * time.Minute,
	}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.DetectionLatency != LatencySLABreached {
		t.Errorf("DetectionLatency = %q, want %q (reason: %s)", outcome.DetectionLatency, LatencySLABreached, outcome.DetectionLatencyReason)
	}
	// Detected-but-allowed is still a real ConfirmedGap on its own merits --
	// this proves the SLA breach didn't CAUSE it, by checking the reason
	// names the real prevention/detection gap, not the latency.
	if outcome.Finding != avval.FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q", outcome.Finding, avval.FindingConfirmedGap)
	}
}

func TestEvaluateVector_WithinSLA(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	executedAt := time.Now().Add(-time.Hour)
	fixture := VectorFixture{
		PreventionEvidence: []avval.CollectionResult{
			{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
				{ControlSource: avval.ControlSourceAVEngine, EventID: "e1", Prevention: avval.PreventionBlocked, Detection: avval.DetectionDetected, ObservedAt: executedAt.Add(time.Minute), EvidenceKind: avval.EvidenceObserved},
			}},
		},
		TestExecutedAt: executedAt,
		DetectionSLA:   5 * time.Minute,
	}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.DetectionLatency != LatencyWithinSLA {
		t.Errorf("DetectionLatency = %q, want %q (reason: %s)", outcome.DetectionLatency, LatencyWithinSLA, outcome.DetectionLatencyReason)
	}
}

func TestEvaluateVector_NoSLADeclared_LatencyNotEvaluated(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")}}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.DetectionLatency != LatencyNotEvaluated {
		t.Errorf("DetectionLatency = %q, want %q", outcome.DetectionLatency, LatencyNotEvaluated)
	}
}

// Review Focus: duplicate events from the same control source must not be
// treated as independent corroboration once bundled through avefficacy --
// this proves avval's own dedup guarantee survives composition.
func TestEvaluateVector_DuplicateEventID_NotDoubleCountedThroughBundling(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{PreventionEvidence: []avval.CollectionResult{
		{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceAVEngine, EventID: "dup", Prevention: avval.PreventionBlocked, EvidenceKind: avval.EvidenceObserved},
			{ControlSource: avval.ControlSourceAVEngine, EventID: "dup", Prevention: avval.PreventionAllowed, EvidenceKind: avval.EvidenceObserved},
		}},
	}}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Finding != avval.FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q (duplicate event must not create Ambiguous evidence)", outcome.Finding, avval.FindingVerifiedProtection)
	}
}

func TestEvaluateVector_NoConfigurationCheckSupplied_EmptyConfiguration(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{
		PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")},
	}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Configuration != "" {
		t.Errorf("Configuration = %q, want empty when no ConfigurationCheck supplied", outcome.Configuration)
	}
}

func TestEvaluateVector_ConfigurationSnapshotSupplied_PolicyGap(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{
		PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")},
		Configuration: &ConfigurationCheck{
			Snapshot: avval.ConfigurationSnapshot{RealTimeProtectionEnabled: false, Coverage: avval.CoverageFound},
			Baseline: avval.ConfigurationBaseline{RequireRealTimeProtection: true},
		},
	}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Configuration != avval.ConfigurationPolicyGap {
		t.Errorf("Configuration = %q, want %q", outcome.Configuration, avval.ConfigurationPolicyGap)
	}
}

// Review Focus: configuration drift (the endpoint's active configuration
// diverging from the centrally managed policy) must be reported via
// avval.EvaluateConfigurationDrift, distinctly from a baseline-compliance
// policy gap.
func TestEvaluateVector_ConfigurationDrift_ReportedViaManagedComparison(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	managed := avval.ConfigurationSnapshot{RealTimeProtectionEnabled: true, Coverage: avval.CoverageFound}
	fixture := VectorFixture{
		PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")},
		Configuration: &ConfigurationCheck{
			Snapshot: avval.ConfigurationSnapshot{RealTimeProtectionEnabled: false, Coverage: avval.CoverageFound}, // local override
			Managed:  &managed,
		},
	}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Configuration != avval.ConfigurationDrift {
		t.Errorf("Configuration = %q, want %q (reason: %s)", outcome.Configuration, avval.ConfigurationDrift, outcome.ConfigurationReason)
	}
}

func TestEvaluateVector_MissedEvidence_ConfirmedGap(t *testing.T) {
	vector := testVector(t, avval.ClaimPrevention)
	fixture := VectorFixture{PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")}}
	outcome, err := EvaluateVector(vector, "baseline", fixture)
	if err != nil {
		t.Fatalf("EvaluateVector: %v", err)
	}
	if outcome.Finding != avval.FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q (reason: %s)", outcome.Finding, avval.FindingConfirmedGap, outcome.FindingReason)
	}
}
