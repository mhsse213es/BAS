package wafcatalog

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafval"
)

// Review Focus: a vector with no BenignCounterpart must return exactly one
// LegExpectation -- never a length-2 slice padded with a zero-value second
// entry that a careless caller could mistake for a real benign leg.
func TestExpectations_NoBenignCounterpart_ReturnsExactlyOne(t *testing.T) {
	v, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "metadata SSRF", SeverityCritical, "x",
		validMalicious(), nil, "no legitimate counterpart", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMalicious {
		t.Errorf("legs[0].Leg = %q, want %q", legs[0].Leg, LegMalicious)
	}
	if legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0].Expectation.Claim = %q, want %q", legs[0].Expectation.Claim, wafval.ClaimPrevention)
	}
}

func TestExpectations_WithBenignCounterpart_ReturnsBoth(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want malicious/ClaimPrevention", legs[0])
	}
	if legs[1].Leg != LegBenign || legs[1].Expectation.Claim != wafval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want benign/ClaimFalsePositive", legs[1])
	}
	if legs[0].Expectation.PolicyBasis != "owasp-crs-default" || legs[1].Expectation.PolicyBasis != "owasp-crs-default" {
		t.Errorf("PolicyBasis not threaded through to both legs: %+v", legs)
	}
}

// TestMaliciousLeg_BlockedByWAF_YieldsBlocked proves a catalog-driven
// malicious leg flows correctly through wafval.EvaluateClaim end to end
// (spec §11, acceptance gate item 7).
func TestMaliciousLeg_BlockedByWAF_YieldsBlocked(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-1", RequestID: "req-1", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-1", RequestID: "req-1", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
		{Mechanism: wafval.MechanismOriginApp, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismOriginApp, EventID: "evt-2", RequestID: "req-1", ObservedAt: now, Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginNotObserved, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	if result.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictBlocked)
	}
}

// TestBenignLeg_Allowed_YieldsAllowed proves the benign leg flows correctly
// (spec §11, acceptance gate item 8).
func TestBenignLeg_Allowed_YieldsAllowed(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-2", RequestID: "req-2", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-3", RequestID: "req-2", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionUnknown, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[1].Expectation, results, key)
	if result.Verdict != wafval.VerdictAllowed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictAllowed)
	}
}

// TestMaliciousLeg_AllowedAndUndetected_YieldsMissed proves a genuine
// catalog-driven negative finding (spec §11, acceptance gate item 9).
func TestMaliciousLeg_AllowedAndUndetected_YieldsMissed(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-3", RequestID: "req-3", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-4", RequestID: "req-3", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
		{Mechanism: wafval.MechanismOriginApp, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismOriginApp, EventID: "evt-5", RequestID: "req-3", ObservedAt: now, Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginReceived, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	if result.Verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictMissed)
	}
}

// TestBenignLeg_Blocked_YieldsIncorrectlyBlocked proves the catalog genuinely
// surfaces a false positive (spec §11, acceptance gate item 10).
func TestBenignLeg_Blocked_YieldsIncorrectlyBlocked(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-4", RequestID: "req-4", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-6", RequestID: "req-4", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionUnknown, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[1].Expectation, results, key)
	if result.Verdict != wafval.VerdictIncorrectlyBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictIncorrectlyBlocked)
	}
}

// TestSameFixture_RunTwice_IdenticalResult proves determinism (spec §11,
// acceptance gate item 12).
func TestSameFixture_RunTwice_IdenticalResult(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-5", RequestID: "req-5", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-7", RequestID: "req-5", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	first := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	second := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	if first.Verdict != second.Verdict || first.Confidence != second.Confidence || first.Completeness != second.Completeness {
		t.Errorf("non-deterministic: first=%+v, second=%+v", first, second)
	}
}
