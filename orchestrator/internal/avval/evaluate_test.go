package avval

import "testing"

func key(id string) CorrelationKey {
	return CorrelationKey{TestExecutionID: id, EndpointID: id}
}

func TestEvaluateClaim_Prevention_Blocked(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked, EvidenceKind: EvidenceObserved},
		}},
		{ControlSource: ControlSourceIndependentSensor, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceIndependentSensor, EventID: "e2", Prevention: PreventionBlocked, Execution: ExecutionNotObserved, EvidenceKind: EvidenceObserved},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, results, key("t1"))
	if r.Finding != FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingVerifiedProtection, r.Reason)
	}
	if r.Completeness != CompletenessComplete {
		t.Errorf("Completeness = %q, want %q", r.Completeness, CompletenessComplete)
	}
	if r.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", r.Confidence, ConfidenceHigh)
	}
}

func TestEvaluateClaim_Prevention_NeitherDetectedNorBlocked_ConfirmedGap(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageSearchedVerifiedNone, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionAllowed, Detection: DetectionNotObservedInWindow},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, results, key("t2"))
	if r.Finding != FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingConfirmedGap, r.Reason)
	}
}

func TestEvaluateClaim_Prevention_DetectedButAllowed_ConfirmedGap(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionAllowed, Detection: DetectionDetected},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, results, key("t3"))
	if r.Finding != FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingConfirmedGap, r.Reason)
	}
}

// Review Focus: a control reporting Blocked must not be trusted at face
// value when independent execution evidence agrees the artifact actually
// ran -- this is the cross-axis bypass the per-axis model alone cannot
// express.
func TestEvaluateClaim_Prevention_BlockedButExecuted_CrossAxisBypass(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked},
		}},
		{ControlSource: ControlSourceIndependentSensor, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceIndependentSensor, EventID: "e2", Execution: ExecutionExecuted},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, results, key("t4"))
	if r.Finding != FindingInconclusive {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingInconclusive, r.Reason)
	}
	if r.Confidence != ConfidenceNone {
		t.Errorf("Confidence = %q, want %q", r.Confidence, ConfidenceNone)
	}
}

func TestEvaluateClaim_Prevention_NoEvidence_Insufficient(t *testing.T) {
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, nil, key("t5"))
	if r.Finding != FindingInconclusive {
		t.Errorf("Finding = %q, want %q", r.Finding, FindingInconclusive)
	}
	if r.Completeness != CompletenessInsufficient {
		t.Errorf("Completeness = %q, want %q", r.Completeness, CompletenessInsufficient)
	}
}

func TestEvaluateClaim_Prevention_CrossControlContradiction_Inconclusive(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked},
		}},
		{ControlSource: ControlSourceEDR, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceEDR, EventID: "e2", Prevention: PreventionAllowed},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, results, key("t6"))
	if r.Finding != FindingInconclusive {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingInconclusive, r.Reason)
	}
}

func TestEvaluateClaim_FalsePositive_AllowedEvidence_VerifiedProtection(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionAllowed},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimFalsePositive}, results, key("t7"))
	if r.Finding != FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingVerifiedProtection, r.Reason)
	}
}

func TestEvaluateClaim_FalsePositive_BlockedEvidence_ConfirmedGap(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked},
		}},
	}
	r := EvaluateClaim(Expectation{Claim: ClaimFalsePositive}, results, key("t8"))
	if r.Finding != FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q (reason: %s)", r.Finding, FindingConfirmedGap, r.Reason)
	}
}

func TestEvaluateClaim_UnknownClaimType_Inconclusive_NoPanic(t *testing.T) {
	r := EvaluateClaim(Expectation{Claim: ClaimType("bogus")}, nil, key("t9"))
	if r.Finding != FindingInconclusive {
		t.Errorf("Finding = %q, want %q", r.Finding, FindingInconclusive)
	}
}
