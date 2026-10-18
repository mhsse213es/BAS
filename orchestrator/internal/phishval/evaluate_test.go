package phishval

import "testing"

func ptrDelivery(o DeliveryOutcome) *DeliveryOutcome                  { return &o }
func ptrEnforcement(o EnforcementOutcome) *EnforcementOutcome         { return &o }
func ptrDetection(o DetectionOutcome) *DetectionOutcome               { return &o }
func ptrInteraction(o UserInteractionOutcome) *UserInteractionOutcome { return &o }
func ptrResponse(o ResponseOutcome) *ResponseOutcome                  { return &o }

func TestEvaluateDelivery_NilExpectation_NotApplicable(t *testing.T) {
	got := EvaluateDelivery(nil, &DeliveryObservation{Outcome: DeliveryDelivered})
	if got.Verdict != VerdictNotApplicable {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictNotApplicable)
	}
}

func TestEvaluateDelivery_NilObservation_NotTested(t *testing.T) {
	got := EvaluateDelivery(ptrDelivery(DeliveryDelivered), nil)
	if got.Verdict != VerdictNotTested {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictNotTested)
	}
	if got.Evidence != EvidenceMissing {
		t.Errorf("Evidence = %q, want %q", got.Evidence, EvidenceMissing)
	}
}

func TestEvaluateDelivery_KnownGood_MatchesExpectation(t *testing.T) {
	got := EvaluateDelivery(ptrDelivery(DeliveryQuarantined), &DeliveryObservation{
		Outcome: DeliveryQuarantined, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictPass)
	}
}

func TestEvaluateDelivery_KnownBad_ContradictsExpectation(t *testing.T) {
	got := EvaluateDelivery(ptrDelivery(DeliveryQuarantined), &DeliveryObservation{
		Outcome: DeliveryDelivered, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictFail)
	}
}

func TestEvaluateDelivery_UnknownObservedOutcome_Inconclusive(t *testing.T) {
	got := EvaluateDelivery(ptrDelivery(DeliveryQuarantined), &DeliveryObservation{Outcome: DeliveryUnknown})
	if got.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
	}
}

func TestEvaluateEnforcement_KnownGood_Blocked(t *testing.T) {
	got := EvaluateEnforcement(ptrEnforcement(EnforcementBlocked), &EnforcementObservation{
		Outcome: EnforcementBlocked, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictPass)
	}
}

func TestEvaluateEnforcement_KnownBad_Allowed(t *testing.T) {
	got := EvaluateEnforcement(ptrEnforcement(EnforcementBlocked), &EnforcementObservation{
		Outcome: EnforcementAllowed, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictFail)
	}
}

// TestEvaluateDetection_NotDetected_WithoutVerifiedSearchCoverage_IsInconclusive
// is phishing.txt §6's own non-negotiable rule: "the engine must not treat
// a missing alert as proof that detection failed until it verifies that
// the test actually reached the relevant control and that the observation
// window and telemetry source were valid." A DetectionNotDetectedWithinWindow
// claim without SearchedComplete=true must never be trusted at face value.
func TestEvaluateDetection_NotDetected_WithoutVerifiedSearchCoverage_IsInconclusive(t *testing.T) {
	got := EvaluateDetection(ptrDetection(DetectionDetected), &DetectionObservation{
		Outcome: DetectionNotDetectedWithinWindow, SearchedComplete: false,
	})
	if got.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q (unverified search coverage must never establish failure)", got.Verdict, VerdictInconclusive)
	}
}

func TestEvaluateDetection_NotDetected_WithVerifiedSearchCoverage_IsFail(t *testing.T) {
	got := EvaluateDetection(ptrDetection(DetectionDetected), &DetectionObservation{
		Outcome: DetectionNotDetectedWithinWindow, SearchedComplete: true,
		Evidence: EvidenceVerifiedTelemetry, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictFail)
	}
}

func TestEvaluateDetection_Detected_MatchesExpectation(t *testing.T) {
	got := EvaluateDetection(ptrDetection(DetectionDetected), &DetectionObservation{
		Outcome: DetectionDetected, Evidence: EvidenceVerifiedTelemetry, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictPass)
	}
}

func TestEvaluateUserInteraction_Reported_MatchesExpectation(t *testing.T) {
	got := EvaluateUserInteraction(ptrInteraction(InteractionReported), &UserInteractionObservation{
		Outcome: InteractionReported, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictPass)
	}
}

func TestEvaluateUserInteraction_Clicked_ContradictsExpectedReport(t *testing.T) {
	got := EvaluateUserInteraction(ptrInteraction(InteractionReported), &UserInteractionObservation{
		Outcome: InteractionClicked, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictFail)
	}
}

// TestEvaluateResponse_NotApplicableExpectation_PassesWithoutObservation is
// avval's own documented rule carried into phishval: NotApplicable is a
// legitimate outcome when nothing required a response -- it must not be
// scored NotTested merely because no response observation exists.
func TestEvaluateResponse_NotApplicableExpectation_PassesWithoutObservation(t *testing.T) {
	got := EvaluateResponse(ptrResponse(ResponseNotApplicable), nil)
	if got.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictPass)
	}
}

func TestEvaluateResponse_KnownGood_Remediated(t *testing.T) {
	got := EvaluateResponse(ptrResponse(ResponseRemediated), &ResponseObservation{
		Outcome: ResponseRemediated, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictPass)
	}
}

func TestEvaluateResponse_KnownBad_Failed(t *testing.T) {
	got := EvaluateResponse(ptrResponse(ResponseRemediated), &ResponseObservation{
		Outcome: ResponseFailed, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh,
	})
	if got.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q", got.Verdict, VerdictFail)
	}
}

func TestEvaluate_Composite_SetsRunIDScenarioIDVariant(t *testing.T) {
	exp := Expectation{
		ScenarioID:  "PH-TEST-000",
		Enforcement: ptrEnforcement(EnforcementBlocked),
	}
	obs := Observation{
		Enforcement: &EnforcementObservation{Outcome: EnforcementBlocked, Evidence: EvidenceControlReceipt, Confidence: ConfidenceHigh},
	}
	got := Evaluate("run-1", "variant-a", exp, obs)
	if got.RunID != "run-1" || got.ScenarioID != "PH-TEST-000" || got.Variant != "variant-a" {
		t.Errorf("Outcome identity = %+v, want RunID=run-1 ScenarioID=PH-TEST-000 Variant=variant-a", got)
	}
	if got.Enforcement.Verdict != VerdictPass {
		t.Errorf("Enforcement.Verdict = %q, want %q", got.Enforcement.Verdict, VerdictPass)
	}
	if got.Delivery.Verdict != VerdictNotApplicable {
		t.Errorf("Delivery.Verdict = %q, want %q (no expectation declared)", got.Delivery.Verdict, VerdictNotApplicable)
	}
}
