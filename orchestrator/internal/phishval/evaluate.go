package phishval

// EvaluateDelivery grades the Delivery dimension. A nil expectation means
// the scenario declared no Delivery assertion (NotApplicable); a nil
// observation means nothing was ever collected (NotTested) -- the two
// are never conflated.
func EvaluateDelivery(exp *DeliveryOutcome, obs *DeliveryObservation) DimensionResult {
	if exp == nil {
		return DimensionResult{Verdict: VerdictNotApplicable, Reason: "no delivery expectation declared for this scenario"}
	}
	if obs == nil {
		return DimensionResult{Verdict: VerdictNotTested, Reason: "no delivery observation collected", Evidence: EvidenceMissing, Confidence: ConfidenceInsufficient}
	}
	r := DimensionResult{Evidence: obs.Evidence, Confidence: obs.Confidence}
	switch {
	case obs.Outcome == DeliveryUnknown || obs.Outcome == DeliveryNotObserved:
		r.Verdict, r.Reason = VerdictInconclusive, "delivery outcome not established"
	case obs.Outcome == *exp:
		r.Verdict, r.Reason = VerdictPass, "observed delivery matches expectation"
	default:
		r.Verdict, r.Reason = VerdictFail, "observed delivery contradicts expectation"
	}
	return r
}

// EvaluateEnforcement grades the Enforcement dimension.
func EvaluateEnforcement(exp *EnforcementOutcome, obs *EnforcementObservation) DimensionResult {
	if exp == nil {
		return DimensionResult{Verdict: VerdictNotApplicable, Reason: "no enforcement expectation declared for this scenario"}
	}
	if obs == nil {
		return DimensionResult{Verdict: VerdictNotTested, Reason: "no enforcement observation collected", Evidence: EvidenceMissing, Confidence: ConfidenceInsufficient}
	}
	r := DimensionResult{Evidence: obs.Evidence, Confidence: obs.Confidence}
	switch {
	case obs.Outcome == EnforcementUnknown:
		r.Verdict, r.Reason = VerdictInconclusive, "enforcement outcome not established"
	case obs.Outcome == *exp:
		r.Verdict, r.Reason = VerdictPass, "observed enforcement matches expectation"
	default:
		r.Verdict, r.Reason = VerdictFail, "observed enforcement contradicts expectation"
	}
	return r
}

// EvaluateDetection grades the Detection dimension. phishing.txt §6's
// non-negotiable rule: a DetectionNotDetectedWithinWindow observation can
// only establish a failure when SearchedComplete confirms the evaluator
// actually verified complete search coverage for the window -- absence of
// evidence is never, by itself, evidence of absence.
func EvaluateDetection(exp *DetectionOutcome, obs *DetectionObservation) DimensionResult {
	if exp == nil {
		return DimensionResult{Verdict: VerdictNotApplicable, Reason: "no detection expectation declared for this scenario"}
	}
	if obs == nil {
		return DimensionResult{Verdict: VerdictNotTested, Reason: "no detection observation collected", Evidence: EvidenceMissing, Confidence: ConfidenceInsufficient}
	}
	r := DimensionResult{Evidence: obs.Evidence, Confidence: obs.Confidence}
	switch {
	case obs.Outcome == DetectionInconclusive:
		r.Verdict, r.Reason = VerdictInconclusive, "detection outcome inconclusive"
	case obs.Outcome == DetectionNotDetectedWithinWindow && !obs.SearchedComplete:
		r.Verdict, r.Reason = VerdictInconclusive, "search coverage not verified complete; absence of an alert is not proof detection failed"
	case obs.Outcome == *exp:
		r.Verdict, r.Reason = VerdictPass, "observed detection matches expectation"
	default:
		r.Verdict, r.Reason = VerdictFail, "observed detection contradicts expectation"
	}
	return r
}

// EvaluateUserInteraction grades the User Interaction dimension.
func EvaluateUserInteraction(exp *UserInteractionOutcome, obs *UserInteractionObservation) DimensionResult {
	if exp == nil {
		return DimensionResult{Verdict: VerdictNotApplicable, Reason: "no user-interaction expectation declared for this scenario"}
	}
	if obs == nil {
		return DimensionResult{Verdict: VerdictNotTested, Reason: "no user-interaction observation collected", Evidence: EvidenceMissing, Confidence: ConfidenceInsufficient}
	}
	r := DimensionResult{Evidence: obs.Evidence, Confidence: obs.Confidence}
	switch {
	case obs.Outcome == InteractionUnknown:
		r.Verdict, r.Reason = VerdictInconclusive, "user-interaction outcome not established"
	case obs.Outcome == *exp:
		r.Verdict, r.Reason = VerdictPass, "observed user interaction matches expectation"
	default:
		r.Verdict, r.Reason = VerdictFail, "observed user interaction contradicts expectation"
	}
	return r
}

// EvaluateResponse grades the Response dimension. ResponseNotApplicable
// is a legitimate expectation that passes without any observation --
// same discipline avval.ResponseOutcome already documents: nothing
// required a response, so there is nothing to have failed.
func EvaluateResponse(exp *ResponseOutcome, obs *ResponseObservation) DimensionResult {
	if exp == nil {
		return DimensionResult{Verdict: VerdictNotApplicable, Reason: "no response expectation declared for this scenario"}
	}
	if *exp == ResponseNotApplicable {
		return DimensionResult{Verdict: VerdictPass, Reason: "no response was required for this scenario"}
	}
	if obs == nil {
		return DimensionResult{Verdict: VerdictNotTested, Reason: "no response observation collected", Evidence: EvidenceMissing, Confidence: ConfidenceInsufficient}
	}
	r := DimensionResult{Evidence: obs.Evidence, Confidence: obs.Confidence}
	switch {
	case obs.Outcome == ResponseNotApplicable:
		r.Verdict, r.Reason = VerdictInconclusive, "response expected but observation reports nothing was required"
	case obs.Outcome == *exp:
		r.Verdict, r.Reason = VerdictPass, "observed response matches expectation"
	default:
		r.Verdict, r.Reason = VerdictFail, "observed response contradicts expectation"
	}
	return r
}

// Evaluate grades every applicable dimension of exp against obs,
// producing the full seven-dimension Outcome for one scenario execution.
// Each dimension is graded independently, from its own disjoint
// Expectation/Observation pair -- by construction, nothing in one
// dimension's Observation can ever change another dimension's Verdict.
func Evaluate(runID, variant string, exp Expectation, obs Observation) Outcome {
	return Outcome{
		RunID:           runID,
		ScenarioID:      exp.ScenarioID,
		Variant:         variant,
		Expectation:     exp,
		Observation:     obs,
		Delivery:        EvaluateDelivery(exp.Delivery, obs.Delivery),
		Enforcement:     EvaluateEnforcement(exp.Enforcement, obs.Enforcement),
		Detection:       EvaluateDetection(exp.Detection, obs.Detection),
		UserInteraction: EvaluateUserInteraction(exp.UserInteraction, obs.UserInteraction),
		Response:        EvaluateResponse(exp.Response, obs.Response),
	}
}
