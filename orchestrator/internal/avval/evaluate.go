package avval

// Result is one claim's graded outcome. Finding is derived, never set by an
// adapter; the raw view and the independent dimensions are all preserved.
type Result struct {
	Key          CorrelationKey
	Expectation  Expectation
	View         CorrelatedView
	Completeness EvidenceCompleteness
	Confidence   Confidence
	Finding      FindingClassification
	Reason       string
}

// EvaluateClaim grades one claim against collected evidence. Pure over its
// inputs: no I/O, no clock, no hidden state.
func EvaluateClaim(exp Expectation, results []CollectionResult, key CorrelationKey) Result {
	view := Correlate(key, results)
	// An unrecognized claim type is caller/adapter error, not evidence: a pure
	// domain function fed by adapters must not crash a worker on it.
	if !knownClaim(exp.Claim) {
		return Result{
			Key: key, Expectation: exp, View: view,
			Completeness: CompletenessInsufficient, Confidence: ConfidenceNone,
			Finding: FindingInconclusive, Reason: "unknown claim type: " + string(exp.Claim),
		}
	}
	comp := deriveCompleteness(exp.Claim, results)
	conf := deriveConfidence(exp.Claim, comp, view, results)
	r := Result{Key: key, Expectation: exp, View: view, Completeness: comp, Confidence: conf}

	switch {
	case crossAxisBypass(exp.Claim, view):
		r.Finding, r.Reason = FindingInconclusive, "a control reported blocking the artifact, but independent evidence shows it executed anyway: prevention contradicted by execution evidence"
	case claimAxisContradictory(exp.Claim, view):
		r.Finding, r.Reason = FindingInconclusive, "claim-relevant evidence is contradictory across control sources"
	case comp == CompletenessInsufficient:
		r.Finding, r.Reason = FindingInconclusive, "insufficient evidence to render a finding"
	default:
		r.Finding, r.Reason = deriveFinding(exp.Claim, view)
	}
	if err := Valid(exp.Claim, r.Finding, r.Completeness); err != nil {
		panic("avval: derived an invalid finding/claim/completeness: " + err.Error())
	}
	return r
}

func knownClaim(c ClaimType) bool {
	switch c {
	case ClaimPrevention, ClaimFalsePositive:
		return true
	default:
		return false
	}
}

// anyControlPresent reports whether any named control source established
// coverage. Unlike wafval (which has one fixed required mechanism, the WAF
// engine), AV/NGAV evidence can legitimately come from any of several
// control sources -- the vendor-neutral minimum is that SOME control
// reported, not a specific one.
func anyControlPresent(results []CollectionResult) bool {
	for _, r := range results {
		if r.ControlSource != "" && r.Coverage.Present() {
			return true
		}
	}
	return false
}

func present(results []CollectionResult, cs ControlSource) bool {
	for _, r := range results {
		if r.ControlSource == cs && r.Coverage.Present() {
			return true
		}
	}
	return false
}

func deriveCompleteness(claim ClaimType, results []CollectionResult) EvidenceCompleteness {
	controlPresent := anyControlPresent(results)
	switch claim {
	case ClaimPrevention:
		if !controlPresent {
			return CompletenessInsufficient
		}
		if present(results, ControlSourceIndependentSensor) {
			return CompletenessComplete
		}
		return CompletenessPartial
	case ClaimFalsePositive:
		if !controlPresent {
			return CompletenessInsufficient
		}
		return CompletenessComplete
	default:
		if !controlPresent {
			return CompletenessInsufficient
		}
		return CompletenessPartial
	}
}

func ceiling(c EvidenceCompleteness) Confidence {
	switch c {
	case CompletenessComplete:
		return ConfidenceHigh
	case CompletenessPartial:
		return ConfidenceMedium
	default:
		return ConfidenceNone
	}
}

func confRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func deriveConfidence(claim ClaimType, c EvidenceCompleteness, view CorrelatedView, results []CollectionResult) Confidence {
	conf := ceiling(c)
	// Contradicted claim evidence -- same-axis across control sources, or the
	// cross-axis block-vs-executed bypass -- carries no confidence.
	if claimAxisContradictory(claim, view) || crossAxisBypass(claim, view) {
		return ConfidenceNone
	}
	// Internally ambiguous claim evidence (same control source, distinct
	// events disagree) cannot support a high/medium reading even under
	// complete coverage; cap it low, by parity with the contradiction rule.
	if claimAxisAmbiguous(claim, view) && confRank(conf) > confRank(ConfidenceLow) {
		conf = ConfidenceLow
	}
	// Inferred-only evidence caps at Medium.
	if allInferredOnly(results) && confRank(conf) > confRank(ConfidenceMedium) {
		conf = ConfidenceMedium
	}
	return conf
}

// allInferredOnly reports whether every observation across every result was
// inferred, never directly observed.
func allInferredOnly(results []CollectionResult) bool {
	sawAny, sawObserved := false, false
	for _, r := range results {
		for _, o := range r.Observations {
			sawAny = true
			if o.EvidenceKind == EvidenceObserved {
				sawObserved = true
			}
		}
	}
	return sawAny && !sawObserved
}

// claimAxisContradictory reports whether an axis the claim depends on is
// contradictory. Both claim shapes depend on prevention; Prevention also
// depends on detection (FalsePositive does not).
func claimAxisContradictory(claim ClaimType, view CorrelatedView) bool {
	if view.PreventionAx.State == AxisContradictory {
		return true
	}
	if claim != ClaimFalsePositive && view.DetectionAx.State == AxisContradictory {
		return true
	}
	return false
}

// claimAxisAmbiguous mirrors claimAxisContradictory for the Ambiguous state.
func claimAxisAmbiguous(claim ClaimType, view CorrelatedView) bool {
	if view.PreventionAx.State == AxisAmbiguous {
		return true
	}
	if claim != ClaimFalsePositive && view.DetectionAx.State == AxisAmbiguous {
		return true
	}
	return false
}

// crossAxisBypass reports the block-vs-executed contradiction the per-axis
// model cannot express on a single axis: a control agrees it blocked the
// artifact, yet independent execution evidence agrees it ran anyway, so the
// "block" did not actually prevent execution. Scoped to prevention-shaped
// claims (not FalsePositive). ExecutionNotObserved is deliberately NOT a
// contradiction here: "not_observed" must never be read as "did not happen".
func crossAxisBypass(claim ClaimType, view CorrelatedView) bool {
	if claim == ClaimFalsePositive {
		return false
	}
	prev := view.PreventionAx
	exe := view.ExecutionAx
	return prev.State == AxisAgree && prev.Prevention == PreventionBlocked &&
		exe.State == AxisAgree && exe.Execution == ExecutionExecuted
}

// deriveFinding is the per-claim switch. Guards have already run, so
// completeness is never Insufficient and no claim-relevant axis is
// contradictory here.
func deriveFinding(claim ClaimType, view CorrelatedView) (FindingClassification, string) {
	switch claim {
	case ClaimFalsePositive:
		return deriveFalsePositive(view)
	default:
		return derivePrevention(view)
	}
}

func derivePrevention(view CorrelatedView) (FindingClassification, string) {
	prev := view.PreventionAx
	det := view.DetectionAx
	if prev.State != AxisAgree {
		return FindingInconclusive, "prevention outcome could not be established"
	}
	switch prev.Prevention {
	case PreventionBlocked:
		return FindingVerifiedProtection, "the control blocked the malicious artifact/behavior"
	case PreventionPartiallyBlocked:
		return FindingConfirmedGap, "the control only partially blocked the malicious artifact/behavior -- a demonstrable gap remains"
	case PreventionAllowed:
		switch {
		case det.State == AxisAgree && det.Detection == DetectionDetected:
			return FindingConfirmedGap, "detected but not blocked -- partial control failure (enforcement gap)"
		case det.State == AxisAgree && det.Detection == DetectionNotObservedInWindow:
			return FindingConfirmedGap, "neither detected nor blocked -- confirmed protection gap"
		default:
			return FindingInconclusive, "allowed, but detection state could not be established"
		}
	default:
		return FindingInconclusive, "prevention outcome could not be established"
	}
}

func deriveFalsePositive(view CorrelatedView) (FindingClassification, string) {
	prev := view.PreventionAx
	if prev.State != AxisAgree {
		return FindingInconclusive, "prevention outcome could not be established"
	}
	switch prev.Prevention {
	case PreventionAllowed:
		return FindingVerifiedProtection, "legitimate business activity correctly allowed without disruption"
	case PreventionBlocked, PreventionPartiallyBlocked:
		return FindingConfirmedGap, "legitimate business activity incorrectly blocked or disrupted (false positive)"
	default:
		return FindingInconclusive, "prevention outcome could not be established"
	}
}
