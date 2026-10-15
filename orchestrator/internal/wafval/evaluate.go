package wafval

// Result is one claim's graded outcome. Verdict is derived, never set by an
// adapter; the raw view and the three independent dimensions are all preserved.
type Result struct {
	Key          CorrelationKey
	Expectation  Expectation
	View         CorrelatedView
	Completeness EvidenceCompleteness
	Confidence   Confidence
	Verdict      Verdict
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
			Verdict: VerdictInconclusive, Reason: "unknown claim type: " + string(exp.Claim),
		}
	}
	comp := deriveCompleteness(exp.Claim, results)
	conf := deriveConfidence(exp.Claim, comp, view, results)
	r := Result{Key: key, Expectation: exp, View: view, Completeness: comp, Confidence: conf}

	switch {
	case crossAxisBypass(exp.Claim, view):
		r.Verdict, r.Reason = VerdictInconclusive, "WAF reported a block but the origin received the request: enforcement contradicted by origin evidence"
	case claimAxisContradictory(exp.Claim, view):
		r.Verdict, r.Reason = VerdictInconclusive, "claim-relevant evidence is contradictory across mechanisms"
	case comp == CompletenessInsufficient:
		r.Verdict, r.Reason = VerdictInconclusive, "insufficient evidence to render a verdict"
	default:
		r.Verdict, r.Reason = deriveVerdict(exp.Claim, view, comp)
	}
	if err := Valid(exp.Claim, r.Verdict, r.Completeness); err != nil {
		panic("wafval: derived an invalid verdict/claim/completeness: " + err.Error())
	}
	return r
}

func knownClaim(c ClaimType) bool {
	switch c {
	case ClaimPrevention, ClaimFalsePositive, ClaimPolicyGap:
		return true
	default:
		return false
	}
}

func present(results []CollectionResult, m Mechanism) bool {
	for _, r := range results {
		if r.Mechanism == m && r.Coverage.Present() {
			return true
		}
	}
	return false
}

func deriveCompleteness(claim ClaimType, results []CollectionResult) EvidenceCompleteness {
	wafPresent := present(results, MechanismWAFEngine)
	switch claim {
	case ClaimPrevention:
		if !wafPresent {
			return CompletenessInsufficient
		}
		if present(results, MechanismOriginApp) {
			return CompletenessComplete
		}
		return CompletenessPartial
	case ClaimFalsePositive:
		if !wafPresent {
			return CompletenessInsufficient
		}
		return CompletenessComplete
	default:
		if !wafPresent {
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

func deriveConfidence(claim ClaimType, c EvidenceCompleteness, view CorrelatedView, results []CollectionResult) Confidence {
	conf := ceiling(c)
	// Contradicted claim evidence — same-axis across mechanisms, or the
	// cross-axis block-vs-received bypass — carries no confidence.
	if claimAxisContradictory(claim, view) || crossAxisBypass(claim, view) {
		return ConfidenceNone
	}
	// Internally ambiguous claim evidence (same mechanism, distinct events
	// disagree) cannot support a high/medium reading even under complete
	// coverage; cap it low, by parity with the contradiction rule.
	if claimAxisAmbiguous(claim, view) && confRank(conf) > confRank(ConfidenceLow) {
		conf = ConfidenceLow
	}
	// Inferred-only minimum evidence caps at Medium.
	if minimumInferredOnly(results) && confRank(conf) > confRank(ConfidenceMedium) {
		conf = ConfidenceMedium
	}
	return conf
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

// minimumInferredOnly reports whether the WAF-engine mechanism contributed only
// inferred observations (no observed evidence at all).
func minimumInferredOnly(results []CollectionResult) bool {
	sawWAF, sawObserved := false, false
	for _, r := range results {
		if r.Mechanism != MechanismWAFEngine {
			continue
		}
		for _, o := range r.Observations {
			sawWAF = true
			if o.EvidenceKind == EvidenceObserved {
				sawObserved = true
			}
		}
	}
	return sawWAF && !sawObserved
}

// claimAxisContradictory reports whether an axis the claim depends on is
// contradictory. Prevention/PolicyGap depend on enforcement + detection;
// FalsePositive depends on enforcement only.
func claimAxisContradictory(claim ClaimType, view CorrelatedView) bool {
	if view.EnforcementAx.State == AxisContradictory {
		return true
	}
	if claim != ClaimFalsePositive && view.DetectionAx.State == AxisContradictory {
		return true
	}
	return false
}

// crossAxisBypass reports the block-vs-received contradiction the per-axis model
// cannot express on a single axis: the WAF agrees it blocked, yet the origin
// agrees it received the request, so the "block" did not prevent reach. Scoped
// to prevention-shaped claims (not FalsePositive). Origin not_observed is
// deliberately NOT a contradiction here: "not_observed" must never be read as
// "did not happen" (spec §4).
func crossAxisBypass(claim ClaimType, view CorrelatedView) bool {
	if claim == ClaimFalsePositive {
		return false
	}
	enf := view.EnforcementAx
	org := view.OriginAx
	return enf.State == AxisAgree && enf.Enforcement == EnforcementBlocked &&
		org.State == AxisAgree && org.Origin == OriginReceived
}

// claimAxisAmbiguous reports whether a claim-relevant axis resolved to Ambiguous
// (same mechanism, distinct events disagree). Prevention/PolicyGap depend on
// enforcement + detection; FalsePositive on enforcement only.
func claimAxisAmbiguous(claim ClaimType, view CorrelatedView) bool {
	if view.EnforcementAx.State == AxisAmbiguous {
		return true
	}
	if claim != ClaimFalsePositive && view.DetectionAx.State == AxisAmbiguous {
		return true
	}
	return false
}

// deriveVerdict is the per-claim switch. Guards A and B have already run, so
// completeness is never Insufficient and no claim-relevant axis is
// contradictory here.
func deriveVerdict(claim ClaimType, view CorrelatedView, c EvidenceCompleteness) (Verdict, string) {
	switch claim {
	case ClaimPrevention:
		return derivePrevention(view)
	case ClaimFalsePositive:
		return deriveFalsePositive(view)
	default:
		// PolicyGap legs are evaluated as Prevention; the pair rule lives in
		// EvaluatePolicyGap. A bare PolicyGap claim here is treated as a
		// single Prevention-shaped leg.
		return derivePrevention(view)
	}
}

func derivePrevention(view CorrelatedView) (Verdict, string) {
	enf := view.EnforcementAx
	det := view.DetectionAx
	if enf.State == AxisAgree && enf.Enforcement == EnforcementBlocked {
		return VerdictBlocked, "WAF enforced a block"
	}
	if enf.State == AxisAgree && enf.Enforcement == EnforcementAllowed {
		switch {
		case det.State == AxisAgree && det.Detection == DetectionMatched:
			return VerdictDetectedButAllowed, "request detected but allowed through (enforcement gap)"
		case det.State == AxisAgree && det.Detection == DetectionNotMatched:
			return VerdictMissed, "request neither detected nor blocked (detection + enforcement gap)"
		default:
			return VerdictInconclusive, "allowed, but detection state could not be established"
		}
	}
	return VerdictInconclusive, "enforcement action could not be established"
}

func deriveFalsePositive(view CorrelatedView) (Verdict, string) {
	enf := view.EnforcementAx
	if enf.State != AxisAgree {
		return VerdictInconclusive, "enforcement action could not be established"
	}
	switch enf.Enforcement {
	case EnforcementAllowed:
		return VerdictAllowed, "legitimate request correctly allowed"
	case EnforcementBlocked, EnforcementChallenged, EnforcementTerminated:
		return VerdictIncorrectlyBlocked, "legitimate request incorrectly blocked (false positive)"
	default:
		return VerdictInconclusive, "enforcement action could not be established"
	}
}
