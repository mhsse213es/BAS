package avval

// EvaluateResponse grades what happened after detection -- remediation,
// containment, failure, or genuinely not applicable -- independent of any
// claim type. Response is one of av.txt's independent result dimensions: a
// product can block execution but still fail to clean up, or detect
// correctly but fail to contain, and neither of those should be folded into
// the prevention/detection finding.
func EvaluateResponse(results []CollectionResult, key CorrelationKey) (ResponseOutcome, Confidence, string) {
	view := Correlate(key, results)
	ax := view.ResponseAx
	switch ax.State {
	case AxisContradictory:
		return ResponseUnknown, ConfidenceNone, "response outcome is contradictory across control sources"
	case AxisAmbiguous:
		return ResponseUnknown, ConfidenceLow, "response outcome is ambiguous within a single control source"
	case AxisAgree:
		conf := ConfidenceHigh
		if allInferredOnly(results) {
			conf = ConfidenceMedium
		}
		return ax.Response, conf, "response outcome established from agreeing control-source evidence"
	default:
		return ResponseUnknown, ConfidenceNone, "response outcome could not be established"
	}
}
