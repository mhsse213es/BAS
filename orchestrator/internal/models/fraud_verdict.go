package models

// CombinedVerdict folds the endpoint and fraud-control verdicts (PASS, FAIL,
// SKIPPED) into one. A FAIL on either side fails the step. It is PASS only when
// both sides are PASS. Anything else is SKIPPED, so an endpoint block with no
// ledger call never reads as an overall PASS.
func CombinedVerdict(endpoint, fraud string) string {
	if endpoint == "FAIL" || fraud == "FAIL" {
		return "FAIL"
	}
	if endpoint == "PASS" && fraud == "PASS" {
		return "PASS"
	}
	return "SKIPPED"
}

// EffectiveResult is the result a step counts as once its fraud-control record
// is folded in. Without a fraud record it is the endpoint result unchanged.
// Only a real endpoint PASS/FAIL (or blocked) is combined; error, skipped and
// vetoed results have no security verdict to combine and are returned as is.
func EffectiveResult(r SimulationResult) CheckResult {
	if r.FraudControl == nil {
		return r.Result
	}
	var endpoint string
	switch r.Result {
	case ResultPass, ResultBlocked:
		endpoint = "PASS"
	case ResultFail:
		endpoint = "FAIL"
	default:
		return r.Result
	}
	switch CombinedVerdict(endpoint, r.FraudControl.Verdict) {
	case "FAIL":
		return ResultFail
	case "PASS":
		return r.Result
	default:
		return ResultSkipped
	}
}

// ApplyFraudControl stores the combined verdict in r.Result, so every reader of
// the result (scorer, dashboards, PDF, CSV, run lists) sees the fraud outcome.
// The endpoint verdict is kept in r.EndpointResult. It is idempotent: it always
// derives from the saved endpoint verdict, so applying it twice changes nothing.
// Remediation is recomputed for the combined result, and Details gets a prefix
// naming the fraud outcome when it is not PASS.
func ApplyFraudControl(r *SimulationResult) {
	if r.FraudControl == nil {
		return
	}
	if r.EndpointResult == "" {
		r.EndpointResult = r.Result
	}
	endpoint := r.EndpointResult
	combined := EffectiveResult(SimulationResult{Result: endpoint, FraudControl: r.FraudControl})

	// Rebuild Details from the endpoint text, not the already-prefixed text.
	details := r.Details
	if idx := len(fraudDetailsPrefix(r.FraudControl)); idx > 0 && len(details) >= idx && details[:idx] == fraudDetailsPrefix(r.FraudControl) {
		details = details[idx:]
	}
	r.Result = combined
	if r.FraudControl.Verdict != "PASS" && r.FraudControl.Verdict != "" {
		r.Details = fraudDetailsPrefix(r.FraudControl) + details
	} else {
		r.Details = details
	}
	r.Remediation = Remediation(combined, r.Technique.Tactic, r.Technique.ID, r.Technique.Name)
}

func fraudDetailsPrefix(fc *FraudControl) string {
	if fc == nil || fc.Verdict == "PASS" || fc.Verdict == "" {
		return ""
	}
	reason := fc.Reason
	if reason == "" {
		reason = "see fraud-control record"
	}
	return "[fraud control " + fc.Verdict + ": " + reason + "] "
}

// BackfillFraudVerdicts applies ApplyFraudControl to stored results that carry a
// fraud-control record but were written before the verdict was folded into
// Result. It returns the rewritten slice and whether anything changed. Results
// without a fraud record are untouched. Running it twice changes nothing.
func BackfillFraudVerdicts(results []SimulationResult) ([]SimulationResult, bool) {
	out := make([]SimulationResult, len(results))
	copy(out, results)
	changed := false
	for i := range out {
		if out[i].FraudControl == nil || out[i].EndpointResult != "" {
			continue
		}
		before := out[i]
		ApplyFraudControl(&out[i])
		if out[i].Result != before.Result || out[i].Details != before.Details || out[i].EndpointResult != before.EndpointResult {
			changed = true
		}
	}
	return out, changed
}
