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
