package dlppolicy

import "fmt"

// DLPPolicyScopedVerdict is one scope's already-computed verdict --
// the only input this file's Verify function consumes. It never
// reaches into rule-level or precedence-level internals: the caller
// has already run VerifyDLPPolicyRuleExpectation or
// VerifyDLPPolicyPrecedenceExpectation once per scope and hands the
// results here as plain data.
type DLPPolicyScopedVerdict struct {
	ScopeID     ScopeID
	Verdict     VerdictDetail
	Fingerprint string
}

// DLPPolicyVarianceExpectation declares which scopes are compared and
// which scope pairs are allowed to legitimately differ, and why -- so
// a documented, intentional policy difference is never reported as a
// finding.
type DLPPolicyVarianceExpectation struct {
	BaselineScopeID    ScopeID
	ComparisonScopeIDs []ScopeID
	PermittedVariance  map[ScopeID]string
	Note               string
}

// VerifyDLPPolicyVarianceExpectation returns one VerdictDetail per
// ComparisonScopeIDs entry, never a single collapsed verdict --
// variance is inherently a multi-way comparison, and collapsing N
// results into one would hide which scope actually diverged.
func VerifyDLPPolicyVarianceExpectation(exp DLPPolicyVarianceExpectation, results map[ScopeID]DLPPolicyScopedVerdict) map[ScopeID]VerdictDetail {
	out := make(map[ScopeID]VerdictDetail, len(exp.ComparisonScopeIDs))
	baseline, baselineFound := results[exp.BaselineScopeID]

	for _, s := range exp.ComparisonScopeIDs {
		comparison, found := results[s]
		if !baselineFound || !found {
			out[s] = VerdictDetail{Verdict: VerdictInconclusive, Reason: "no verdict available for this scope in this window"}
			continue
		}
		if !comparableVerdict(baseline.Verdict.Verdict) || !comparableVerdict(comparison.Verdict.Verdict) {
			out[s] = VerdictDetail{Verdict: VerdictInconclusive, Reason: "underlying check was inconclusive, not tested, or not applicable for at least one side; cannot claim variance"}
			continue
		}

		permittedReason, permitted := exp.PermittedVariance[s]

		if baseline.Verdict.Verdict != comparison.Verdict.Verdict {
			if permitted {
				out[s] = VerdictDetail{Verdict: VerdictConfirmedSuccess, Reason: fmt.Sprintf("scope differs as declared: %s", permittedReason)}
			} else {
				out[s] = VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: fmt.Sprintf("scope %q diverges from baseline %q: baseline verdict %q (fingerprint %q), comparison verdict %q (fingerprint %q)", s, exp.BaselineScopeID, baseline.Verdict.Verdict, baseline.Fingerprint, comparison.Verdict.Verdict, comparison.Fingerprint)}
			}
			continue
		}

		if baseline.Fingerprint != comparison.Fingerprint {
			if permitted {
				out[s] = VerdictDetail{Verdict: VerdictConfirmedSuccess, Reason: fmt.Sprintf("scope differs as declared: %s", permittedReason)}
			} else {
				out[s] = VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: fmt.Sprintf("both scopes satisfy their own expectation, but observed configuration differs: baseline fingerprint %q, comparison fingerprint %q", baseline.Fingerprint, comparison.Fingerprint)}
			}
			continue
		}

		out[s] = VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}

	return out
}

// comparableVerdict returns true only for the two verdicts that
// represent an actual pass/fail state. Inconclusive, NotTested, and
// NotApplicable are all incomparable -- none of them is a claim this
// function can safely diff against another scope's claim.
func comparableVerdict(v DLPPOLVerdict) bool {
	return v == VerdictConfirmedSuccess || v == VerdictConfirmedFailure
}
