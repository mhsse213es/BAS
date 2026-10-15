package webgwefficacy

// AttackChainStep is one step's own already-computed verdict,
// labeled for reporting -- ComposeAttackChain never recomputes a
// step's verdict itself, it only combines verdicts callers already
// derived from VerifyHTTPExpectation, VerifyTLSInspectionExpectation,
// VerifyFailureModeExpectation, or VerifyPolicyBaselineExpectation.
type AttackChainStep struct {
	Label  string        `json:"label"`
	Result VerdictDetail `json:"result"`
}

// AttackChainResult composes several independently-verified steps
// into one chain-level finding.
type AttackChainResult struct {
	ChainLabel     string            `json:"chainLabel"`
	Steps          []AttackChainStep `json:"steps"`
	OverallVerdict WebGWVerdict      `json:"overallVerdict"`
}

// ComposeAttackChain combines each step's own verdict into one
// chain-level verdict representing whether the organization's
// controls, collectively, stopped this kill chain. A single step
// whose control held (Pass) breaks the chain -- the attacker's
// objective requires every step to succeed, so one blocked step is
// enough to defeat the whole chain, regardless of any other step's
// status. Only when every step's control failed (Fail) does the
// chain succeed for the attacker, the worst finding. A step with no
// evidence (Inconclusive/Unsupported) that isn't overridden by an
// actual Pass elsewhere in the chain leaves the overall result
// Inconclusive -- missing evidence is never read as the chain having
// succeeded.
func ComposeAttackChain(chainLabel string, steps []AttackChainStep) AttackChainResult {
	result := AttackChainResult{ChainLabel: chainLabel, Steps: steps}
	if len(steps) == 0 {
		result.OverallVerdict = VerdictNotApplicable
		return result
	}
	anyPass := false
	anyInconclusive := false
	for _, s := range steps {
		switch s.Result.Verdict {
		case VerdictPass:
			anyPass = true
		case VerdictInconclusive, VerdictUnsupported:
			anyInconclusive = true
		}
	}
	switch {
	case anyPass:
		result.OverallVerdict = VerdictPass
	case anyInconclusive:
		result.OverallVerdict = VerdictInconclusive
	default:
		result.OverallVerdict = VerdictFail
	}
	return result
}
