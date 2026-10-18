package dlpcorrelate

import "fmt"

// Campaign06BusinessContinuityVersusDataProtection is dlp.txt §3C's
// Campaign 06: "Business continuity versus data protection. Test
// legitimate business workflows alongside prohibited disclosure cases
// -> verify authorized collaboration succeeds -> verify restricted
// actions remain blocked -> measure false positives and operational
// friction." It reuses scenariodifferentiation.go's existing
// EvaluateScenarioDifferentiation unchanged, generalized to variable-
// length buckets rather than Campaign 03's 3 fixed named cases, since
// this campaign's own text speaks of categories ("workflows", "cases"),
// not named roles.
//
// Each legitimate case must already have ExpectedToSucceed == true and
// each prohibited case must already have ExpectedToSucceed == false --
// a case placed in the wrong bucket is a scenario-authoring mistake,
// not a DLP finding, and is rejected with an error rather than silently
// folded into the differentiation verdict.
func Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited []ScenarioCase) (ScenarioDifferentiationResult, error) {
	for _, c := range legitimate {
		if !c.ExpectedToSucceed {
			return ScenarioDifferentiationResult{}, fmt.Errorf("dlpcorrelate: legitimate case %q has ExpectedToSucceed=false, which contradicts its bucket", c.Label)
		}
	}
	for _, c := range prohibited {
		if c.ExpectedToSucceed {
			return ScenarioDifferentiationResult{}, fmt.Errorf("dlpcorrelate: prohibited case %q has ExpectedToSucceed=true, which contradicts its bucket", c.Label)
		}
	}

	all := make([]ScenarioCase, 0, len(legitimate)+len(prohibited))
	all = append(all, legitimate...)
	all = append(all, prohibited...)
	return EvaluateScenarioDifferentiation(all)
}
