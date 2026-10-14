package backupassurance

import (
	"fmt"

	"github.com/audspect/bas/internal/controlval"
)

// classifyObserverResult is the 5-branch decision tree (spec section C).
// An observer error always wins over tested/outcome -- a failed lookup
// must never produce a PASS. The second branch is a deliberate rejection
// of a malformed observer response (claiming a successful outcome while
// also claiming the check never ran) -- validated, never silently
// accepted as either SKIPPED or PASS.
func classifyObserverResult(tested, outcome bool, reason string, err error) (controlval.Verdict, controlval.SkipReason, string) {
	if err != nil {
		return controlval.VerdictError, "", "observer failed: " + err.Error()
	}
	if !tested && outcome {
		return controlval.VerdictError, "", fmt.Sprintf("observer contract violation: outcome=true but tested=false (reason=%q)", reason)
	}
	if !tested {
		return controlval.VerdictSkipped, controlval.SkipNotTested, reason
	}
	if outcome {
		return controlval.VerdictPass, "", reason
	}
	return controlval.VerdictFail, "", reason
}
