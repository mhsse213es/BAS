package scenario

import (
	"strings"
	"testing"
)

func TestClassifyExecution_VetoedStepTakesPriorityOverEverything(t *testing.T) {
	r := ExecResult{
		Vetoed: true, VetoedActionKey: "vss_delete",
		VetoedExecutionClass: "destructive", VetoedBlockSource: "catalog",
		ExitCode: -1,
	}
	outcome, reason, detail := classifyExecution(r, "")
	if outcome != OutcomeVetoed {
		t.Errorf("outcome = %v, want OutcomeVetoed", outcome)
	}
	if reason != ErrNone {
		t.Errorf("reason = %v, want ErrNone -- a veto is not a BAS execution error", reason)
	}
	if !strings.Contains(detail, "VETOED") || !strings.Contains(detail, "not tested") {
		t.Errorf("detail = %q, must clearly state the customer's defenses were not tested", detail)
	}
}
