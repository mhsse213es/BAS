package coverage

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
)

// Expectations are written before the cases run. A scenario whose verdicts are valid in both builds is
// Validated, unless its timing claim is provisional. A provisional scenario is evaluated, not validated, and
// the reason is kept.
func TestProvisionalTimingClaimIsEvaluatedNotValidated(t *testing.T) {
	validVerdicts := Verdicts{
		Vulnerable: &grade.Outcome{Result: grade.FAIL, Exploitability: grade.Exploited},
		Fixed:      &grade.Outcome{Result: grade.PASS, Control: grade.Enforced},
	}
	supported := func(string) bool { return true }
	results := map[string]Verdicts{"S-1": validVerdicts, "S-2": validVerdicts}
	catalog := []contract.Scenario{
		{ID: "S-1", TimingClaim: "provisional", TimingClaimReason: "no approved requirement"},
		{ID: "S-2"},
	}
	r := Build(catalog, supported, results)
	if r.Validated != 1 || r.Provisional != 1 || r.Evaluated != 2 {
		t.Fatalf("validated=%d provisional=%d evaluated=%d, want 1, 1, 2", r.Validated, r.Provisional, r.Evaluated)
	}
	if !r.Consistent() {
		t.Fatalf("report is not consistent: %+v", r)
	}
	for _, e := range r.Entries {
		if e.ID == "S-1" && (e.Status != Provisional || e.Reason != "no approved requirement") {
			t.Fatalf("S-1 entry = %+v, want provisional with its reason", e)
		}
	}
}
