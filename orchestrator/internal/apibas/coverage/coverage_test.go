package coverage

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/reporting"
)

// withoutAsync models the state before the async adapter exists: every protocol is supported
// except async. The catalog's async scenarios are then unsupported.
func withoutAsync(p string) bool {
	return contract.ProtocolSupported(p) && p != "async"
}

func loadCatalog(t *testing.T) []contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	return all
}

func validFail() grade.Outcome {
	return grade.Outcome{Result: grade.FAIL, Exploitability: grade.Exploited, Control: grade.Failed}
}

func validPass() grade.Outcome {
	return grade.Outcome{Result: grade.PASS, Exploitability: grade.NotExploited, Control: grade.Enforced}
}

func entry(r Report, id string) Entry {
	for _, e := range r.Entries {
		if e.ID == id {
			return e
		}
	}
	return Entry{}
}

func ptr(o grade.Outcome) *grade.Outcome { return &o }

// An unsupported scenario counts toward the catalogue, and nowhere else.
func TestUnsupportedCountsOnlyInCatalogue(t *testing.T) {
	all := loadCatalog(t)
	r := Build(all, withoutAsync, nil)
	if r.Catalogued != len(all) {
		t.Fatalf("catalogued = %d, want %d", r.Catalogued, len(all))
	}
	if r.Unsupported != 2 {
		t.Fatalf("unsupported = %d, want the 2 async scenarios", r.Unsupported)
	}
	if r.Evaluated != 0 || r.Validated != 0 {
		t.Fatalf("no results were supplied, but evaluated=%d validated=%d", r.Evaluated, r.Validated)
	}
	if !r.Consistent() {
		t.Fatalf("classes do not sum to the catalog size: %+v", r)
	}
	if got := entry(r, "API-BAS-ABUSE-010"); got.Status != Unsupported || got.Reason != grade.ReasonUnsupportedProtocol {
		t.Fatalf("async entry = %+v, want unsupported with UNSUPPORTED_PROTOCOL", got)
	}
}

// An unsupported scenario is not inflated by results supplied for it.
func TestUnsupportedIgnoresResults(t *testing.T) {
	all := loadCatalog(t)
	results := map[string]Verdicts{
		"API-BAS-ABUSE-010": {Vulnerable: ptr(validFail()), Fixed: ptr(validPass())},
	}
	r := Build(all, withoutAsync, results)
	if got := entry(r, "API-BAS-ABUSE-010"); got.Status != Unsupported {
		t.Fatalf("unsupported scenario with results = %s, want unsupported", got.Status)
	}
}

// Coverage increases only after a valid evaluation: an adapter that exists but has no verdict makes
// the scenario implemented and unevaluated, not evaluated.
func TestAdapterLaterIncreasesCoverageOnlyAfterValidEvaluation(t *testing.T) {
	all := loadCatalog(t)

	before := Build(all, withoutAsync, nil)
	after := Build(all, contract.ProtocolSupported, nil)
	if after.Implemented <= before.Implemented {
		t.Fatalf("implemented did not rise when the async adapter was added: %d -> %d", before.Implemented, after.Implemented)
	}
	if after.Evaluated != before.Evaluated {
		t.Fatalf("evaluated rose without any verdict: %d -> %d", before.Evaluated, after.Evaluated)
	}
	if got := entry(after, "API-BAS-ABUSE-010"); got.Status != Unevaluated {
		t.Fatalf("implemented async scenario with no verdict = %s, want unevaluated", got.Status)
	}

	withVerdict := Build(all, contract.ProtocolSupported, map[string]Verdicts{
		"API-BAS-ABUSE-010": {Vulnerable: ptr(validFail()), Fixed: ptr(validPass())},
	})
	if withVerdict.Evaluated != after.Evaluated+1 || withVerdict.Validated != 1 {
		t.Fatalf("valid pair did not raise evaluated and validated: evaluated %d -> %d, validated %d",
			after.Evaluated, withVerdict.Evaluated, withVerdict.Validated)
	}
}

// Validated needs both builds. A vulnerable FAIL alone is evaluated, not validated.
func TestValidatedNeedsBothBuilds(t *testing.T) {
	all := loadCatalog(t)
	r := Build(all, contract.ProtocolSupported, map[string]Verdicts{
		"API-BAS-INJ-007": {Vulnerable: ptr(validFail())},
	})
	if got := entry(r, "API-BAS-INJ-007"); got.Status != Evaluated {
		t.Fatalf("vulnerable-only verdict = %s, want evaluated", got.Status)
	}
	if r.Validated != 0 {
		t.Fatalf("validated = %d with only one build, want 0", r.Validated)
	}
}

// An ERROR is never a valid verdict and is reported separately.
func TestErrorsAreExcluded(t *testing.T) {
	all := loadCatalog(t)
	errOut := grade.Outcome{Result: grade.ERROR, Reason: "TARGET_UNREACHABLE"}
	r := Build(all, contract.ProtocolSupported, map[string]Verdicts{
		"API-BAS-AUTHZ-001": {Vulnerable: ptr(errOut)},
	})
	got := entry(r, "API-BAS-AUTHZ-001")
	if got.Status != Errored || got.Reason != "TARGET_UNREACHABLE" {
		t.Fatalf("errored scenario = %+v, want error with its reason", got)
	}
	if r.Evaluated != 0 || r.Errored != 1 {
		t.Fatalf("evaluated=%d errored=%d, want 0 and 1", r.Evaluated, r.Errored)
	}
}

// The report shows numerators, denominators and exclusions.
func TestFormatShowsDenominatorAndExclusions(t *testing.T) {
	all := loadCatalog(t)
	r := Build(all, withoutAsync, nil)
	out := Format(r)
	for _, want := range []string{"Evaluated:", "/", "unsupported (no adapter)", "API-BAS-ABUSE-010", "UNSUPPORTED_PROTOCOL"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func reportScenario() contract.Scenario {
	return contract.Scenario{ID: "API-BAS-REPORT-X", Reporting: &reporting.Policy{}}
}

func enforcedPass() *grade.Outcome {
	o := grade.Outcome{Result: grade.PASS, Exploitability: grade.ExploitNotApplicable, Control: grade.Enforced}
	return &o
}

// A reporting scenario that PASSes with control enforced in both builds is workflow-verified: counted on its own line, in the
// catalogue, and in neither Evaluated nor Validated.
func TestWorkflowVerifiedIsSeparateFromEvaluatedAndValidated(t *testing.T) {
	cat := []contract.Scenario{reportScenario()}
	r := Build(cat, contract.ProtocolSupported, map[string]Verdicts{"API-BAS-REPORT-X": {Vulnerable: enforcedPass(), Fixed: enforcedPass()}})
	if r.WorkflowVerified != 1 || r.Evaluated != 0 || r.Validated != 0 || r.Unevaluated != 0 {
		t.Fatalf("workflow=%d evaluated=%d validated=%d unevaluated=%d, want 1/0/0/0", r.WorkflowVerified, r.Evaluated, r.Validated, r.Unevaluated)
	}
	if got := entry(r, "API-BAS-REPORT-X"); got.Status != WorkflowVerified || got.Reason == "" {
		t.Errorf("entry = %+v, want workflow_verified with a reason", got)
	}
	if !r.Consistent() {
		t.Errorf("classes do not sum to the catalogue: %+v", r)
	}
	if !strings.Contains(Format(r), "Workflow-verified (reporting obligations, simulated; not in Evaluated or Validated): 1") {
		t.Error("the report does not print the workflow-verified line")
	}
}

// Anything short of a PASS with control enforced in both builds stays unevaluated: skipped, failed, run in one build, or not a
// reporting scenario.
func TestWorkflowVerifiedRequiresPassEnforcedInBothBuilds(t *testing.T) {
	skipped := &grade.Outcome{Result: grade.SKIPPED, Exploitability: grade.ExploitNotApplicable, Control: grade.ControlInconclusive, Reason: "deadline_not_defined_by_provision"}
	failed := &grade.Outcome{Result: grade.FAIL, Exploitability: grade.ExploitNotApplicable, Control: grade.Failed}
	plain := contract.Scenario{ID: "API-BAS-REPORT-X"}
	cases := map[string]struct {
		s contract.Scenario
		v Verdicts
	}{
		"skipped":           {reportScenario(), Verdicts{Vulnerable: skipped, Fixed: skipped}},
		"failed":            {reportScenario(), Verdicts{Vulnerable: failed, Fixed: failed}},
		"fixed build only":  {reportScenario(), Verdicts{Fixed: enforcedPass()}},
		"not a report type": {plain, Verdicts{Vulnerable: enforcedPass(), Fixed: enforcedPass()}},
	}
	for name, c := range cases {
		r := Build([]contract.Scenario{c.s}, contract.ProtocolSupported, map[string]Verdicts{"API-BAS-REPORT-X": c.v})
		if r.WorkflowVerified != 0 {
			t.Errorf("%s was counted workflow-verified", name)
		}
		if !r.Consistent() {
			t.Errorf("%s: classes do not sum: %+v", name, r)
		}
	}
}
