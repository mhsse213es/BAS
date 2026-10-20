package coverage

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
)

func loadCatalog(t *testing.T) []contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	return all
}

func byID(all []contract.Scenario, id string) contract.Scenario {
	for _, s := range all {
		if s.ID == id {
			return s
		}
	}
	return contract.Scenario{}
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

// Unsupported scenarios count toward the catalog size and nothing else.
func TestUnsupportedCountsOnlyInCatalogue(t *testing.T) {
	all := loadCatalog(t)
	r := Build(all, contract.ProtocolSupported, nil)
	if r.Catalogued != len(all) {
		t.Fatalf("catalogued = %d, want %d", r.Catalogued, len(all))
	}
	if r.Unsupported < 4 {
		t.Fatalf("unsupported = %d, want at least the 5 protocol entries without an adapter", r.Unsupported)
	}
	if r.Evaluated != 0 || r.Validated != 0 {
		t.Fatalf("no results were supplied, but evaluated=%d validated=%d", r.Evaluated, r.Validated)
	}
	if !r.Consistent() {
		t.Fatalf("classes do not sum to the catalog size: %+v", r)
	}
	if got := entry(r, "API-BAS-DISC-009"); got.Status != Unsupported || got.Reason != grade.ReasonUnsupportedProtocol {
		t.Fatalf("gRPC entry = %+v, want unsupported with UNSUPPORTED_PROTOCOL", got)
	}
}

// Unsupported is not inflated by results: a valid verdict on an unsupported protocol is ignored.
func TestUnsupportedIgnoresResults(t *testing.T) {
	all := loadCatalog(t)
	results := map[string]Verdicts{
		"API-BAS-DISC-009": {Vulnerable: ptr(validFail()), Fixed: ptr(validPass())},
	}
	r := Build(all, contract.ProtocolSupported, results)
	if got := entry(r, "API-BAS-DISC-009"); got.Status != Unsupported {
		t.Fatalf("unsupported scenario with results = %s, want unsupported", got.Status)
	}
}

// Coverage increases only after a valid evaluation: an adapter that exists but has no verdict
// makes the scenario implemented and unevaluated, not evaluated.
func TestAdapterLaterIncreasesCoverageOnlyAfterValidEvaluation(t *testing.T) {
	all := loadCatalog(t)
	// The "later" adapter is gRPC: the test adds it to the supported set and nothing else.
	withGRPC := func(p string) bool { return contract.ProtocolSupported(p) || p == "grpc" }

	before := Build(all, contract.ProtocolSupported, nil)
	after := Build(all, withGRPC, nil)
	if after.Implemented <= before.Implemented {
		t.Fatalf("implemented did not rise when the GraphQL adapter was added: %d -> %d", before.Implemented, after.Implemented)
	}
	if after.Evaluated != before.Evaluated {
		t.Fatalf("evaluated rose without any verdict: %d -> %d", before.Evaluated, after.Evaluated)
	}
	if got := entry(after, "API-BAS-DISC-009"); got.Status != Unevaluated {
		t.Fatalf("implemented gRPC scenario with no verdict = %s, want unevaluated", got.Status)
	}

	withVerdict := Build(all, withGRPC, map[string]Verdicts{
		"API-BAS-DISC-009": {Vulnerable: ptr(validFail()), Fixed: ptr(validPass())},
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
	r := Build(all, contract.ProtocolSupported, nil)
	out := Format(r)
	for _, want := range []string{"Evaluated:", "/", "unsupported (no adapter)", "API-BAS-INJ-007", "UNSUPPORTED_PROTOCOL"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func ptr(o grade.Outcome) *grade.Outcome { return &o }
