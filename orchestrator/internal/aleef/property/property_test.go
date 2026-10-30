package property

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nonTestSources returns the source of every non-test .go file in the package.
func nonTestSources() (map[string]string, error) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out[f] = string(b)
	}
	return out, nil
}

func TestNoPropertyNamesBankResources(t *testing.T) {
	banned := []string{"beneficiary", "kyc", "settle", "ledger", "account number", "ifsc", "upi", "labels.json"}
	files, err := nonTestSources()
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		low := strings.ToLower(src)
		for _, w := range banned {
			if strings.Contains(low, w) {
				t.Errorf("%s mentions %q", name, w)
			}
		}
	}
}

func TestAllListsPropertiesInSpecOrder(t *testing.T) {
	want := []string{"P-OWN-1", "P-OWN-2", "P-OWN-3", "P-ROLE-1", "P-ROLE-2", "P-AUTH-1", "P-AUTH-2", "P-MC-1",
		"P-IDEM-1", "P-IDEM-2", "P-STATE-1", "P-STATE-2", "P-RACE-1"}
	var got []string
	for _, p := range All() {
		got = append(got, p.ID())
		if p.Class() == "" {
			t.Errorf("%s has no class", p.ID())
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

// sweep generates templates from every property for every toy operation,
// under a workflow with and without an approval step.
func sweep(t *testing.T) map[string][]Template {
	t.Helper()
	out := map[string][]Template{}
	for _, wf := range []*Workflow{toyWorkflow(), noAuthWorkflow()} {
		for _, o := range toyModel().Operations {
			ctx := toyCtx(t, o.ID)
			ctx.Workflow = wf
			ctx.ReservedRoles = map[string]string{"archive": "admin", "reports": "admin"}
			for _, p := range All() {
				out[p.ID()] = append(out[p.ID()], p.Templates(ctx)...)
			}
		}
	}
	return out
}

func TestEveryTemplateNamesItsOracle(t *testing.T) {
	for id, tpls := range sweep(t) {
		if len(tpls) == 0 {
			t.Errorf("%s produced no template in the sweep", id)
		}
		for _, tp := range tpls {
			if tp.Oracle == "" {
				t.Errorf("%s template %q has no Oracle", id, tp.Description)
			}
			if _, stale := tp.Params["oracle"]; stale {
				t.Errorf("%s still carries Params[oracle]", id)
			}
		}
	}
}

func TestOracleKindPerProperty(t *testing.T) {
	want := map[string][]OracleKind{
		"P-OWN-1": {OracleRunnerGrade}, "P-OWN-2": {OracleRunnerGrade}, "P-OWN-3": {OracleRunnerGrade},
		"P-ROLE-1": {OracleStateChange, OracleRepeatAccepted}, "P-ROLE-2": {OracleRunnerGrade},
		"P-AUTH-1": {OracleStateChange}, "P-AUTH-2": {OracleStateChange}, "P-MC-1": {OracleStateChange},
		"P-IDEM-1": {OracleStateChangeOnReplay}, "P-IDEM-2": {OracleStateChangeOnReplay},
		"P-STATE-1": {OracleStateChange}, "P-STATE-2": {OracleForbiddenValues},
		"P-RACE-1": {OracleAcceptedOverLimit},
	}
	for id, tpls := range sweep(t) {
		for _, tp := range tpls {
			ok := false
			for _, k := range want[id] {
				ok = ok || tp.Oracle == k
			}
			if !ok {
				t.Errorf("%s has oracle %q, want one of %v", id, tp.Oracle, want[id])
			}
			// A read reserved for a role is decided by repeated acceptance, a write by state.
			if id == "P-ROLE-1" {
				last := tp.Steps[len(tp.Steps)-1]
				if (last.Method == "GET") != (tp.Oracle == OracleRepeatAccepted) {
					t.Errorf("P-ROLE-1 %s %s has oracle %s", last.Method, last.Path, tp.Oracle)
				}
			}
		}
	}
}

func TestRunnerSignalValidity(t *testing.T) {
	for id, tpls := range sweep(t) {
		for _, tp := range tpls {
			ownerActing := tp.Claim != "cross_identity"
			if ownerActing && tp.RunnerLeakValid {
				t.Errorf("%s owner-acting template must have RunnerLeakValid false", id)
			}
			if !ownerActing && !tp.RunnerLeakValid {
				t.Errorf("%s cross-identity template must trust the runner leak signal", id)
			}
			if wantState := id != "P-RACE-1"; tp.RunnerStateValid != wantState {
				t.Errorf("%s RunnerStateValid = %v, want %v", id, tp.RunnerStateValid, wantState)
			}
		}
	}
}
