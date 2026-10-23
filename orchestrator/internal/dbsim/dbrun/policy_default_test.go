package dbrun

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
)

// Ruling R-AK: Evaluate forces the policy-diff requirement for read_grants no
// matter what the caller put in ScenarioMeta.
func TestPipeline_FakeAgentFakeConnector_ReadGrantsRequirementIsForced(t *testing.T) {
	for _, flag := range []bool{false, true} {
		in := input("dbsim-db02-excessive-grants", "read_grants", okExec(4))
		in.Scenario.RequirePolicyDiff = flag
		in.Scenario.RequireObservation = false
		in.Scenario.ExpectDetection, in.Scenario.ExpectResponse = false, false
		ev := mustEval(t, nil, in)
		if ev.Result != dbsim.ResultError || ev.Report.Dimensions.Policy != dbsim.DimUnverifiable {
			t.Fatalf("flag=%v: %s / %s", flag, ev.Result, ev.Report.Dimensions.Policy)
		}
		if !strings.Contains(ev.Record.Limitations, "policy diff not performed; grants were observable (4)") {
			t.Fatalf("flag=%v limitations %q", flag, ev.Record.Limitations)
		}
	}
	in := input("dbsim-db02-excessive-grants", "read_grants", okExec(4))
	in.Scenario.RequirePolicyDiff = false
	in.Scenario.ExpectDetection, in.Scenario.ExpectResponse = false, false
	in.Diff = &dbsim.DiffReport{PolicySource: "lab", GrantsChecked: 4, Deviations: []dbsim.Deviation{}}
	if ev := mustEval(t, nil, in); ev.Result != dbsim.ResultPass {
		t.Fatalf("clean diff: %s", ev.Result)
	}
	in.Diff = &dbsim.DiffReport{PolicySource: "lab", GrantsChecked: 4, Deviations: []dbsim.Deviation{{Kind: dbsim.DeviationExcessive, Role: "r", Object: "o", Privilege: "SELECT", PolicySource: "lab"}}}
	if ev := mustEval(t, nil, in); ev.Result != dbsim.ResultFail {
		t.Fatalf("deviating diff: %s", ev.Result)
	}
	// other probes unaffected
	in2 := input("dbsim-db01-auth-policy", "read_roles", okExec(4))
	in2.Scenario.ExpectDetection, in2.Scenario.ExpectResponse = false, false
	if ev := mustEval(t, nil, in2); ev.Result != dbsim.ResultPass {
		t.Fatalf("read_roles: %s", ev.Result)
	}
}
