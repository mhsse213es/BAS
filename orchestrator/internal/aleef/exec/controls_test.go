package exec

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/contract"
)

func noApprovalWorkflow() *property.Workflow {
	w := toyWorkflow()
	var steps []property.WorkflowStep
	for _, s := range w.Steps {
		if s.Kind != property.StepAuthorize {
			steps = append(steps, s)
		}
	}
	w.Steps = steps
	return w
}

func generatedFor(t *testing.T, wf *property.Workflow, prop, opID string) generate.Test {
	t.Helper()
	tests, err := generate.Generate(toyModel(), toyFixture(), toyAccounts(), generate.Options{
		Seed: 1, Catalogue: []contract.Scenario{}, Workflow: wf,
		ReservedRoles: map[string]string{"reports": "admin", "archive": "admin"},
		Limits:        map[string]int{"redeem": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range tests {
		if x.Property == prop && x.Params["operation"] == opID {
			return x
		}
	}
	t.Fatalf("no generated test %s on %s", prop, opID)
	return generate.Test{}
}

// finalResponses are the responses to the last step of a test.
func finalResponses(x generate.Test, res Result) []property.Response {
	last := x.Scenario.Steps[len(x.Scenario.Steps)-1].ID
	var rs []property.Response
	for _, e := range res.Report.Exchanges[1:] {
		if e.StepID == last {
			rs = append(rs, property.Response{Status: e.Status, Body: []byte(e.Body)})
		}
	}
	return rs
}

type controlRow struct {
	prop, op string
	wf       func() *property.Workflow
	flawed   []string // flaws that make the application vulnerable
	base     []string // flaws that only configure the toy and keep it correct
}

func TestControlsPassOnCorrectedAndFlawedApplications(t *testing.T) {
	rows := []controlRow{
		{prop: "P-OWN-1", op: "getV2", flawed: []string{"read-v2"}},
		{prop: "P-OWN-2", op: "patchV2", flawed: []string{"write"}},
		{prop: "P-OWN-3", op: "move", flawed: []string{"body"}},
		{prop: "P-OWN-3", op: "listQ", flawed: []string{"query"}},
		{prop: "P-ROLE-1", op: "archive", flawed: []string{"role"}},
		{prop: "P-ROLE-1", op: "reports", flawed: []string{"role"}},
		{prop: "P-ROLE-2", op: "getV1", flawed: []string{"read-v1"}},
		{prop: "P-AUTH-1", op: "execute", flawed: []string{"noauth"}},
		{prop: "P-AUTH-2", op: "terms", flawed: []string{"tamper"}},
		{prop: "P-MC-1", op: "authorize", flawed: []string{"selfapprove"}},
		{prop: "P-IDEM-1", op: "invoice", flawed: []string{"idem-ignore"}},
		{prop: "P-IDEM-2", op: "invoice", flawed: []string{"idem-nobody"}},
		{prop: "P-STATE-1", op: "execute", wf: noApprovalWorkflow, flawed: []string{"revive"}, base: []string{"openexec"}},
		{prop: "P-STATE-2", op: "reverse", flawed: []string{"status-lie"}},
		{prop: "P-RACE-1", op: "redeem", flawed: []string{"race"}},
	}
	for _, r := range rows {
		r := r
		t.Run(r.prop+"/"+r.op, func(t *testing.T) {
			wf := toyWorkflow
			if r.wf != nil {
				wf = r.wf
			}
			x := generatedFor(t, wf(), r.prop, r.op)
			if x.OwnerControl == nil || x.NegativeControl == nil || x.ControlsBlocked {
				t.Fatal("generated test has no controls")
			}
			for _, side := range []struct {
				name  string
				flaws []string
				want  Finding
			}{
				{"corrected", r.base, FindingNo},
				{"flawed", append(append([]string{}, r.base...), r.flawed...), FindingYes},
			} {
				ty, srv := newToy(side.flaws...)
				ty.hideRedeem = true // a state adapter that omits the permitted once-only effect
				res := runTest(t, ty, srv, x)
				if res.Verdict.Finding != side.want {
					t.Errorf("%s: test verdict %s (%s), want %s", side.name, res.Verdict.Finding, res.Verdict.Reason, side.want)
				}
				for _, c := range []*generate.Test{x.OwnerControl, x.NegativeControl} {
					cr := runTest(t, ty, srv, *c)
					if cr.Verdict.Finding != FindingNo {
						t.Errorf("%s: %s verdict %s (%s), want no", side.name, c.ID, cr.Verdict.Finding, cr.Verdict.Reason)
					}
					if !property.GradedSuccess(finalResponses(*c, cr)) {
						var ex []string
						for _, e := range cr.Report.Exchanges {
							ex = append(ex, e.Method+" "+e.Path+" -> "+e.Body)
						}
						t.Errorf("%s: %s graded exchange is not a success: %s", side.name, c.ID, strings.Join(ex, " | "))
					}
				}
				srv.Close()
			}
		})
	}
	_ = context.Background
	_ = httptest.NewServer
}
