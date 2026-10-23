package property

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/runner"
)

func TestEveryTemplateCarriesBothControls(t *testing.T) {
	sw := sweep(t)
	for _, p := range All() {
		tpls := sw[p.ID()]
		if len(tpls) == 0 {
			t.Errorf("%s: no templates in the sweep, controls untested", p.ID())
		}
		for _, tp := range tpls {
			for kind, c := range map[string]*Template{"owner": tp.OwnerControl, "negative": tp.NegativeControl} {
				if c == nil {
					t.Errorf("%s %q: missing %s control", p.ID(), tp.Description, kind)
					continue
				}
				if c.OwnerControl != nil || c.NegativeControl != nil {
					t.Errorf("%s: a control must not carry controls", p.ID())
				}
				if !c.ExpectSuccess || c.Oracle != OracleForbiddenValues || !c.CleanIsEnforced {
					t.Errorf("%s %s control: ExpectSuccess=%v oracle=%s clean=%v", p.ID(), kind, c.ExpectSuccess, c.Oracle, c.CleanIsEnforced)
				}
				if c.Params["control"] != kind || c.Property != tp.Property {
					t.Errorf("%s %s control: bad params/property %v %s", p.ID(), kind, c.Params, c.Property)
				}
				if c.RunnerLeakValid || c.RunnerStateValid {
					t.Errorf("%s %s control must ignore the runner's leak and state signals", p.ID(), kind)
				}
				toScenario(t, *c, "BIZ") // must validate as a scenario
			}
		}
	}
}

// finalResponses returns the responses to the control's final step.
func finalResponses(tpl Template, rep runner.Report) []Response {
	last := tpl.Steps[len(tpl.Steps)-1].ID
	var rs []Response
	for _, e := range rep.Exchanges[1:] {
		if e.StepID == last {
			rs = append(rs, Response{Status: e.Status, Body: []byte(e.Body)})
		}
	}
	return rs
}

// controlCase names one (property, operation) the toy serves with a
// legitimate owner action. Other operations of the toy are role-restricted or
// not idempotent by design, so their owner controls legitimately fail there.
type controlCase struct{ prop, op string }

var controlCases = []controlCase{
	{"P-OWN-1", "getV2"}, {"P-OWN-2", "patchV2"}, {"P-OWN-2", "deleteV2"},
	{"P-OWN-3", "listQ"}, {"P-OWN-3", "move"}, {"P-OWN-3", "getV2"}, {"P-OWN-3", "patchV2"},
	{"P-ROLE-1", "archive"}, {"P-ROLE-1", "reports"}, {"P-ROLE-2", "getV1"}, {"P-ROLE-2", "getV2"},
	{"P-AUTH-1", "execute"}, {"P-AUTH-2", "terms"}, {"P-MC-1", "authorize"},
	{"P-IDEM-1", "invoice"}, {"P-IDEM-2", "invoice"},
	{"P-STATE-1", "execute"}, {"P-STATE-2", "reverse"}, {"P-RACE-1", "redeem"},
}

func caseCtx(c controlCase) func(*TemplateCtx) {
	return func(x *TemplateCtx) {
		x.Workflow = toyWorkflow()
		if c.prop == "P-STATE-1" {
			x.Workflow = noAuthWorkflow()
		}
		x.ReservedRoles = map[string]string{"archive": "admin", "reports": "admin"}
	}
}

func TestControlsSucceedOnTheCorrectedToy(t *testing.T) {
	ty, srv := newToy("openexec") // execute is allowed from pending in this app
	defer srv.Close()
	for _, c := range controlCases {
		tpls := templatesFor(t, c.prop, c.op, caseCtx(c))
		if len(tpls) == 0 {
			t.Errorf("%s on %s: no templates", c.prop, c.op)
		}
		for _, tp := range tpls {
			for _, ctl := range []*Template{tp.OwnerControl, tp.NegativeControl} {
				rep := run(t, ty, srv, *ctl)
				if !GradedSuccess(finalResponses(*ctl, rep)) {
					var ex []string
					for _, e := range rep.Exchanges {
						ex = append(ex, e.Method+" "+e.Path+" -> "+strings.TrimSpace(e.Body))
					}
					t.Errorf("%s/%s %s control: graded exchange is not a success: %v", c.prop, c.op, ctl.Params["control"], ex)
				}
			}
		}
	}
}

func TestGradedSuccess(t *testing.T) {
	ok := Response{Status: 200, Body: []byte(`{"id":"1"}`)}
	if !GradedSuccess([]Response{ok, {Status: 201, Body: []byte(`{}`)}}) {
		t.Fatal("2xx must be a success")
	}
	for _, bad := range [][]Response{nil, {{Status: 403}}, {ok, {Status: 200, Body: []byte(`{"error":"x"}`)}}, {{Status: 500}}} {
		if GradedSuccess(bad) {
			t.Fatalf("%v must not be a success", bad)
		}
	}
}
