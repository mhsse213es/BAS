package property

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
)

func withWorkflow(w *Workflow) func(*TemplateCtx) {
	return func(c *TemplateCtx) { c.Workflow = w }
}

func noAuthWorkflow() *Workflow {
	w := toyWorkflow()
	var steps []WorkflowStep
	for _, s := range w.Steps {
		if s.Kind != StepAuthorize {
			steps = append(steps, s)
		}
	}
	w.Steps = steps
	return w
}

func TestFlowTemplatesDetectToyPostApprovalTamper(t *testing.T) {
	// P-AUTH-2: the owner changes the terms of an already approved object.
	tpls := templatesFor(t, "P-AUTH-2", "terms", withWorkflow(toyWorkflow()))
	if len(tpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tpls))
	}
	s := tpls[0].Steps
	if len(s) != 3 || !s[1].CoActor || s[1].Identity != "carol" || s[2].Identity != "alice" {
		t.Fatalf("approval must be a co_actor step by a different account: %+v", s)
	}
	ty, srv := newToy("tamper")
	defer srv.Close()
	expect(t, ty, srv, tpls, grade.FAIL)
	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)

	// P-AUTH-1: the final action without its approval.
	exec := templatesFor(t, "P-AUTH-1", "execute", withWorkflow(toyWorkflow()))
	if len(exec) != 1 {
		t.Fatalf("want 1 template, got %d", len(exec))
	}
	ty2, srv2 := newToy("noauth")
	defer srv2.Close()
	expect(t, ty2, srv2, exec, grade.FAIL)
	expect(t, ok, srvOK, exec, grade.PASS)
}

func TestMakerCheckerDetectsToySelfApproval(t *testing.T) {
	tpls := templatesFor(t, "P-MC-1", "authorize", withWorkflow(toyWorkflow()))
	if len(tpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tpls))
	}
	// The maker must hold the approver role, so a role check cannot explain a refusal.
	if tpls[0].Params["account"] != "carol" {
		t.Fatalf("maker must be an approver-role account, got %s", tpls[0].Params["account"])
	}
	ty, srv := newToy("selfapprove")
	defer srv.Close()
	expect(t, ty, srv, tpls, grade.FAIL)
	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)
}

func TestStateTemplatesDetectToyInvalidTransitionAndFalseSuccess(t *testing.T) {
	// P-STATE-1: execute after reverse (workflow without an approval step).
	tpls := templatesFor(t, "P-STATE-1", "execute", withWorkflow(noAuthWorkflow()))
	if len(tpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tpls))
	}
	ty, srv := newToy("revive")
	defer srv.Close()
	expect(t, ty, srv, tpls, grade.FAIL)
	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)
	// With an approval step the template would be vacuous, so none is emitted.
	if got := templatesFor(t, "P-STATE-1", "execute", withWorkflow(toyWorkflow())); len(got) != 0 {
		t.Fatal("P-STATE-1 must not emit a vacuous template when execute needs an approval")
	}

	// P-STATE-2: a reversed object reported as successful.
	st := templatesFor(t, "P-STATE-2", "reverse", withWorkflow(toyWorkflow()))
	if len(st) != 1 || len(st[0].ForbiddenValues) != 1 || !st[0].CleanIsEnforced {
		t.Fatalf("bad P-STATE-2 template: %+v", st)
	}
	ty2, srv2 := newToy("status-lie")
	defer srv2.Close()
	expect(t, ty2, srv2, st, grade.FAIL)
	expect(t, ok, srvOK, st, grade.PASS)
}

func TestFlowPropertiesNeedAWorkflow(t *testing.T) {
	for _, c := range []struct{ prop, op string }{
		{"P-AUTH-1", "execute"}, {"P-AUTH-2", "terms"}, {"P-MC-1", "authorize"}, {"P-STATE-1", "execute"}, {"P-STATE-2", "reverse"},
	} {
		if got := templatesFor(t, c.prop, c.op, nil); len(got) != 0 {
			t.Errorf("%s without a workflow must emit nothing, got %d", c.prop, len(got))
		}
		// A workflow that does not name this operation for the step also emits nothing.
		if got := templatesFor(t, c.prop, "getV2", withWorkflow(toyWorkflow())); len(got) != 0 {
			t.Errorf("%s on an unrelated operation must emit nothing", c.prop)
		}
	}
	// No second party available for the approval: no P-AUTH-2 template.
	only := func(c *TemplateCtx) {
		c.Workflow = toyWorkflow()
		c.Identities = c.Identities[:2] // alice, bob: neither is a checker
	}
	if got := templatesFor(t, "P-AUTH-2", "terms", only); len(got) != 0 {
		t.Fatal("no approver account: P-AUTH-2 must emit nothing")
	}
	// STATE-2 needs success values.
	noVals := func(c *TemplateCtx) { w := toyWorkflow(); w.SuccessValues = nil; c.Workflow = w }
	if got := templatesFor(t, "P-STATE-2", "reverse", noVals); len(got) != 0 {
		t.Fatal("P-STATE-2 without success values must emit nothing")
	}
}
