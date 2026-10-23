package property

import (
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// GradedSuccess reports whether every response is a real success: 2xx and not
// a soft failure. An empty list is not a success.
func GradedSuccess(rs []Response) bool {
	if len(rs) == 0 {
		return false
	}
	for _, r := range rs {
		if r.Status < 200 || r.Status > 299 || IsSoftFailure(r.Status, r.Body) {
			return false
		}
	}
	return true
}

// newControl builds a control template. kind is "owner" or "negative".
func newControl(ctx TemplateCtx, base Template, kind, desc, claim string, obj fixture.Object, steps []contract.Step, forbidden []string) *Template {
	c := Template{
		Property:        base.Property,
		Description:     desc,
		Steps:           steps,
		DeniedStatuses:  deniedRule(),
		ForbiddenValues: forbidden,
		Oracle:          OracleForbiddenValues,
		CleanIsEnforced: true,
		ExpectSuccess:   true,
		Params:          map[string]string{"control": kind, "operation": ctx.Op.ID, "object": obj.ID},
	}
	c = finish(ctx, c, obj, base.Property, claim)
	c.RunnerLeakValid, c.RunnerStateValid = false, false
	return &c
}

// withControls attaches both controls; a template missing one is dropped.
func withControls(t Template, owner, negative *Template) ([]Template, bool) {
	if owner == nil || negative == nil {
		return nil, false
	}
	t.OwnerControl, t.NegativeControl = owner, negative
	return []Template{t}, true
}

// protectedValues lists an object's protected values long enough to be
// forbidden values.
func protectedValues(o fixture.Object) []string {
	var out []string
	for _, k := range sortedKeys(o.Protected) {
		if v := o.Protected[k]; len(v) >= 4 {
			out = append(out, v)
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// actStep is the control's graded request: op called by acct on obj. A DELETE
// is replaced by the owner's read, so a control never destroys the fixture.
func actStep(ctx TemplateCtx, op model.Operation, acct model.Account, obj fixture.Object, id, hypothesis string) (contract.Step, bool) {
	if op.Method == "DELETE" {
		b, ok := baselineStep(ctx, op, acct, false)
		if !ok {
			return contract.Step{}, false
		}
		b.ID, b.Role, b.Hypothesis = id, "attack", hypothesis
		return b, true
	}
	path, body := buildRequest(op, victimVals(op, obj), 0)
	return mkStep(id, "attack", acct.Name, op.Method, path, body, hypothesis), true
}

// actControl builds a baseline + one request control in which acct acts on
// its own object obj.
func actControl(ctx TemplateCtx, base Template, op model.Operation, kind, desc string, acct model.Account, obj fixture.Object, forbidden []string, selfBaseline bool) *Template {
	var b contract.Step
	ok := false
	if selfBaseline {
		b, ok = baselineOrSelf(ctx, op, acct, obj)
	} else {
		b, ok = baselineStep(ctx, op, acct, false)
	}
	if !ok {
		return nil
	}
	a, ok := actStep(ctx, op, acct, obj, "control-"+kind, "The legitimate request succeeds.")
	if !ok {
		return nil
	}
	return newControl(ctx, base, kind, desc, "property_level", obj, []contract.Step{b, a}, forbidden)
}
