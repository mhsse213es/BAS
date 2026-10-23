package property

import (
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// Flow properties need to know the application's state machine, which an
// OpenAPI description does not carry. The operator declares it as a Workflow
// on the TemplateCtx. Without a Workflow (or without the step a property
// needs) the flow properties return no templates.

// StepKind names the role an operation plays in a workflow.
type StepKind string

const (
	StepCreate    StepKind = "create"    // makes the object (informational: fixture objects already exist)
	StepAuthorize StepKind = "authorize" // approval by a second party
	StepExecute   StepKind = "execute"   // the consequential, final action
	StepModify    StepKind = "modify"    // changes the values the approval covered
	StepReverse   StepKind = "reverse"   // cancels or reverses the object
	StepRead      StepKind = "read"      // reads the object's status (a GET operation)
)

// WorkflowStep binds an operation id to a role in the flow.
type WorkflowStep struct {
	Op   string
	Kind StepKind
	// Role is the account role that performs the step ("" means any). For an
	// authorize step it also selects the approving account.
	Role string
	// Body optionally overrides the request body generated from the schema.
	Body string
}

// Workflow is an operator-declared description of one object lifecycle.
// Steps are listed in the valid order (for example create, authorize, modify,
// execute, reverse, read); every step operates on the fixture object, whose
// id fills the operation's path.
type Workflow struct {
	Name  string
	Steps []WorkflowStep
	// SuccessValues are response values that mean the object completed
	// successfully (for example a status word). P-STATE-2 uses them as
	// forbidden values on a reversed object. Each must be at least four
	// characters, as the contract requires for forbidden values.
	SuccessValues []string
}

func (w *Workflow) step(kind StepKind) (WorkflowStep, bool) {
	if w == nil {
		return WorkflowStep{}, false
	}
	for _, s := range w.Steps {
		if s.Kind == kind {
			return s, true
		}
	}
	return WorkflowStep{}, false
}

// isStep reports whether the context operation is the workflow step of kind.
func isStep(ctx TemplateCtx, kind StepKind) (WorkflowStep, bool) {
	s, ok := ctx.Workflow.step(kind)
	return s, ok && s.Op == ctx.Op.ID && supportedMethod(ctx.Op.Method)
}

func flowOp(op model.Operation) bool { return supportedMethod(op.Method) && op.Method != "GET" }

// stepCall renders a workflow step as a request on the fixture object.
func stepCall(ctx TemplateCtx, ws WorkflowStep, obj fixture.Object, variant int) (model.Operation, string, string, bool) {
	o, ok := opByID(ctx.Model, ws.Op)
	if !ok || !supportedMethod(o.Method) {
		return model.Operation{}, "", "", false
	}
	path, body := buildRequest(o, victimVals(o, obj), variant)
	if ws.Body != "" && (o.Method == "POST" || o.Method == "PATCH") {
		body = ws.Body
	}
	return o, path, body, true
}

// flowBaseline is the owner's read of the object: the declared read step if
// there is one, otherwise the best related GET operation.
func flowBaseline(ctx TemplateCtx, owner model.Account) (contract.Step, bool) {
	if rs, ok := ctx.Workflow.step(StepRead); ok {
		if o, found := opByID(ctx.Model, rs.Op); found && o.Method == "GET" {
			return baselineStep(ctx, o, owner, true)
		}
	}
	return baselineStep(ctx, ctx.Op, owner, false)
}

// approver picks the account that performs an authorize step as a co-actor:
// a different customer than the owner, with the step's role when it names one.
func approver(ctx TemplateCtx, owner model.Account, role string) (model.Account, bool) {
	for _, a := range sortedAccounts(ctx) {
		if a.CustomerID == owner.CustomerID || (role != "" && a.Role != role) {
			continue
		}
		return a, true
	}
	return model.Account{}, false
}

func flowTemplate(ctx TemplateCtx, prop, claim, desc string, p pair, steps []contract.Step, oracle OracleKind) Template {
	t := Template{
		Description:    desc,
		Steps:          steps,
		DeniedStatuses: deniedRule(),
		Params: map[string]string{
			"operation": ctx.Op.ID, "account": p.victim.Name, "object": p.obj.ID,
			"workflow": ctx.Workflow.Name,
		},
		Oracle: oracle,
	}
	return finish(ctx, t, p.obj, prop, claim)
}

// ---- P-AUTH-1 ----

type auth1 struct{ meta }

func (auth1) Applies(op model.Operation, _ model.Model) bool { return flowOp(op) }

// Templates: the owner performs the execute step without the approval the
// workflow requires. The oracle is a state change (the final state was
// reached without the step).
func (a auth1) Templates(ctx TemplateCtx) []Template {
	exec, ok := isStep(ctx, StepExecute)
	if _, hasAuth := ctx.Workflow.step(StepAuthorize); !ok || !hasAuth || !a.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	owners := ownersWithObject(ctx, exec.Role)
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	base, ok := flowBaseline(ctx, p.victim)
	if !ok {
		return nil
	}
	_, path, body, ok := stepCall(ctx, exec, p.obj, 0)
	if !ok {
		return nil
	}
	atk := mkStep("attack-skip-approval", "attack", p.victim.Name, ctx.Op.Method, path, body,
		"The action is refused until its required approval has been given.")
	return []Template{flowTemplate(ctx, a.id, "property_level",
		"Account "+p.victim.Name+" performs "+ctx.Op.ID+" without the required approval.", p,
		[]contract.Step{base, atk}, OracleStateChange)}
}

// ---- P-AUTH-2 ----

type auth2 struct{ meta }

func (auth2) Applies(op model.Operation, _ model.Model) bool { return flowOp(op) }

// Templates: a second party approves the object (co_actor setup), then the
// owner changes the values the approval covered. The change must be refused
// (or must void the approval). The oracle is a state change from the
// modification. An application that accepts the change and voids the approval
// is reported as a candidate too: the runner cannot see the approval flag, so
// the verifier decides whether that is intended (the "unconfirmed" state).
func (a auth2) Templates(ctx TemplateCtx) []Template {
	mod, ok := isStep(ctx, StepModify)
	auth, hasAuth := ctx.Workflow.step(StepAuthorize)
	if !ok || !hasAuth || !a.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	owners := ownersWithObject(ctx, mod.Role)
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	checker, ok := approver(ctx, p.victim, auth.Role)
	if !ok {
		return nil
	}
	base, ok := flowBaseline(ctx, p.victim)
	if !ok {
		return nil
	}
	_, apath, abody, ok := stepCall(ctx, auth, p.obj, 0)
	if !ok {
		return nil
	}
	_, mpath, mbody, ok := stepCall(ctx, mod, p.obj, 1)
	if !ok {
		return nil
	}
	approve := mkStep("setup-approval", "setup", checker.Name, methodOf(ctx, auth), apath, abody,
		"The approving party approves the object.")
	approve.CoActor = true
	atk := mkStep("attack-modify-after-approval", "attack", p.victim.Name, ctx.Op.Method, mpath, mbody,
		"Values covered by an approval cannot be changed afterwards without voiding the approval.")
	t := flowTemplate(ctx, a.id, "property_level",
		"Account "+p.victim.Name+" changes the values of an approved object through "+ctx.Op.ID+".", p,
		[]contract.Step{base, approve, atk}, OracleStateChange)
	t.Params["approver"] = checker.Name
	return []Template{t}
}

func methodOf(ctx TemplateCtx, ws WorkflowStep) string {
	o, _ := opByID(ctx.Model, ws.Op)
	return o.Method
}

// ---- P-MC-1 ----

type mc1 struct{ meta }

func (mc1) Applies(op model.Operation, _ model.Model) bool { return flowOp(op) }

// Templates: the account that owns (made) the object, and holds the approver
// role so that a role check cannot explain a refusal, tries to approve its
// own object. The oracle is a state change (self-approval accepted).
func (m mc1) Templates(ctx TemplateCtx) []Template {
	auth, ok := isStep(ctx, StepAuthorize)
	if !ok || !m.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	owners := ownersWithObject(ctx, auth.Role)
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	base, ok := flowBaseline(ctx, p.victim)
	if !ok {
		return nil
	}
	_, path, body, ok := stepCall(ctx, auth, p.obj, 0)
	if !ok {
		return nil
	}
	atk := mkStep("attack-self-approval", "attack", p.victim.Name, ctx.Op.Method, path, body,
		"The account that made an object cannot approve it.")
	return []Template{flowTemplate(ctx, m.id, "property_level",
		"Account "+p.victim.Name+" approves its own object through "+ctx.Op.ID+".", p,
		[]contract.Step{base, atk}, OracleStateChange)}
}

// ---- P-STATE-1 ----

type state1 struct{ meta }

func (state1) Applies(op model.Operation, _ model.Model) bool { return flowOp(op) }

// Templates: the owner reverses the object, then tries to execute it. A
// reversed object must not reach the executed state. Only workflows without
// an approval step are covered: with one, the execute step is refused for a
// missing approval whether or not the transition check exists, which would
// make a pass meaningless (P-AUTH-1 covers that case). If a setup step is
// unexpectedly refused the runner attributes the earlier state change to the
// attack, so the workflow declaration must match the application.
func (s state1) Templates(ctx TemplateCtx) []Template {
	exec, ok := isStep(ctx, StepExecute)
	rev, hasRev := ctx.Workflow.step(StepReverse)
	if _, hasAuth := ctx.Workflow.step(StepAuthorize); !ok || !hasRev || hasAuth || !s.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	owners := ownersWithObject(ctx, exec.Role)
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	base, ok := flowBaseline(ctx, p.victim)
	if !ok {
		return nil
	}
	_, rpath, rbody, ok := stepCall(ctx, rev, p.obj, 0)
	if !ok {
		return nil
	}
	_, epath, ebody, ok := stepCall(ctx, exec, p.obj, 0)
	if !ok {
		return nil
	}
	reverse := mkStep("setup-reverse", "setup", p.victim.Name, methodOf(ctx, rev), rpath, rbody, "The owner reverses the object.")
	atk := mkStep("attack-execute-reversed", "attack", p.victim.Name, ctx.Op.Method, epath, ebody,
		"A reversed object cannot be executed.")
	return []Template{flowTemplate(ctx, s.id, "property_level",
		"Account "+p.victim.Name+" executes an object after reversing it, through "+ctx.Op.ID+".", p,
		[]contract.Step{base, reverse, atk}, OracleStateChange)}
}

// ---- P-STATE-2 ----

type state2 struct{ meta }

func (state2) Applies(op model.Operation, _ model.Model) bool { return flowOp(op) }

// Templates: the owner reverses the object and then reads its status. The
// read must not report any of Workflow.SuccessValues. A 2xx read with none of
// them is the correct outcome, so CleanIsEnforced is set.
//
// The declared read operation should be a status view that does not echo the
// object's free-text fields: the runner counts any protected value (the
// fixture canary) in an attack response as a leak, even to the owner, which
// would grade the run FAIL regardless of the status reported.
func (s state2) Templates(ctx TemplateCtx) []Template {
	rev, ok := isStep(ctx, StepReverse)
	read, hasRead := ctx.Workflow.step(StepRead)
	if !ok || !hasRead || !s.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	var forbidden []string
	for _, v := range ctx.Workflow.SuccessValues {
		if len(v) >= 4 {
			forbidden = append(forbidden, v)
		}
	}
	readOp, found := opByID(ctx.Model, read.Op)
	if len(forbidden) == 0 || !found || readOp.Method != "GET" {
		return nil
	}
	owners := ownersWithObject(ctx, rev.Role)
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	base, ok := flowBaseline(ctx, p.victim)
	if !ok {
		return nil
	}
	_, rpath, rbody, ok := stepCall(ctx, rev, p.obj, 0)
	if !ok {
		return nil
	}
	_, spath, _, ok := stepCall(ctx, read, p.obj, 0)
	if !ok {
		return nil
	}
	reverse := mkStep("setup-reverse", "setup", p.victim.Name, ctx.Op.Method, rpath, rbody, "The owner reverses the object.")
	atk := mkStep("attack-read-status", "attack", p.victim.Name, "GET", spath, "",
		"The status of a reversed object never reports success.")
	t := flowTemplate(ctx, s.id, "property_level",
		"The status read after reversing an object through "+ctx.Op.ID+" never reports success.", p,
		[]contract.Step{base, reverse, atk}, OracleForbiddenValues)
	t.ForbiddenValues = forbidden
	t.CleanIsEnforced = true
	return []Template{t}
}
