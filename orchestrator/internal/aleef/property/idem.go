package property

import (
	"strconv"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
)

// Idempotency and concurrency properties.

// IdempotencyHeader is the request header carrying the idempotency key.
const IdempotencyHeader = "Idempotency-Key"

// creatingOp reports whether an operation is a candidate for idempotency
// testing: a POST that is classified (not read, not unknown).
func creatingOp(op model.Operation) bool {
	return op.Method == "POST" && op.Class != model.ClassRead && op.Class != model.ClassUnknown && op.Class != ""
}

// idemTemplate builds the replay chain: the owner reads the object
// (baseline), sends the request with a key (setup, expected to succeed), then
// sends it again with the same key (attack) and, for P-IDEM-2, a different
// body. The oracle is the state diff taken just before the attack: a second
// processing creates or changes a record. A replay that returns the stored
// response without side effects is correct, so a 2xx with no state change is
// enforcement (CleanIsEnforced).
//
// The runner cannot count records, only detect that the snapshot changed, so
// "count of resulting records > 1" is expressed as "the replay changed the
// snapshot". The key is a fixed string: the lab must be reset between runs
// (these templates are STATE_CHANGE_SANDBOX).
func idemTemplate(ctx TemplateCtx, prop string, variant int, desc string) []Template {
	op := ctx.Op
	if !creatingOp(op) {
		return nil
	}
	owners := ownersWithObject(ctx, "")
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	base, ok := baselineStep(ctx, op, p.victim, false)
	if !ok {
		return nil
	}
	vals := victimVals(op, p.obj)
	path, body1 := buildRequest(op, vals, 0)
	_, body2 := buildRequest(op, vals, variant)
	if variant > 0 && body1 == body2 {
		return nil // nothing to vary: the body has no field a second request could change
	}
	key := "aleef-" + prop[2:]
	first := mkStep("setup-first-request", "setup", p.victim.Name, op.Method, path, body1,
		"The first request with the key is processed once.")
	first.Headers = map[string]string{IdempotencyHeader: key}
	replay := mkStep("attack-replay", "attack", p.victim.Name, op.Method, path, body2,
		"A second request with the same key does not process again.")
	replay.Headers = map[string]string{IdempotencyHeader: key}
	t := Template{
		Description:     desc,
		Steps:           []contract.Step{base, first, replay},
		DeniedStatuses:  deniedRule(),
		CleanIsEnforced: true,
		Oracle:          OracleStateChangeOnReplay,
		Params: map[string]string{
			"operation": op.ID, "account": p.victim.Name, "object": p.obj.ID,
			"header": IdempotencyHeader,
		},
	}
	return []Template{finish(ctx, t, p.obj, prop, "property_level")}
}

// ---- P-IDEM-1 ----

type idem1 struct{ meta }

func (idem1) Applies(op model.Operation, _ model.Model) bool { return creatingOp(op) }

// Templates: the same request is sent twice with the same key.
func (i idem1) Templates(ctx TemplateCtx) []Template {
	return idemTemplate(ctx, i.id, 0, "Repeating "+ctx.Op.ID+" with the same idempotency key is processed once.")
}

// ---- P-IDEM-2 ----

type idem2 struct{ meta }

func (idem2) Applies(op model.Operation, _ model.Model) bool { return creatingOp(op) }

// Templates: the second request reuses the key with a different body. It
// must be refused (or answered with the first response), never processed.
func (i idem2) Templates(ctx TemplateCtx) []Template {
	return idemTemplate(ctx, i.id, 1, "Reusing an idempotency key on "+ctx.Op.ID+" with a different body is refused.")
}

// ---- P-RACE-1 ----

type race1 struct{ meta }

// raceLimit returns the number of concurrent successes an operation may
// legitimately have. Operations classified money or notifying default to one
// (a once-only action); other classes need an operator-declared limit.
func raceLimit(ctx TemplateCtx) (int, bool) {
	if n, ok := ctx.Limits[ctx.Op.ID]; ok && n >= 1 {
		return n, true
	}
	switch ctx.Op.Class {
	case model.ClassMoney, model.ClassNotifying:
		return 1, true
	}
	return 0, false
}

func (race1) Applies(op model.Operation, _ model.Model) bool {
	if !supportedMethod(op.Method) || op.Method == "GET" {
		return false
	}
	switch op.Class {
	case model.ClassMoney, model.ClassNotifying, model.ClassReversible:
		return true
	}
	return false
}

// Templates: the owner sends limit+4 identical requests in parallel;
// MaxAccepted is the limit, so more accepted responses than the limit is a
// finding. Operations that may legitimately succeed repeatedly need a
// declared limit; reversible operations without one produce nothing.
func (r race1) Templates(ctx TemplateCtx) []Template {
	op := ctx.Op
	if !r.Applies(op, ctx.Model) {
		return nil
	}
	limit, ok := raceLimit(ctx)
	if !ok {
		return nil
	}
	owners := ownersWithObject(ctx, "")
	if len(owners) == 0 {
		return nil
	}
	p := owners[0]
	base, ok := baselineStep(ctx, op, p.victim, false)
	if !ok {
		return nil
	}
	path, body := buildRequest(op, victimVals(op, p.obj), 0)
	atk := mkStep("attack-parallel", "attack", p.victim.Name, op.Method, path, body,
		"At most "+strconv.Itoa(limit)+" of the concurrent identical requests succeed.")
	atk.Repeat = limit + 4
	atk.Parallel = true
	t := Template{
		Description:    "Parallel identical requests to " + op.ID + " cannot exceed the limit of " + strconv.Itoa(limit) + ".",
		Steps:          []contract.Step{base, atk},
		MaxAccepted:    limit,
		DeniedStatuses: deniedRule(),
		Params: map[string]string{
			"operation": op.ID, "account": p.victim.Name, "object": p.obj.ID,
			"limit": strconv.Itoa(limit), "repeat": strconv.Itoa(atk.Repeat),
		},
	}
	t.Oracle = OracleAcceptedOverLimit
	t = finish(ctx, t, p.obj, r.id, "property_level")
	t.RunnerStateValid = false // the permitted success changes state too
	return []Template{t}
}

// Response is the part of an exchange the soft-failure and limit helpers need.
type Response struct {
	Status int
	Body   []byte
}

// AcceptedCount counts responses that are neither refused (a denied status,
// or a soft failure when the template opts in) nor server faults.
func (t Template) AcceptedCount(rs []Response) int {
	n := 0
	for _, r := range rs {
		if r.Status < 500 && !t.Denied(r.Status, r.Body) {
			n++
		}
	}
	return n
}

// ExceedsLimit reports whether more attack responses were accepted than the
// template allows (MaxAccepted). It is the decisive oracle for P-RACE-1.
//
// The runner also grades any state change between the snapshot before and
// after the attack as exploitation. For a once-only or limited action the
// permitted successes change state too, so with a state adapter that reports
// that effect the runner grade is FAIL even when the limit held. Callers of
// P-RACE-1 templates must therefore either use a state adapter that does not
// report the permitted effect, or decide the verdict with ExceedsLimit on the
// recorded attack exchanges (Oracle is OracleAcceptedOverLimit).
func (t Template) ExceedsLimit(rs []Response) bool {
	return t.MaxAccepted > 0 && t.AcceptedCount(rs) > t.MaxAccepted
}
