package property

import (
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// Ownership properties: one account must not reach another account's object.

// crossIdentity builds a baseline (the owner reads their object) followed by
// an attack by a different customer that calls op with the given identifier
// assignment. The oracle is a leak of the owner's canary or customer id, or a
// state change.
func crossIdentity(ctx TemplateCtx, prop string, op model.Operation, p pair, vals map[string]string, extra map[string]string, desc string) (Template, bool) {
	if !supportedMethod(op.Method) {
		return Template{}, false
	}
	base, ok := baselineOrSelf(ctx, op, p.victim, p.obj)
	if !ok {
		return Template{}, false
	}
	path, body := buildRequest(op, vals, 0)
	atk := mkStep("attack-"+strings.ToLower(prop[2:]), "attack", p.attacker.Name, op.Method, path, body,
		"The application checks that the caller owns the referenced object before acting on it.")
	t := Template{
		Description:     desc,
		Steps:           []contract.Step{base, atk},
		DeniedStatuses:  deniedAuthz(),
		ForbiddenValues: leakValues(p.victim),
		Params: map[string]string{
			"operation": op.ID, "victim": p.victim.Name, "attacker": p.attacker.Name,
			"object": p.obj.ID, "confidence": confidence(p.obj),
		},
	}
	for k, v := range extra {
		t.Params[k] = v
	}
	return finish(ctx, t, p.obj, prop, "cross_identity"), true
}

// ---- P-OWN-1 ----

type own1 struct{ meta }

func (own1) Applies(op model.Operation, _ model.Model) bool {
	return op.Method == "GET" && hasPathID(op)
}

// Templates: another account reads the object through the primary
// identifier of a read operation (path, and any other identifier field set to
// the same object).
func (o own1) Templates(ctx TemplateCtx) []Template {
	if !o.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	var out []Template
	for _, p := range pairs(ctx) {
		t, ok := crossIdentity(ctx, o.id, ctx.Op, p, victimVals(ctx.Op, p.obj),
			map[string]string{"location": "path"},
			"Account "+p.attacker.Name+" reads "+p.victim.Name+"'s object through "+ctx.Op.ID+".")
		if ok {
			out = append(out, t)
		}
	}
	return out
}

// ---- P-OWN-2 ----

type own2 struct{ meta }

func (own2) Applies(op model.Operation, _ model.Model) bool {
	return (op.Method == "PATCH" || op.Method == "DELETE" || op.Method == "POST") && hasPathID(op)
}

// Templates: another account modifies or deletes the object. The oracle is a
// change in the state snapshot. PUT operations are not expressible in the
// contract and produce nothing.
func (o own2) Templates(ctx TemplateCtx) []Template {
	if !o.Applies(ctx.Op, ctx.Model) {
		return nil
	}
	var out []Template
	for _, p := range pairs(ctx) {
		t, ok := crossIdentity(ctx, o.id, ctx.Op, p, victimVals(ctx.Op, p.obj),
			map[string]string{"location": "path"},
			"Account "+p.attacker.Name+" changes "+p.victim.Name+"'s object through "+ctx.Op.ID+".")
		if ok {
			out = append(out, t)
		}
	}
	return out
}

// ---- P-OWN-3 ----

type own3 struct{ meta }

// OwnHeaders are the identifier-override headers tried by the header variant
// of P-OWN-3 on read operations.
var ownHeaders = []string{"X-Object-Id", "X-Resource-Id"}

func (own3) Applies(op model.Operation, _ model.Model) bool {
	if !supportedMethod(op.Method) {
		return false
	}
	return hasNonPathID(op) || (op.Method == "GET" && hasPathID(op))
}

// Templates covers every identifier-bearing location other than a mutating
// operation's path (which P-OWN-1/2 cover):
//
//   - query and body (including nested) identifier fields, one template per
//     field; on operations that also have a path identifier, only reads are
//     isolated this way (the path then carries the attacker's own object, so
//     a legitimate write to it cannot be mistaken for a finding), and
//     mutating operations get one combined template with every field set to
//     the victim's object;
//   - identifier-override headers on read operations, with the path carrying
//     the attacker's own object.
func (o own3) Templates(ctx TemplateCtx) []Template {
	op := ctx.Op
	if !o.Applies(op, ctx.Model) {
		return nil
	}
	refs := idRefsOf(op)
	var out []Template
	for _, p := range pairs(ctx) {
		own, hasOwn := firstOwned(ctx.Fixture, p.attacker)
		var nonPath []idRef
		for _, r := range refs {
			if r.loc != "path" {
				nonPath = append(nonPath, r)
			}
		}
		switch {
		case len(nonPath) > 0 && !hasPathID(op):
			for _, r := range nonPath {
				vals := map[string]string{}
				for _, other := range nonPath {
					vals[other.key()] = literalFor(other, own, hasOwn, false)
				}
				vals[r.key()] = literalFor(r, p.obj, true, true)
				if t, ok := crossIdentity(ctx, o.id, op, p, vals, map[string]string{"location": r.key()},
					"Account "+p.attacker.Name+" references "+p.victim.Name+"'s object in "+r.key()+" of "+op.ID+"."); ok {
					out = append(out, t)
				}
			}
		case len(nonPath) > 0 && op.Method == "GET":
			if !hasOwn {
				break
			}
			for _, r := range nonPath {
				vals := ownPathVals(op, own)
				for _, other := range nonPath {
					vals[other.key()] = literalFor(other, own, true, false)
				}
				vals[r.key()] = literalFor(r, p.obj, true, true)
				if t, ok := crossIdentity(ctx, o.id, op, p, vals, map[string]string{"location": r.key()},
					"Account "+p.attacker.Name+" references "+p.victim.Name+"'s object in "+r.key()+" of "+op.ID+" while the path names its own."); ok {
					t.CleanIsEnforced = true // the attacker's own object is legitimately readable
					out = append(out, t)
				}
			}
		case len(nonPath) > 0:
			if t, ok := crossIdentity(ctx, o.id, op, p, victimVals(op, p.obj), map[string]string{"location": "all"},
				"Account "+p.attacker.Name+" references "+p.victim.Name+"'s object in every identifier field of "+op.ID+"."); ok {
				out = append(out, t)
			}
		}
		if op.Method == "GET" && hasPathID(op) && hasOwn {
			for _, h := range ownHeaders {
				t, ok := crossIdentity(ctx, o.id, op, p, ownPathVals(op, own), map[string]string{"location": "header:" + h},
					"Account "+p.attacker.Name+" names its own object in the path of "+op.ID+" and "+p.victim.Name+"'s object in header "+h+".")
				if !ok {
					continue
				}
				last := &t.Steps[len(t.Steps)-1]
				last.Headers = map[string]string{h: p.obj.ID}
				t.CleanIsEnforced = true // the attacker's own object is legitimately readable
				out = append(out, t)
			}
		}
	}
	return out
}

// literalFor renders the value of an identifier field: the object token in
// path or query position for the victim, the literal id elsewhere.
func literalFor(r idRef, o fixture.Object, have bool, victim bool) string {
	if !have {
		return "aleef-none"
	}
	if victim && r.loc != "body" {
		return objToken
	}
	return o.ID
}

// ownPathVals sets every path identifier to the attacker's own object.
func ownPathVals(op model.Operation, own fixture.Object) map[string]string {
	vals := map[string]string{}
	for _, r := range idRefsOf(op) {
		if r.loc == "path" {
			vals[r.key()] = own.ID
		}
	}
	return vals
}

func firstOwned(f fixture.Fixture, a model.Account) (fixture.Object, bool) {
	objs := ownedObjects(f, a)
	if len(objs) == 0 {
		return fixture.Object{}, false
	}
	return objs[0], true
}
