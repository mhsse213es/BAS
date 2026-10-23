package property

import (
	"regexp"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
)

// Role and route-consistency properties.

// ---- P-ROLE-1 ----

type role1 struct{ meta }

// Applies when the model declares at least two roles. Which operations are
// reserved is operator knowledge (TemplateCtx.ReservedRoles); without it the
// property emits nothing for the operation.
func (role1) Applies(op model.Operation, m model.Model) bool {
	return len(m.Roles) >= 2 && supportedMethod(op.Method)
}

func roleRank(roles []string, role string) int {
	for i, r := range roles {
		if r == role {
			return i
		}
	}
	return -1
}

// Templates: for a reserved operation, every account whose role ranks below
// the required role (and who owns an object) calls it on its own object. The
// object belongs to the attacker, so a refusal can only come from the role
// check, never from ownership.
//
// Oracle: a state change for writes. A read has no state to diff, so the
// attack is sent twice and MaxAccepted is 1: two non-denied responses are
// exploitation ("2xx where the control should deny"). The caveat is that a
// 2xx soft failure counts as accepted inside the runner; Template.Denied lets
// a later stage reclassify those exchanges.
func (r role1) Templates(ctx TemplateCtx) []Template {
	op := ctx.Op
	if !r.Applies(op, ctx.Model) {
		return nil
	}
	required, ok := ctx.ReservedRoles[op.ID]
	if !ok {
		return nil
	}
	reqRank := roleRank(ctx.Model.Roles, required)
	if reqRank < 0 {
		return nil
	}
	var out []Template
	for _, p := range ownersWithObject(ctx, "") {
		rank := roleRank(ctx.Model.Roles, p.victim.Role)
		if rank < 0 || rank >= reqRank {
			continue
		}
		base, ok := baselineStep(ctx, op, p.victim, false)
		if !ok {
			continue
		}
		path, body := buildRequest(op, victimVals(op, p.obj), 0)
		atk := mkStep("attack-role", "attack", p.victim.Name, op.Method, path, body,
			"The application refuses an operation reserved for role "+required+" to an account with role "+p.victim.Role+".")
		oracle := "state_change"
		t := Template{
			Description:    "Account " + p.victim.Name + " (" + p.victim.Role + ") calls " + op.ID + ", reserved for " + required + ".",
			Steps:          []contract.Step{base, atk},
			DeniedStatuses: deniedAuthz(),
		}
		if op.Method == "GET" {
			t.Steps[1].Repeat = 2
			t.MaxAccepted = 1
			oracle = "repeat_accepted"
		}
		t.Params = map[string]string{
			"operation": op.ID, "attacker": p.victim.Name, "role": p.victim.Role,
			"required_role": required, "object": p.obj.ID, "oracle": oracle,
		}
		out = append(out, finish(ctx, t, p.obj, r.id, "function_level"))
	}
	return out
}

// ---- P-ROLE-2 ----

type role2 struct{ meta }

var (
	versionSeg = regexp.MustCompile(`^v\d+(\.\d+)*$`)
	paramSeg   = regexp.MustCompile(`^\{[^}]*\}$`)
	altSegs    = map[string]bool{"legacy": true, "internal": true, "mobile": true, "beta": true, "old": true}
)

// routeKey normalizes a route so that versioned and alternative-channel
// copies of one operation share a key: version and channel segments are
// dropped and parameter names are erased.
func routeKey(op model.Operation) string {
	var segs []string
	for _, s := range strings.Split(strings.Trim(op.Path, "/"), "/") {
		switch {
		case versionSeg.MatchString(strings.ToLower(s)), altSegs[strings.ToLower(s)]:
		case paramSeg.MatchString(s):
			segs = append(segs, "{}")
		default:
			segs = append(segs, s)
		}
	}
	return op.Method + " /" + strings.Join(segs, "/")
}

// peers returns the ids of other operations sharing op's route key.
func peers(op model.Operation, m model.Model) []string {
	key := routeKey(op)
	var out []string
	for _, o := range m.Operations {
		if o.ID != op.ID && o.Path != op.Path && routeKey(o) == key {
			out = append(out, o.ID)
		}
	}
	sort.Strings(out)
	return out
}

func (role2) Applies(op model.Operation, m model.Model) bool {
	return supportedMethod(op.Method) && hasPathID(op) && len(peers(op, m)) > 0
}

// Templates: the cross-account test of P-OWN-1/2 is applied to each member of
// a group of equivalent routes (versions or channels). Every member carries
// the same Params["group"], so the verifier can compare outcomes across the
// group: the same attack must be refused on all of them. The runner grades
// each template on its own; the differential itself is a comparison of
// results by group, which the contract cannot express in a single scenario.
func (r role2) Templates(ctx TemplateCtx) []Template {
	op := ctx.Op
	if !r.Applies(op, ctx.Model) {
		return nil
	}
	ps := pairs(ctx)
	if len(ps) == 0 {
		return nil
	}
	p := ps[0]
	t, ok := crossIdentity(ctx, r.id, op, p, victimVals(op, p.obj), map[string]string{
		"group": routeKey(op), "peers": strings.Join(peers(op, ctx.Model), ","), "location": "route",
	}, "Account "+p.attacker.Name+" reaches "+p.victim.Name+"'s object through the alternative route "+op.Path+".")
	if !ok {
		return nil
	}
	return []Template{t}
}
