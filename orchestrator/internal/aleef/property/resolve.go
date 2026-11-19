package property

import (
	"regexp"
	"sort"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// Resource-aware object selection.
//
// Every identifier reference of an operation has a resource type (see
// model/resource.go). A test names ONE primary object with the runner's
// "{object}" token: the owner's object of the operation's primary type. Every
// other identifier that has a known type is written literally from the same
// owner's object of THAT type. When the owner has no object of a needed type
// the identifier is rendered with an unresolved marker; the generator drops
// such a test and counts it (UnresolvedTypes) instead of sending a wrong id.
//
// Objects whose Kind is empty (hand-built fixtures) match every type and keep
// the single-object behaviour.

const noObjectPrefix = "ALEEF_NO_OBJECT__"

var noObjectRe = regexp.MustCompile(noObjectPrefix + `([a-z0-9_]+?)__`)

func noObject(t string) string { return noObjectPrefix + t + "__" }

// missingKind marks an object stand-in for an owner that has no object of the
// needed primary type; every typed reference then reads as unresolved.
const missingKind = "\x00missing"

// UnresolvedTypes returns the sorted resource types for which a step
// references a fixture object that does not exist.
func UnresolvedTypes(steps []contract.Step) []string {
	set := map[string]bool{}
	scan := func(s string) {
		for _, m := range noObjectRe.FindAllStringSubmatch(s, -1) {
			set[m[1]] = true
		}
	}
	for _, st := range steps {
		scan(st.Path)
		scan(st.Body)
		for _, v := range st.Headers {
			scan(v)
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func knownType(ctx TemplateCtx, t string) bool {
	if t == "" {
		return false
	}
	if ctx.Model.HasResourceType(t) {
		return true
	}
	for _, o := range ctx.Fixture.Objects {
		if o.Kind == t {
			return true
		}
	}
	return false
}

// refType is the resource type an identifier reference points at, "" when it
// has none or the type is unknown to the model and the fixture.
func refType(ctx TemplateCtx, op model.Operation, r idRef) string {
	t := ""
	if r.loc == "path" {
		for _, p := range op.PathParams {
			if p.Name == r.name {
				t = p.ResourceType
			}
		}
	} else if !principalRef(r) {
		t = model.NameStem(r.name)
	}
	if !knownType(ctx, t) {
		return ""
	}
	return t
}

// primaryType is the type of the object a test on op names with "{object}":
// the last path identifier's type, else the first typed query or body
// identifier, else "" (any object).
func primaryType(ctx TemplateCtx, op model.Operation) string {
	if t := op.PrimaryType(); t != "" {
		return t
	}
	for _, r := range idRefsOf(op) {
		if r.loc == "path" {
			continue
		}
		if t := refType(ctx, op, r); t != "" {
			return t
		}
	}
	return ""
}

// PrimaryTypeOf exposes primaryType to the generator's variations.
func PrimaryTypeOf(m model.Model, fx fixture.Fixture, op model.Operation) string {
	return primaryType(TemplateCtx{Model: m, Fixture: fx}, op)
}

// ownedOfType lists a's objects of type t (every object when t is empty),
// lowest id first.
func ownedOfType(f fixture.Fixture, a model.Account, t string) []fixture.Object {
	var out []fixture.Object
	for _, o := range f.Objects {
		if o.OwnerID == a.CustomerID && (t == "" || o.Kind == "" || o.Kind == t) {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// OwnedObject returns a's lowest-id object of type t.
func OwnedObject(f fixture.Fixture, a model.Account, t string) (fixture.Object, bool) {
	objs := ownedOfType(f, a, t)
	if len(objs) == 0 {
		return fixture.Object{}, false
	}
	return objs[0], true
}

// peerOf finds the owner's object of exactly type t.
func peerOf(f fixture.Fixture, ownerID, t string) (fixture.Object, bool) {
	var best fixture.Object
	found := false
	for _, o := range f.Objects {
		if o.OwnerID == ownerID && o.Kind == t && (!found || o.ID < best.ID) {
			best, found = o, true
		}
	}
	return best, found
}

// objectFor is the owner's object a request to op acts on (the stand-in
// carries only the owner when there is none, so typed references read as
// unresolved).
func objectFor(ctx TemplateCtx, owner model.Account, op model.Operation) fixture.Object {
	t := primaryType(ctx, op)
	if o, ok := OwnedObject(ctx.Fixture, owner, t); ok {
		return o
	}
	if t == "" {
		return fixture.Object{OwnerID: owner.CustomerID}
	}
	return fixture.Object{OwnerID: owner.CustomerID, Kind: missingKind}
}

// resolveRef renders one identifier reference relative to obj (the primary
// object of the request's owner). useToken selects the "{object}" token for
// a reference to obj in a path or query position.
func resolveRef(ctx TemplateCtx, op model.Operation, r idRef, obj fixture.Object, useToken bool) string {
	if principalRef(r) {
		return obj.OwnerID
	}
	t := refType(ctx, op, r)
	if t == "" || obj.Kind == "" || obj.Kind == t {
		if useToken && r.loc != "body" {
			return objToken
		}
		return obj.ID
	}
	if peer, ok := peerOf(ctx.Fixture, obj.OwnerID, t); ok {
		return peer.ID
	}
	return noObject(t)
}
