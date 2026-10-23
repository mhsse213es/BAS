package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// Variation names. Each is a parameter mutation applied to a base template; a
// variation that a template cannot take yields nothing for it.
const (
	// VarOtherAccount: the attack addresses a third account's object by its
	// literal id, and that account's customer id is added to the forbidden
	// values. Needs three customers.
	VarOtherAccount = "id-other-account"
	// VarNeighbourID: the attack addresses the id next to the victim's.
	VarNeighbourID = "id-neighbour"
	// VarStaleID: the attack addresses a derived "stale" id of the victim's
	// object (the generator cannot know a really retired id).
	VarStaleID = "id-stale"
	// VarFieldLocation: a read puts the attacker's own object in the path and
	// the victim's in a duplicate query identifier.
	VarFieldLocation = "field-location"
	// VarMethodOverride: a PATCH or DELETE attack is sent as POST with an
	// X-HTTP-Method-Override header.
	VarMethodOverride = "method-override"
	// VarAPIVersion: the attack is sent to another API version that the model
	// serves for the same method.
	VarAPIVersion = "api-version"
	// VarRequestOrder: the setup steps run in reverse order.
	VarRequestOrder = "request-order"
	// VarBoundary: every number in the attack body becomes a boundary value.
	VarBoundary = "boundary-values"
	// VarRepeat and VarParallel: the attack is sent several times, one after
	// another or concurrently. The verdict becomes "more than one accepted"
	// (OracleRepeatAccepted, MaxAccepted 1): a single acceptance is not
	// distinguishable from a soft failure by the runner, which counts bodies
	// it cannot see.
	VarRepeat   = "repeat"
	VarParallel = "parallel"
)

// boundaryValues maps a boundary name to the JSON number written into bodies.
var boundaryValues = map[string]string{
	"zero": "0", "negative": "-1", "max": "9223372036854775807", "rounding": "99.995",
}

// boundaryOrder fixes the order variants are produced in.
var boundaryOrder = []string{"zero", "negative", "max", "rounding"}

type vctx struct {
	op    model.Operation
	model model.Model
	fx    fixture.Fixture
	accts []model.Account
}

type variation struct {
	name string
	fn   func(vctx, property.Template) []property.Template
}

var registry = []variation{
	{VarOtherAccount, varOtherAccount},
	{VarNeighbourID, func(c vctx, t property.Template) []property.Template {
		return literalID(t, "neighbour", neighbourID)
	}},
	{VarStaleID, func(c vctx, t property.Template) []property.Template {
		return literalID(t, "stale", func(id string) string { return id + "-stale" })
	}},
	{VarFieldLocation, varFieldLocation},
	{VarMethodOverride, varMethodOverride},
	{VarAPIVersion, varAPIVersion},
	{VarRequestOrder, func(_ vctx, t property.Template) []property.Template {
		if v, ok := reorderSteps(t); ok {
			v.Params["order"] = "setup-reversed"
			return []property.Template{v}
		}
		return nil
	}},
	{VarBoundary, varBoundary},
	{VarRepeat, func(_ vctx, t property.Template) []property.Template { return repeated(t, 3, false) }},
	{VarParallel, func(_ vctx, t property.Template) []property.Template { return repeated(t, 4, true) }},
}

// AllVariations lists every variation name.
func AllVariations() []string {
	out := make([]string, len(registry))
	for i, v := range registry {
		out[i] = v.name
	}
	return out
}

func resolveVariations(names []string) ([]variation, error) {
	want := map[string]bool{}
	for _, n := range names {
		found := false
		for _, v := range registry {
			found = found || v.name == n
		}
		if !found {
			return nil, fmt.Errorf("generate: unknown variation %q (known: %s)", n, strings.Join(AllVariations(), ", "))
		}
		want[n] = true
	}
	var out []variation
	for _, v := range registry {
		if want[v.name] {
			out = append(out, v)
		}
	}
	return out, nil
}

func attackOf(t property.Template) *contract.Step {
	return &t.Steps[len(t.Steps)-1]
}

func crossIdentity(t property.Template) bool {
	return t.Claim == "cross_identity" && t.Params["victim"] != "" && t.Params["attacker"] != ""
}

func hasToken(t property.Template) bool {
	return strings.Contains(attackOf(t).Path, "{object}")
}

func ownedBy(fx fixture.Fixture, a model.Account) (fixture.Object, bool) {
	var best fixture.Object
	found := false
	for _, o := range fx.Objects {
		if o.OwnerID == a.CustomerID && (!found || o.ID < best.ID) {
			best, found = o, true
		}
	}
	return best, found
}

func account(accts []model.Account, name string) (model.Account, bool) {
	for _, a := range accts {
		if a.Name == name {
			return a, true
		}
	}
	return model.Account{}, false
}

// ---- identifier source ----

func varOtherAccount(c vctx, t property.Template) []property.Template {
	if !crossIdentity(t) || !hasToken(t) {
		return nil
	}
	victim, ok1 := account(c.accts, t.Params["victim"])
	attacker, ok2 := account(c.accts, t.Params["attacker"])
	if !ok1 || !ok2 {
		return nil
	}
	sorted := append([]model.Account(nil), c.accts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, a := range sorted {
		if a.CustomerID == victim.CustomerID || a.CustomerID == attacker.CustomerID {
			continue
		}
		if _, ok := c.fx.Identity(a.Name); !ok {
			continue
		}
		obj, ok := ownedBy(c.fx, a)
		if !ok {
			continue
		}
		v := clone(t)
		at := attackOf(v)
		at.Path = strings.ReplaceAll(at.Path, "{object}", obj.ID)
		if len(a.CustomerID) >= 4 {
			v.ForbiddenValues = append(v.ForbiddenValues, a.CustomerID)
		}
		v.Params["id_source"] = "other-account"
		v.Params["other_object"] = obj.ID
		v.Description += " It addresses " + a.Name + "'s object instead."
		return []property.Template{v}
	}
	return nil
}

// literalID replaces the object token in the attack path with an id derived
// from the victim's object.
func literalID(t property.Template, kind string, derive func(string) string) []property.Template {
	if !crossIdentity(t) || !hasToken(t) || t.Preconditions.Object == "" {
		return nil
	}
	v := clone(t)
	at := attackOf(v)
	id := derive(t.Preconditions.Object)
	at.Path = strings.ReplaceAll(at.Path, "{object}", id)
	v.Params["id_source"] = kind
	v.Params["probe_id"] = id
	v.Description += " It addresses a " + kind + " id (" + id + ") instead."
	return []property.Template{v}
}

var trailingDigits = regexp.MustCompile(`[0-9]+$`)

// neighbourID increments the trailing number of an id, keeping its width;
// an id without one gets "-1" appended.
func neighbourID(id string) string {
	d := trailingDigits.FindString(id)
	if d == "" {
		return id + "-1"
	}
	n, err := strconv.ParseUint(d, 10, 64)
	if err != nil {
		return id + "-1"
	}
	next := strconv.FormatUint(n+1, 10)
	for len(next) < len(d) {
		next = "0" + next
	}
	return id[:len(id)-len(d)] + next
}

// ---- field location ----

func varFieldLocation(c vctx, t property.Template) []property.Template {
	if !crossIdentity(t) || !hasToken(t) || attackOf(t).Method != "GET" {
		return nil
	}
	attacker, ok := account(c.accts, t.Params["attacker"])
	if !ok {
		return nil
	}
	own, ok := ownedBy(c.fx, attacker)
	if !ok {
		return nil
	}
	name := "id"
	for _, p := range c.op.PathParams {
		if p.IsObjectID {
			name = p.Name
			break
		}
	}
	v := clone(t)
	at := attackOf(v)
	sep := "?"
	if strings.Contains(at.Path, "?") {
		sep = "&"
	}
	at.Path = strings.ReplaceAll(at.Path, "{object}", own.ID) + sep + name + "={object}"
	v.Params["location"] = "path+query"
	v.Description += " The attacker's own object is in the path and the victim's in the query."
	return []property.Template{v}
}

// ---- method override ----

func varMethodOverride(_ vctx, t property.Template) []property.Template {
	at := attackOf(t)
	if at.Method != "PATCH" && at.Method != "DELETE" {
		return nil
	}
	v := clone(t)
	a := attackOf(v)
	if a.Headers == nil {
		a.Headers = map[string]string{}
	}
	a.Headers["X-HTTP-Method-Override"] = a.Method
	v.Params["method_override"] = a.Method
	a.Method = "POST"
	if strings.TrimSpace(a.Body) == "" {
		a.Body = "{}"
	}
	v.SideEffect = "STATE_CHANGE_SANDBOX"
	return []property.Template{v}
}

// ---- API version ----

var versionSeg = regexp.MustCompile(`^v[0-9]+$`)

func pathMatches(opPath, concrete string) bool {
	a := strings.Split(strings.Trim(opPath, "/"), "/")
	b := strings.Split(strings.Trim(concrete, "/"), "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !(strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}")) && a[i] != b[i] {
			return false
		}
	}
	return true
}

func varAPIVersion(c vctx, t property.Template) []property.Template {
	at := attackOf(t)
	segs := strings.Split(trimQuery(at.Path), "/")
	idx := -1
	for i, s := range segs {
		if versionSeg.MatchString(s) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	versions := map[string]bool{}
	for _, op := range c.model.Operations {
		for _, s := range strings.Split(op.Path, "/") {
			if versionSeg.MatchString(s) {
				versions[s] = true
			}
		}
	}
	var names []string
	for v := range versions {
		if v != segs[idx] {
			names = append(names, v)
		}
	}
	sort.Strings(names)
	var out []property.Template
	for _, ver := range names {
		alt := append([]string(nil), segs...)
		alt[idx] = ver
		altPath := strings.Join(alt, "/")
		served := false
		for _, op := range c.model.Operations {
			if op.Method == at.Method && runnable(op.Class) && pathMatches(op.Path, altPath) {
				served = true
				break
			}
		}
		if !served {
			continue
		}
		v := clone(t)
		a := attackOf(v)
		a.Path = altPath + a.Path[len(trimQuery(a.Path)):]
		v.Params["api_version"] = ver
		out = append(out, v)
	}
	return out
}

// ---- request order ----

func reorderSteps(t property.Template) (property.Template, bool) {
	n := len(t.Steps)
	if n < 4 {
		return t, false
	}
	v := clone(t)
	for i, j := 1, n-2; i < j; i, j = i+1, j-1 {
		v.Steps[i], v.Steps[j] = v.Steps[j], v.Steps[i]
	}
	return v, true
}

// ---- boundary values ----

func varBoundary(_ vctx, t property.Template) []property.Template {
	at := attackOf(t)
	if strings.TrimSpace(at.Body) == "" {
		return nil
	}
	var out []property.Template
	for _, name := range boundaryOrder {
		dec := json.NewDecoder(strings.NewReader(at.Body))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err != nil {
			return nil
		}
		var replaced int
		doc = replaceNumbers(doc, json.Number(boundaryValues[name]), &replaced)
		if replaced == 0 {
			return nil
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			return nil
		}
		v := clone(t)
		attackOf(v).Body = strings.TrimSpace(buf.String())
		v.Params["boundary"] = name
		out = append(out, v)
	}
	return out
}

func replaceNumbers(v any, with json.Number, n *int) any {
	switch x := v.(type) {
	case json.Number:
		*n++
		return with
	case map[string]any:
		for k, e := range x {
			x[k] = replaceNumbers(e, with, n)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = replaceNumbers(e, with, n)
		}
		return x
	}
	return v
}

// ---- repeat and parallel ----

func repeated(t property.Template, count int, parallel bool) []property.Template {
	at := attackOf(t)
	if t.MaxAccepted != 0 || at.Repeat > 1 || len(t.DeniedStatuses) == 0 {
		return nil
	}
	if t.Claim != "cross_identity" && t.Claim != "function_level" {
		return nil
	}
	if t.Oracle != property.OracleRunnerGrade && t.Oracle != property.OracleStateChange {
		return nil
	}
	v := clone(t)
	a := attackOf(v)
	a.Repeat, a.Parallel = count, parallel
	v.MaxAccepted = 1
	v.Oracle = property.OracleRepeatAccepted
	v.RunnerLeakValid, v.RunnerStateValid = false, false
	v.Params["repeat"] = strconv.Itoa(count)
	v.Params["parallel"] = strconv.FormatBool(parallel)
	return []property.Template{v}
}
