// Package binding turns an imported API inventory plus customer-supplied test data into scenarios the runner can execute against
// that API.
//
// The catalogue scenarios are written against the lab's own routes and fixtures. A customer's API has different routes, so a
// scenario has to be bound: given an operation from the inventory, two identities the customer supplies credentials for, and
// objects each identity owns, the binder writes a concrete cross-identity read scenario (the owner reads their object as the
// baseline, another identity requests the same object as the attack).
//
// Only read-only object-level scenarios are bound. A change to state needs an independent check that the state did not change,
// and a customer's API offers none, so write operations are reported as skipped rather than bound with a weaker claim. A bound
// scenario is graded on the HTTP response alone: the attack passes only if it is refused and returns none of the distinctive
// values the customer marked as protected. See runner.NoState.
//
// The binder reads and writes no database and contacts no network. It never receives a credential value, only the names of
// credentials the runner resolves at job time.
package binding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/openapi"
)

// MaxScenarios is how many scenarios one plan may hold. Bound scenarios take the ids API-BAS-AUTHZ-901 to 999, clear of the
// catalogue.
const MaxScenarios = 99

// FixtureName is the fixture name every bound scenario declares.
const FixtureName = "customer-bound"

var (
	identityNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	paramValueRE   = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
	credentialRE   = regexp.MustCompile(`^[A-Za-z0-9_./:@-]{1,200}$`)
)

// IdentitySpec names an identity and the credential the runner resolves for it. CredentialRef is a name, never a value.
type IdentitySpec struct {
	Name          string `json:"name"`
	CredentialRef string `json:"credential_ref"`
}

// ObjectSpec is one test object: an operation, the values of its path parameters, the identity that owns it, and optionally
// distinctive values (at least four characters) that only the owner may see in a response.
type ObjectSpec struct {
	Operation       string            `json:"operation"` // "GET /v2/orders/{orderId}"
	Params          map[string]string `json:"params"`
	Owner           string            `json:"owner"`
	ProtectedValues []string          `json:"protected_values,omitempty"`
	// Write is required for an object of a PUT or PATCH operation and forbidden otherwise.
	Write *WriteSpec `json:"write,omitempty"`
}

// WriteSpec describes how a write is attempted against an object and how the object is checked and put back. The target offers no
// administrative view, so state is judged by reading the object back through its own read route as its owner.
type WriteSpec struct {
	// AttackBody is the JSON object another identity sends. RestoreBody is the JSON object the owner sends afterwards (and before the
	// run) to put the object back; it must be a request the target accepts and that returns the object to the state wanted.
	AttackBody  string `json:"attack_body"`
	RestoreBody string `json:"restore_body"`
	// ReadOperation is the operation the object is read back through, for example "GET /v2/orders/{orderId}". When empty it is the
	// GET operation with the same path as the write.
	ReadOperation string `json:"read_operation,omitempty"`
	// IgnoreFields are response fields left out of the comparison because they change on every read (timestamps, request ids).
	IgnoreFields []string `json:"ignore_fields,omitempty"`
}

// FunctionSpec is one privileged read-only route that an ordinary identity must not be able to call. Privileged is an identity that
// is allowed to call it (it proves the route works), Ordinary is the identity that must be refused, and ProtectedValues are
// distinctive values the privileged response contains and an ordinary identity must never receive. Without them a 2xx to the
// ordinary identity could not be told from a harmless one, so at least one is required.
type FunctionSpec struct {
	Operation       string            `json:"operation"` // a GET, for example "GET /v2/admin/users/{userId}"
	Params          map[string]string `json:"params,omitempty"`
	Privileged      string            `json:"privileged"`
	Ordinary        string            `json:"ordinary"`
	ProtectedValues []string          `json:"protected_values"`
}

// PropertySpec is one object the owner reads, whose response must not contain values the owner should not see (an internal flag, a
// stored hash, another party's data). ForbiddenValues are distinctive values of those properties, at least one is required, and
// they are checked in the owner's own response.
type PropertySpec struct {
	Operation       string            `json:"operation"` // a GET, for example "GET /v2/profiles/{pid}"
	Params          map[string]string `json:"params,omitempty"`
	Owner           string            `json:"owner"`
	ForbiddenValues []string          `json:"forbidden_values"`
}

// Spec is the customer-supplied test data.
type Spec struct {
	Identities []IdentitySpec `json:"identities"`
	Objects    []ObjectSpec   `json:"objects"`
	// Functions and Properties add function-level and property-level read checks. Both are optional and read-only.
	Functions  []FunctionSpec `json:"functions,omitempty"`
	Properties []PropertySpec `json:"properties,omitempty"`
	// AllowWrites acknowledges that the objects listed with a write block may be changed while the test runs, and are put back by the
	// restore request afterwards. Without it no write is bound.
	AllowWrites bool `json:"allow_writes,omitempty"`
}

// Bound describes one generated scenario.
type Bound struct {
	ScenarioID string `json:"scenario_id"`
	Operation  string `json:"operation"`
	Attacker   string `json:"attacker"`
	Victim     string `json:"victim"`
	Path       string `json:"path"`
	// Kind is "function" or "property" for those checks; empty for an object-level check. For a function check Attacker is the ordinary
	// identity and Victim the privileged one; for a property check both are the owner.
	Kind string `json:"kind,omitempty"`
	// Write is true for a scenario that attempts a state change; its result is judged by reading the object back.
	Write bool `json:"write,omitempty"`
}

// Probe is one object the runner reads back as its owner before and after a write attempt. Path is concrete.
type Probe struct {
	Key      string
	Identity string
	Path     string
	Ignore   []string
}

// Restore is the owner's request that puts one object back to the supplied state.
type Restore struct {
	Key      string
	Identity string
	Method   string
	Path     string
	Body     string
}

// Skipped is an object-level operation that was not bound, with the reason.
type Skipped struct {
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
}

// Plan is the result of binding. Fixture and Scenarios are what the runner needs.
type Plan struct {
	Fixture   fixture.Fixture     `json:"-"`
	Scenarios []contract.Scenario `json:"-"`
	Bound     []Bound             `json:"bound"`
	Skipped   []Skipped           `json:"skipped"`
	Limits    []string            `json:"limits"`
	// Writes is true when any scenario attempts a state change. Probes and Restores are what the runner needs for those.
	Writes   bool      `json:"-"`
	Probes   []Probe   `json:"-"`
	Restores []Restore `json:"-"`
}

// planLimits states what a bound plan does not claim. It is part of every plan.
func planLimits(writes bool) []string {
	out := []string{
		"Only object-level operations on objects the customer supplied are bound: reads, and PUT or PATCH writes when the test data allows them. DELETE and other operations are skipped because a repeated request cannot put the object back.",
		"A read scenario is graded on the HTTP response alone. It proves the attack was refused and leaked none of the protected values supplied; it cannot see a leak of a value the customer did not supply.",
		"Function-level and property-level checks are read-only and graded on the response alone: they find a privileged route that answers an ordinary identity, or a forbidden value in an owner's response, only for the routes, identities and values supplied. Writing a field that should be read-only (mass assignment) is not tested.",
		"The scenarios have no detection integration (detection is not evaluated) and no regulatory mapping.",
		"An operation passes only for the objects and identities supplied. It says nothing about other objects, roles or parameters.",
	}
	if writes {
		out = append(out,
			"A write scenario is judged by reading the object back through its own read route as its owner, before and after the attempt. A change to anything that route does not return, or to a field listed as ignored, cannot be detected.",
			"A write that succeeds changes the customer's object. It is put back by the owner's restore request, which the runner sends before the run (proving it works) and after. If a restore fails the result is an error and the object's state is unknown; check it by hand.",
		)
	}
	return out
}

// Validate checks the spec on its own, and against the inventory when one is given.
func (s Spec) Validate(inv *openapi.Inventory) error {
	if len(s.Identities) < 2 {
		return errors.New("binding: at least two identities are needed to test one identity against another")
	}
	names := map[string]bool{}
	creds := map[string]bool{}
	for _, id := range s.Identities {
		if !identityNameRE.MatchString(id.Name) {
			return fmt.Errorf("binding: identity name %q must be lower-case letters, digits and '-', 1 to 40 characters", id.Name)
		}
		if names[id.Name] {
			return fmt.Errorf("binding: identity %q is listed twice", id.Name)
		}
		names[id.Name] = true
		if !credentialRE.MatchString(id.CredentialRef) {
			return fmt.Errorf("binding: identity %q needs a credential reference of letters, digits and _ . / : @ -", id.Name)
		}
		if creds[id.CredentialRef] {
			return fmt.Errorf("binding: two identities share the credential reference %q; they would not be different identities", id.CredentialRef)
		}
		creds[id.CredentialRef] = true
	}
	if len(s.Objects) == 0 && len(s.Functions) == 0 && len(s.Properties) == 0 {
		return errors.New("binding: no test objects supplied")
	}
	ops := map[string]openapi.Operation{}
	if inv != nil {
		for _, o := range inv.Operations {
			ops[o.Key()] = o
		}
	}
	seen := map[string]bool{}
	for i, ob := range s.Objects {
		if !names[ob.Owner] {
			return fmt.Errorf("binding: object %d: owner %q is not a listed identity", i+1, ob.Owner)
		}
		if inv != nil {
			op, ok := ops[ob.Operation]
			if !ok {
				return fmt.Errorf("binding: object %d: operation %q is not in the inventory", i+1, truncate(ob.Operation, 80))
			}
			if err := checkParams(op, ob); err != nil {
				return fmt.Errorf("binding: object %d: %w", i+1, err)
			}
		}
		if err := s.checkWrite(i+1, ob, ops, inv != nil); err != nil {
			return err
		}
		for k, v := range ob.Params {
			if !paramValueRE.MatchString(v) {
				return fmt.Errorf("binding: object %d: value of %q must be 1 to 128 letters, digits and . _ ~ -", i+1, truncate(k, 40))
			}
		}
		for _, pv := range ob.ProtectedValues {
			if len(pv) < 4 || len(pv) > 200 || strings.ContainsAny(pv, "\r\n\x00") {
				return fmt.Errorf("binding: object %d: a protected value must be 4 to 200 characters on one line", i+1)
			}
		}
		key := ob.Operation + "|" + fmt.Sprint(sortedParams(ob.Params))
		if seen[key] {
			return fmt.Errorf("binding: object %d repeats an earlier object", i+1)
		}
		seen[key] = true
	}
	return s.checkExtras(names, ops, inv != nil)
}

// checkExtras validates the function-level and property-level entries.
func (s Spec) checkExtras(names map[string]bool, ops map[string]openapi.Operation, haveInventory bool) error {
	checkRead := func(kind string, n int, operation string, params map[string]string, values []string, what string) error {
		if haveInventory {
			op, ok := ops[operation]
			if !ok {
				return fmt.Errorf("binding: %s %d: operation %q is not in the inventory", kind, n, truncate(operation, 80))
			}
			if op.Method != "GET" {
				return fmt.Errorf("binding: %s %d: %s is not a GET; only read-only routes are checked here", kind, n, op.Key())
			}
			if op.Auth == openapi.AuthNone {
				return fmt.Errorf("binding: %s %d: the specification declares %s public, so there is nothing to refuse", kind, n, op.Key())
			}
			if err := checkParams(op, ObjectSpec{Params: params}); err != nil {
				return fmt.Errorf("binding: %s %d: %w", kind, n, err)
			}
		}
		for k, v := range params {
			if !paramValueRE.MatchString(v) {
				return fmt.Errorf("binding: %s %d: value of %q must be 1 to 128 letters, digits and . _ ~ -", kind, n, truncate(k, 40))
			}
		}
		if len(values) == 0 {
			return fmt.Errorf("binding: %s %d needs at least one %s: without one, a successful response could not be told from a harmless one", kind, n, what)
		}
		if len(values) > 20 {
			return fmt.Errorf("binding: %s %d: at most 20 values", kind, n)
		}
		for _, v := range values {
			if len(v) < 4 || len(v) > 200 || strings.ContainsAny(v, "\r\n\x00") {
				return fmt.Errorf("binding: %s %d: a %s must be 4 to 200 characters on one line", kind, n, what)
			}
		}
		return nil
	}
	seenF := map[string]bool{}
	for i, f := range s.Functions {
		n := i + 1
		if !names[f.Privileged] || !names[f.Ordinary] {
			return fmt.Errorf("binding: function %d: privileged and ordinary must be listed identities", n)
		}
		if f.Privileged == f.Ordinary {
			return fmt.Errorf("binding: function %d: the privileged and ordinary identities must differ", n)
		}
		if err := checkRead("function", n, f.Operation, f.Params, f.ProtectedValues, "protected value"); err != nil {
			return err
		}
		key := f.Operation + "|" + f.Ordinary + "|" + fmt.Sprint(sortedParams(f.Params))
		if seenF[key] {
			return fmt.Errorf("binding: function %d repeats an earlier function", n)
		}
		seenF[key] = true
	}
	seenP := map[string]bool{}
	for i, p := range s.Properties {
		n := i + 1
		if !names[p.Owner] {
			return fmt.Errorf("binding: property check %d: owner %q is not a listed identity", n, truncate(p.Owner, 40))
		}
		if err := checkRead("property check", n, p.Operation, p.Params, p.ForbiddenValues, "forbidden value"); err != nil {
			return err
		}
		key := p.Operation + "|" + p.Owner + "|" + fmt.Sprint(sortedParams(p.Params))
		if seenP[key] {
			return fmt.Errorf("binding: property check %d repeats an earlier check", n)
		}
		seenP[key] = true
	}
	return nil
}

var ignoreFieldRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// maxWriteBody bounds an attack or restore body.
const maxWriteBody = 4096

func isWriteMethod(m string) bool { return m == "PUT" || m == "PATCH" }

// checkWrite validates an object's write block, and that a write operation has one.
func (s Spec) checkWrite(n int, ob ObjectSpec, ops map[string]openapi.Operation, haveInventory bool) error {
	if ob.Write == nil {
		if haveInventory && isWriteMethod(ops[ob.Operation].Method) {
			return fmt.Errorf("binding: object %d: %s changes state; add a write block (attack_body and restore_body) or remove the object", n, ob.Operation)
		}
		return nil
	}
	if !s.AllowWrites {
		return fmt.Errorf("binding: object %d: a write block needs allow_writes set to true, acknowledging the object may be changed during the test", n)
	}
	w := ob.Write
	if haveInventory && !isWriteMethod(ops[ob.Operation].Method) {
		return fmt.Errorf("binding: object %d: only a PUT or PATCH operation takes a write block", n)
	}
	for name, body := range map[string]string{"attack_body": w.AttackBody, "restore_body": w.RestoreBody} {
		if err := checkJSONObject(body); err != nil {
			return fmt.Errorf("binding: object %d: %s %w", n, name, err)
		}
	}
	if bytes.Equal(bytes.TrimSpace([]byte(w.AttackBody)), bytes.TrimSpace([]byte(w.RestoreBody))) {
		return fmt.Errorf("binding: object %d: attack_body and restore_body are identical, so a successful write could not be told from none", n)
	}
	if len(w.IgnoreFields) > 20 {
		return fmt.Errorf("binding: object %d: at most 20 ignore_fields", n)
	}
	for _, f := range w.IgnoreFields {
		if !ignoreFieldRE.MatchString(f) {
			return fmt.Errorf("binding: object %d: ignore field %q must be 1 to 64 letters, digits and . _ -", n, truncate(f, 40))
		}
	}
	if haveInventory {
		if _, err := readOperationFor(ops, ops[ob.Operation], w); err != nil {
			return fmt.Errorf("binding: object %d: %w", n, err)
		}
	}
	return nil
}

func checkJSONObject(body string) error {
	if len(body) < 2 || len(body) > maxWriteBody || strings.ContainsRune(body, 0) {
		return fmt.Errorf("must be a JSON object of 2 to %d bytes", maxWriteBody)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil || m == nil {
		return errors.New("must be a JSON object")
	}
	return nil
}

// readOperationFor finds the operation an object is read back through and checks it can be: a GET the specification does not
// declare public, taking exactly the write's path parameters.
func readOperationFor(ops map[string]openapi.Operation, write openapi.Operation, w *WriteSpec) (openapi.Operation, error) {
	key := w.ReadOperation
	if key == "" {
		key = "GET " + write.Path
	}
	rd, ok := ops[key]
	switch {
	case !ok:
		return rd, fmt.Errorf("the object cannot be read back: %q is not in the inventory (name a GET operation in read_operation)", truncate(key, 80))
	case rd.Method != "GET":
		return rd, errors.New("read_operation must be a GET")
	case rd.Auth == openapi.AuthNone:
		return rd, errors.New("read_operation is declared public, so it cannot show an owner's view")
	}
	a, b := templateNames(rd.Path), templateNames(write.Path)
	sort.Strings(a)
	sort.Strings(b)
	if !slices.Equal(a, b) {
		return rd, errors.New("read_operation must take the same path parameters as the write")
	}
	return rd, nil
}

func checkParams(op openapi.Operation, ob ObjectSpec) error {
	want := map[string]bool{}
	for _, p := range templateNames(op.Path) {
		want[p] = true
		if _, ok := ob.Params[p]; !ok {
			return fmt.Errorf("a value for path parameter %q is required", p)
		}
	}
	for k := range ob.Params {
		if !want[k] {
			return fmt.Errorf("%q is not a path parameter of %s", truncate(k, 40), op.Key())
		}
	}
	return nil
}

func templateNames(path string) []string {
	var out []string
	for seg := range strings.SplitSeq(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && len(seg) > 2 {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}

func sortedParams(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func resolvePath(op openapi.Operation, params map[string]string) string {
	p := op.Path
	for k, v := range params {
		p = strings.ReplaceAll(p, "{"+k+"}", v)
	}
	return p
}

// Bind generates the plan for an inventory and a spec.
func Bind(inv *openapi.Inventory, spec Spec) (*Plan, error) {
	if inv == nil {
		return nil, errors.New("binding: no inventory")
	}
	if err := spec.Validate(inv); err != nil {
		return nil, err
	}
	plan := &Plan{Fixture: fixture.Fixture{Name: FixtureName}, Limits: planLimits(false), Bound: []Bound{}, Skipped: []Skipped{}}
	for _, id := range spec.Identities {
		plan.Fixture.Identities = append(plan.Fixture.Identities, fixture.Identity{Name: id.Name, CustomerID: id.Name, TokenRef: id.CredentialRef})
	}
	opsByKey := map[string]openapi.Operation{}
	for _, o := range inv.Operations {
		opsByKey[o.Key()] = o
	}
	byOp := map[string][]ObjectSpec{}
	for _, ob := range spec.Objects {
		byOp[ob.Operation] = append(byOp[ob.Operation], ob)
	}
	next := 901
	for _, op := range inv.Operations {
		objs := byOp[op.Key()]
		candidate := len(objs) > 0
		for _, c := range op.Classes {
			if c == openapi.ClassObjectLevel {
				candidate = true
			}
		}
		if !candidate {
			continue
		}
		if reason := unbindable(op, objs, spec.AllowWrites); reason != "" {
			plan.Skipped = append(plan.Skipped, Skipped{Operation: op.Key(), Reason: reason})
			continue
		}
		for _, victim := range objs {
			attacker := firstOtherOwner(objs, victim.Owner)
			if attacker == "" {
				continue
			}
			if next > 999 {
				return nil, fmt.Errorf("binding: more than %d scenarios; supply fewer objects", MaxScenarios)
			}
			objID := fmt.Sprintf("bound-%d", next)
			plan.Fixture.Objects = append(plan.Fixture.Objects, fixture.Object{ID: objID, OwnerID: victim.Owner, Status: "bound"})
			var sc contract.Scenario
			isWrite := isWriteMethod(op.Method)
			if isWrite {
				rd, err := readOperationFor(opsByKey, op, victim.Write)
				if err != nil {
					return nil, err
				}
				readPath := resolvePath(rd, victim.Params)
				sc = scenarioForWrite(next, op, victim, attacker, objID, resolvePath(op, victim.Params), readPath)
				plan.Writes = true
				plan.Probes = append(plan.Probes, Probe{Key: objID, Identity: victim.Owner, Path: readPath, Ignore: victim.Write.IgnoreFields})
				plan.Restores = append(plan.Restores, Restore{Key: objID, Identity: victim.Owner, Method: op.Method, Path: resolvePath(op, victim.Params), Body: victim.Write.RestoreBody})
			} else {
				sc = scenarioFor(next, op, victim, attacker, objID, resolvePath(op, victim.Params))
			}
			if err := sc.Validate(); err != nil {
				return nil, fmt.Errorf("binding: generated scenario is invalid (a binder bug): %w", err)
			}
			plan.Scenarios = append(plan.Scenarios, sc)
			plan.Bound = append(plan.Bound, Bound{ScenarioID: sc.ID, Operation: op.Key(), Attacker: attacker, Victim: victim.Owner, Path: sc.Steps[1].Path, Write: isWrite})
			next++
		}
	}
	for _, f := range spec.Functions {
		if next > 999 {
			return nil, fmt.Errorf("binding: more than %d scenarios; supply fewer objects", MaxScenarios)
		}
		op := opsByKey[f.Operation]
		objID := fmt.Sprintf("bound-%d", next)
		plan.Fixture.Objects = append(plan.Fixture.Objects, fixture.Object{ID: objID, OwnerID: f.Privileged, Status: "bound"})
		sc := scenarioForFunction(next, op, f, objID, resolvePath(op, f.Params))
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("binding: generated scenario is invalid (a binder bug): %w", err)
		}
		plan.Scenarios = append(plan.Scenarios, sc)
		plan.Bound = append(plan.Bound, Bound{ScenarioID: sc.ID, Operation: op.Key(), Attacker: f.Ordinary, Victim: f.Privileged, Path: sc.Steps[1].Path, Kind: "function"})
		next++
	}
	for _, p := range spec.Properties {
		if next > 999 {
			return nil, fmt.Errorf("binding: more than %d scenarios; supply fewer objects", MaxScenarios)
		}
		op := opsByKey[p.Operation]
		objID := fmt.Sprintf("bound-%d", next)
		plan.Fixture.Objects = append(plan.Fixture.Objects, fixture.Object{ID: objID, OwnerID: p.Owner, Status: "bound"})
		sc := scenarioForProperty(next, op, p, objID, resolvePath(op, p.Params))
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("binding: generated scenario is invalid (a binder bug): %w", err)
		}
		plan.Scenarios = append(plan.Scenarios, sc)
		plan.Bound = append(plan.Bound, Bound{ScenarioID: sc.ID, Operation: op.Key(), Attacker: p.Owner, Victim: p.Owner, Path: sc.Steps[1].Path, Kind: "property"})
		next++
	}
	if len(plan.Scenarios) == 0 && len(plan.Skipped) == 0 {
		return nil, errors.New("binding: nothing in the inventory can be bound to the objects supplied")
	}
	plan.Limits = planLimits(plan.Writes)
	return plan, nil
}

// unbindable returns why an operation cannot be bound, or "" when it can.
func unbindable(op openapi.Operation, objs []ObjectSpec, allowWrites bool) string {
	switch op.Method {
	case "GET":
	case "PUT", "PATCH":
		if !allowWrites {
			return "it changes state; the test data does not set allow_writes, so no write is attempted"
		}
	case "DELETE":
		return "it destroys the object, and a repeated request cannot put the object back, so it is not bound"
	case "QUERY", "MUTATION", "SUBSCRIPTION":
		return "it is a GraphQL operation; GraphQL schemas are inventoried and classified, but binding them to test data is not supported yet"
	default:
		return "its effect cannot be undone by repeating the request, so the object could not be restored after the test; it is not bound"
	}
	switch {
	case op.Auth == openapi.AuthNone:
		return "the specification declares it public, so there is no owner to cross"
	case len(objs) == 0:
		return "no test objects were supplied for it"
	}
	owners := map[string]bool{}
	for _, o := range objs {
		owners[o.Owner] = true
	}
	if len(owners) < 2 {
		return "it needs objects owned by two different identities"
	}
	return ""
}

func firstOtherOwner(objs []ObjectSpec, owner string) string {
	var names []string
	for _, o := range objs {
		if o.Owner != owner {
			names = append(names, o.Owner)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

// scenarioForFunction builds the function-level check: a privileged identity calls a privileged read-only route (the baseline, which
// shows the route works), then an ordinary identity calls it. The ordinary identity must be refused and must receive none of the
// protected values the privileged response carries.
func scenarioForFunction(n int, op openapi.Operation, f FunctionSpec, objID, path string) contract.Scenario {
	id := fmt.Sprintf("API-BAS-AUTHZ-%03d", n)
	objective := fmt.Sprintf("%s calls the privileged function %s that is meant for %s.", f.Ordinary, op.Key(), f.Privileged)
	return contract.Scenario{
		ID:              id,
		Name:            fmt.Sprintf("Bound: %s cannot call the privileged function %s", f.Ordinary, op.Key()),
		Category:        "AUTHZ",
		Claim:           "function_level",
		AttackObjective: objective,
		ThreatModel: contract.ThreatModel{
			Attacker: "an authenticated ordinary identity of the customer's API", Identity: f.Ordinary,
			AccessLevel: "valid credential supplied by the customer, without the privilege the function needs", Objective: objective,
		},
		Preconditions: contract.Preconditions{Fixture: FixtureName, Identities: []string{f.Ordinary, f.Privileged}, Object: objID},
		Steps: []contract.Step{
			{ID: "baseline-privileged", Role: "baseline", Identity: f.Privileged, Auth: "valid", Method: "GET", Path: path,
				Hypothesis: "The privileged identity calls the function. If this fails, the scenario is not testable."},
			{ID: "attack-ordinary-identity", Role: "attack", Identity: f.Ordinary, Auth: "valid", Method: "GET", Path: path,
				Hypothesis: "An ordinary identity's call to the privileged function is refused and returns none of the protected values."},
		},
		DeniedStatuses:  []int{403, 404},
		ForbiddenValues: f.ProtectedValues,
		ExpectedControl: "An ordinary identity cannot call a privileged function. The request is refused and no protected value from the privileged response is returned.",
		GroundTruth: contract.GroundTruth{
			Adapters: []string{"state", "response"},
			Check:    "The response to the ordinary identity's call carries none of the protected values supplied. The target offers no independent state, so this is response evidence only.",
		},
		DetectionAssert: contract.DetectionAssertion{
			Status: "not_evaluated", Reason: "Bound to a customer API with no detection integration.",
		},
		SideEffectClass: "READ_ONLY",
		Evidence:        []string{"sanitized_request", "sanitized_response"},
	}
}

// scenarioForProperty builds the property-level read check: the owner reads their own object (the baseline), then reads it again and
// the response is checked for values the owner should never receive. A clean 2xx is the pass, because the request is meant to succeed.
func scenarioForProperty(n int, op openapi.Operation, p PropertySpec, objID, path string) contract.Scenario {
	id := fmt.Sprintf("API-BAS-AUTHZ-%03d", n)
	objective := fmt.Sprintf("%s reads their own object through %s and looks for properties they should not receive.", p.Owner, op.Key())
	return contract.Scenario{
		ID:              id,
		Name:            fmt.Sprintf("Bound: %s's own response from %s carries no forbidden property", p.Owner, op.Key()),
		Category:        "AUTHZ",
		Claim:           "property_level",
		AttackObjective: objective,
		ThreatModel: contract.ThreatModel{
			Attacker: "an authenticated identity of the customer's API reading its own object", Identity: p.Owner,
			AccessLevel: "valid credential supplied by the customer, owning the requested object", Objective: objective,
		},
		Preconditions: contract.Preconditions{Fixture: FixtureName, Identities: []string{p.Owner}, Object: objID},
		Steps: []contract.Step{
			{ID: "baseline-owner", Role: "baseline", Identity: p.Owner, Auth: "valid", Method: "GET", Path: path,
				Hypothesis: "The owner reads their own object. If this fails, the scenario is not testable."},
			{ID: "attack-read-own-object", Role: "attack", Identity: p.Owner, Auth: "valid", Method: "GET", Path: path,
				Hypothesis: "The owner's response carries none of the forbidden property values."},
		},
		CleanIsEnforced: true,
		ForbiddenValues: p.ForbiddenValues,
		ExpectedControl: "The API returns an object's allowed properties only. None of the forbidden property values supplied appears in the owner's response.",
		GroundTruth: contract.GroundTruth{
			Adapters: []string{"state", "response"},
			Check:    "The owner's response carries none of the forbidden values supplied. A property whose value was not supplied cannot be seen, so this is response evidence only.",
		},
		DetectionAssert: contract.DetectionAssertion{
			Status: "not_evaluated", Reason: "Bound to a customer API with no detection integration.",
		},
		SideEffectClass: "READ_ONLY",
		Evidence:        []string{"sanitized_request", "sanitized_response"},
	}
}

func scenarioFor(n int, op openapi.Operation, victim ObjectSpec, attacker, objID, path string) contract.Scenario {
	id := fmt.Sprintf("API-BAS-AUTHZ-%03d", n)
	objective := fmt.Sprintf("%s requests an object owned by %s through %s.", attacker, victim.Owner, op.Key())
	return contract.Scenario{
		ID:              id,
		Name:            fmt.Sprintf("Bound: %s cannot read %s's object through %s", attacker, victim.Owner, op.Key()),
		Category:        "AUTHZ",
		Claim:           "cross_identity",
		AttackObjective: objective,
		ThreatModel: contract.ThreatModel{
			Attacker: "an authenticated identity of the customer's API", Identity: attacker,
			AccessLevel: "valid credential supplied by the customer, owns none of the requested object", Objective: objective,
		},
		Preconditions: contract.Preconditions{Fixture: FixtureName, Identities: []string{attacker, victim.Owner}, Object: objID},
		Steps: []contract.Step{
			{ID: "baseline-owner", Role: "baseline", Identity: victim.Owner, Auth: "valid", Method: "GET", Path: path,
				Hypothesis: "The owner reads their own object. If this fails, the scenario is not testable."},
			{ID: "attack-other-identity", Role: "attack", Identity: attacker, Auth: "valid", Method: "GET", Path: path,
				Hypothesis: "Another identity's request for the owner's object is refused and returns none of the owner's protected values."},
		},
		DeniedStatuses:  []int{403, 404},
		ForbiddenValues: victim.ProtectedValues,
		ExpectedControl: "An identity cannot read an object it does not own. The request is refused and no protected value supplied for the object is returned.",
		GroundTruth: contract.GroundTruth{
			Adapters: []string{"state", "response"},
			Check:    "The response to the other identity's request carries none of the protected values supplied for the object. The target offers no independent state, so this is response evidence only.",
		},
		DetectionAssert: contract.DetectionAssertion{
			Status: "not_evaluated", Reason: "Bound to a customer API with no detection integration.",
		},
		SideEffectClass: "READ_ONLY",
		Evidence:        []string{"sanitized_request", "sanitized_response"},
	}
}

func scenarioForWrite(n int, op openapi.Operation, victim ObjectSpec, attacker, objID, path, readPath string) contract.Scenario {
	id := fmt.Sprintf("API-BAS-AUTHZ-%03d", n)
	objective := fmt.Sprintf("%s changes an object owned by %s through %s.", attacker, victim.Owner, op.Key())
	return contract.Scenario{
		ID:              id,
		Name:            fmt.Sprintf("Bound: %s cannot change %s's object through %s", attacker, victim.Owner, op.Key()),
		Category:        "AUTHZ",
		Claim:           "cross_identity",
		AttackObjective: objective,
		ThreatModel: contract.ThreatModel{
			Attacker: "an authenticated identity of the customer's API", Identity: attacker,
			AccessLevel: "valid credential supplied by the customer, owns none of the object it tries to change", Objective: objective,
		},
		Preconditions: contract.Preconditions{Fixture: FixtureName, Identities: []string{attacker, victim.Owner}, Object: objID},
		Steps: []contract.Step{
			{ID: "baseline-owner", Role: "baseline", Identity: victim.Owner, Auth: "valid", Method: "GET", Path: readPath,
				Hypothesis: "The owner reads their own object. If this fails, the scenario is not testable."},
			{ID: "attack-other-identity", Role: "attack", Identity: attacker, Auth: "valid", Method: op.Method, Path: path, Body: victim.Write.AttackBody,
				Hypothesis: "Another identity's write to the owner's object is refused, and the object the owner reads back is unchanged."},
		},
		DeniedStatuses:  []int{403, 404},
		ForbiddenValues: victim.ProtectedValues,
		ExpectedControl: "An identity cannot change an object it does not own. The request is refused and the owner's object, read back through its own read route, is unchanged.",
		GroundTruth: contract.GroundTruth{
			Adapters: []string{"state", "response"},
			Check:    "The owner's object, read back as the owner before and after the other identity's write, is identical apart from the fields listed as ignored. A change to anything that read route does not return cannot be seen.",
		},
		DetectionAssert: contract.DetectionAssertion{
			Status: "not_evaluated", Reason: "Bound to a customer API with no detection integration.",
		},
		SideEffectClass: "STATE_CHANGE_SANDBOX",
		Cleanup:         []string{"The owner sends the supplied restore request, before the run and again after, to put the object back to the supplied state."},
		Evidence:        []string{"sanitized_request", "sanitized_response"},
	}
}
