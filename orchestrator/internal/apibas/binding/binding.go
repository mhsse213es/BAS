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
	"errors"
	"fmt"
	"regexp"
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
}

// Spec is the customer-supplied test data.
type Spec struct {
	Identities []IdentitySpec `json:"identities"`
	Objects    []ObjectSpec   `json:"objects"`
}

// Bound describes one generated scenario.
type Bound struct {
	ScenarioID string `json:"scenario_id"`
	Operation  string `json:"operation"`
	Attacker   string `json:"attacker"`
	Victim     string `json:"victim"`
	Path       string `json:"path"`
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
}

// Limits states what a bound plan does not claim. It is part of every plan.
var planLimits = []string{
	"Only read-only object-level scenarios are bound. Operations that change state are skipped: the target offers no independent check that state did not change.",
	"A bound scenario is graded on the HTTP response alone. It proves the attack was refused and leaked none of the protected values supplied; it cannot see a leak of a value the customer did not supply.",
	"The scenarios have no detection integration (detection is not evaluated) and no regulatory mapping.",
	"An operation passes only for the objects and identities supplied. It says nothing about other objects, roles or parameters.",
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
	if len(s.Objects) == 0 {
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
	return nil
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
	plan := &Plan{Fixture: fixture.Fixture{Name: FixtureName}, Limits: planLimits, Bound: []Bound{}, Skipped: []Skipped{}}
	for _, id := range spec.Identities {
		plan.Fixture.Identities = append(plan.Fixture.Identities, fixture.Identity{Name: id.Name, CustomerID: id.Name, TokenRef: id.CredentialRef})
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
		if reason := unbindable(op, objs); reason != "" {
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
			sc := scenarioFor(next, op, victim, attacker, objID, resolvePath(op, victim.Params))
			if err := sc.Validate(); err != nil {
				return nil, fmt.Errorf("binding: generated scenario is invalid (a binder bug): %w", err)
			}
			plan.Scenarios = append(plan.Scenarios, sc)
			plan.Bound = append(plan.Bound, Bound{ScenarioID: sc.ID, Operation: op.Key(), Attacker: attacker, Victim: victim.Owner, Path: sc.Steps[1].Path})
			next++
		}
	}
	if len(plan.Scenarios) == 0 && len(plan.Skipped) == 0 {
		return nil, errors.New("binding: nothing in the inventory can be bound to the objects supplied")
	}
	return plan, nil
}

// unbindable returns why an operation cannot be bound, or "" when it can.
func unbindable(op openapi.Operation, objs []ObjectSpec) string {
	switch {
	case op.Method != "GET":
		return "it changes state, and the target offers no independent check that state did not change, so it cannot be bound yet"
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
