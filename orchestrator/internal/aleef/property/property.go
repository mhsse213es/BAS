// Package property is the generator-side security property library. A
// property is data plus a small amount of generation logic: it inspects one
// operation of the application model and emits Templates, each of which a
// later task assembles into a contract.Scenario. A Template is not a
// scenario: it carries no scenario id, category or reporting metadata.
//
// Properties are general. They talk about resources, owners, approvals,
// transitions and limits, never about a particular application's domain.
//
// Conventions shared by every property:
//
//   - The single fixture object under test is addressed with the runner's
//     "{object}" path token. Identifiers that must appear in a body or header
//     are written literally from the fixture.
//   - Baseline steps are always a read (GET) by the object's owner, because
//     the runner requires the baseline to return 200 for that owner.
//   - Only the final attack step is graded. Multi-step flows put earlier
//     actions in setup steps; an approval by a second identity is a co_actor
//     step so that its outcome never ends the chain.
//   - The contract supports GET, PATCH, POST and DELETE only. Operations with
//     other methods (for example PUT) produce no templates.
//   - Output is deterministic: accounts, objects, operations and fields are
//     visited in sorted order.
//
// # Verdicts, soft failures and operator declarations
//
// The runner and grader decide FAIL/PASS from three signals: a protected
// value (the fixture canary) in an attack response, any change between the
// state snapshot taken before and after the attack, and the count of attack
// responses outside denied_statuses. They cannot express every property's
// oracle, so each Template names the oracle that is authoritative for it
// (Template.Oracle, OracleKind) and says which of the runner's own signals to
// believe (RunnerLeakValid, RunnerStateValid). The documentation of each
// OracleKind states exactly what Task 8 must do. Task 8 must not read the
// runner's FAIL/PASS as the verdict unless Oracle is OracleRunnerGrade.
//
// Soft failures. A 2xx response whose JSON body has an "error" key, status
// "error" or success false is a refusal in practice. IsSoftFailure
// implements that rule and Template.Denied applies it with DeniedStatuses.
// The runner cannot see response bodies when counting accepted attempts, so
// under a soft failure: leak and state oracles are unaffected (a refusal
// leaks nothing and changes nothing, so the grade is SKIPPED/inconclusive,
// not FAIL); but the count-based oracles (OracleRepeatAccepted,
// OracleAcceptedOverLimit) see the soft failure as accepted and the runner
// grade can be a false FAIL. For those two kinds Task 8 must recount with
// Template.AcceptedCount / Denied on the recorded exchanges, which is why
// they are never decided by the runner grade.
//
// Owner-acting templates. The runner counts a protected value in an attack
// response as a leak even when the caller owns the object. Every template in
// which the actor is the owner of Preconditions.Object (all property_level and
// function_level templates) has RunnerLeakValid false: a canary in that
// response is not a finding and Task 8 must ignore the runner's leak signal.
// Cross-identity templates have RunnerLeakValid true. In the OWN-3 variants
// where the attacker names its own object in the path, the scanned canary is
// still the victim's, so a leak there remains a finding.
//
// Operator declarations. Several properties need knowledge a description
// cannot carry; without it they emit no templates:
//
//   - TemplateCtx.Workflow: the object lifecycle (P-AUTH-1/2, P-MC-1,
//     P-STATE-1/2).
//   - TemplateCtx.ReservedRoles (and Model.Roles, lowest first): which
//     operations need which role (P-ROLE-1).
//   - TemplateCtx.Limits: how many concurrent successes a reversible
//     operation may have (P-RACE-1; operations classified money or notifying
//     default to one).
//
// Controls. A finding may be marked verified only if two controls pass next
// to it, against the same application, fixture and accounts:
//
//   - OwnerControl: the single graded request is the legitimate actor doing
//     the legitimate thing. Expectation: running it through the executor
//     gives Verdict Finding=No AND GradedSuccess is true for the final step's
//     responses (ExpectSuccess). Failing means the environment or plumbing is
//     broken, not that the application is safe.
//   - NegativeControl: the same shape as the test with the violating element
//     removed, which a correct application must allow. Expectation: Verdict
//     Finding=No (inconclusive counts as a failed control) and, because the
//     application must allow it, GradedSuccess is true as well.
//
// The owner control uses OracleForbiddenValues with CleanIsEnforced: the
// verdict is No when the final response is a clean 2xx (or a refusal), and the
// runner's leak and state signals are ignored (a legitimate write changes
// state, an owner sees its own canary). It is the plumbing check; the
// ExpectSuccess check is what turns a refusal into a failed control.
//
// Oracle selectivity. A negative control must show that the test's oracle does
// not fire on everything. Two mechanisms:
//
//   - Same-oracle negative control (sameOracleNegative): P-AUTH-1, P-AUTH-2,
//     P-MC-1, P-STATE-1 (OracleStateChange), P-ROLE-1 (OracleStateChange for
//     writes, OracleRepeatAccepted for reads), P-IDEM-1/2
//     (OracleStateChangeOnReplay) and P-RACE-1 (OracleAcceptedOverLimit). The
//     negative control is judged by the same Oracle, DeniedStatuses,
//     SoftFailure, MaxAccepted and limit as the test, but its final graded
//     step is a request a correct application must allow without the
//     violating effect: a read of the object, or at most the limit of
//     requests. Setup and co-actor steps before it stay as in the test. The
//     oracle compares the state snapshot taken just before the final step
//     with the one just after it, so setup writes are outside the window.
//     Expectation: Verdict No. If a correct application perturbs state on
//     every request (a hit counter, a last-seen field), the state oracle fires
//     on the read too and the negative control is not No: do not verify. Count
//     oracles are immune to such noise by construction; their negative control
//     shows the count rule accepts a request within the limit. A negative
//     control that coincides with its owner control (P-RACE-1 with a limit of
//     one) carries Params["control"] = "shared" on both.
//   - Forbidden-value signal: P-OWN-1/2/3 and P-ROLE-2 (the victim's customer
//     id and protected values) and P-STATE-2 (the success values). The
//     negative control uses OracleForbiddenValues over the same values with a
//     request that must not expose them.
//
// The per-property rule is written next to each builder:
//
//	P-OWN-1/2/3  owner acts on own object / attacker acts on attacker's own
//	             object (DELETE operations are replaced by a read, so the
//	             control never destroys the fixture)
//	P-ROLE-1     privileged role performs the reserved operation / the
//	             unprivileged identity performs a non-reserved read
//	P-ROLE-2     owner uses the route under test (intentionally the route
//	             being tested, not its current-version peer: it proves that
//	             route works for its owner) / attacker uses it on its own object
//	P-AUTH-1     approval then execute / approval then a read
//	P-AUTH-2     owner modifies before any approval / approval then a read
//	P-MC-1       a distinct approver approves / the owner reads its object
//	P-IDEM-1/2   single request / the first request then a read, no replay
//	P-STATE-1    legitimate transition (execute) / reverse then a read
//	P-STATE-2    reverse succeeds / status read of an unreversed object
//	P-RACE-1     one request / at most the limit of concurrent requests
//
// A template whose controls cannot be built (no suitable account or object)
// is not emitted.
//
// Method limitation. The contract supports GET, PATCH, POST and DELETE only;
// operations with other methods (for example PUT) produce no templates.
package property

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// Property generates test templates for one security property.
type Property interface {
	ID() string
	Class() string
	// Applies is the operation-level necessary condition. A true result does
	// not guarantee templates: Templates may still return none when the
	// fixture, identities or operator declarations are insufficient.
	Applies(op model.Operation, m model.Model) bool
	Templates(ctx TemplateCtx) []Template
}

// Template is one generated test, before it becomes a scenario.
type Template struct {
	Property    string
	Description string
	// Claim is the contract claim the steps depend on (cross_identity,
	// property_level, function_level or authentication).
	Claim         string
	Steps         []contract.Step
	Preconditions contract.Preconditions
	// MaxAccepted is contract max_accepted_attempts (zero when the attack is
	// not repeated).
	MaxAccepted     int
	DeniedStatuses  []int
	ForbiddenValues []string
	// Params records what produced the template (operation, identities,
	// field location, group), for reporting and the novelty check.
	Params map[string]string
	// SideEffect is the contract side-effect class derived from the steps.
	SideEffect string
	// CleanIsEnforced marks templates where a 2xx with no leak and no state
	// change is the correct behaviour (contract clean_is_enforcement). The
	// assembler must then list the response adapter in the ground truth.
	CleanIsEnforced bool
	// SoftFailure is true when a 2xx soft-failure body counts as denied.
	SoftFailure bool
	// Oracle names the authoritative verdict rule (see OracleKind).
	Oracle OracleKind
	// RunnerLeakValid is false when the runner's protected-value (canary)
	// finding must be ignored: the actor owns the object, so seeing its own
	// canary is not a leak.
	RunnerLeakValid bool
	// RunnerStateValid is false when the runner's state-change finding must be
	// ignored: a permitted success changes state too (P-RACE-1).
	RunnerStateValid bool
	// ExpectSuccess is set on control templates only: every graded exchange
	// (every response to the final step) must be a real success, that is 2xx
	// and not a soft failure (see GradedSuccess).
	ExpectSuccess bool
	// OwnerControl and NegativeControl are the verifier's controls. Every
	// template produced by a property carries both; controls themselves carry
	// neither. See the "Controls" section of the package documentation.
	OwnerControl    *Template
	NegativeControl *Template
}

// OracleKind says which rule decides a template's verdict, and so what the
// consumer of the runner's report (Task 8) must do. Inputs for every kind:
// the recorded runner exchanges of the attack step(s) (status, body), the
// state diff between the snapshot before and after the attack, and the
// Template fields. Output: finding yes / no / inconclusive.
type OracleKind string

const (
	// OracleRunnerGrade: the runner/grade verdict is authoritative. FAIL with
	// exploited = finding; PASS = no finding; SKIPPED/ERROR = inconclusive.
	// Used by cross-identity templates (P-OWN-1/2/3, P-ROLE-2), where a
	// canary or owner-id leak, or a state change, is exactly the finding.
	// RunnerLeakValid and RunnerStateValid are both true.
	OracleRunnerGrade OracleKind = "runner_grade"

	// OracleStateChange: the finding is a state change caused by the attack
	// step (P-ROLE-1 writes, P-AUTH-1/2, P-MC-1, P-STATE-1). Task 8: yes if
	// the runner reports the state diff as non-empty (grade FAIL), ignoring
	// any leak signal (RunnerLeakValid is false). A refusal (status in
	// DeniedStatuses, or Template.Denied) with no state change is no finding.
	// A 2xx with no change is no finding only when CleanIsEnforced is set (a
	// negative control). Anything else is inconclusive.
	OracleStateChange OracleKind = "state_change"

	// OracleRepeatAccepted: the finding is two accepted responses to a
	// repeated attack (P-ROLE-1 reads, which have no state to diff). Task 8:
	// count attack exchanges with Template.AcceptedCount; yes if the count is
	// greater than MaxAccepted (the runner grade is only a hint because it
	// counts a 2xx soft failure as accepted); no if at most MaxAccepted;
	// inconclusive on any 5xx or transport error. Ignore leak signals.
	OracleRepeatAccepted OracleKind = "repeat_accepted"

	// OracleStateChangeOnReplay: the finding is that the replayed request
	// (last step) changed the state snapshot taken just before it
	// (P-IDEM-1/2: a second record or change). Task 8: yes if the runner
	// reports a state change on the attack; no if the attack was refused or
	// returned 2xx with no state change (CleanIsEnforced); inconclusive
	// otherwise. Ignore leak signals. The lab must be reset between runs
	// because the idempotency key is fixed.
	OracleStateChangeOnReplay OracleKind = "state_change_on_replay"

	// OracleAcceptedOverLimit: the finding is more accepted attack responses
	// than the limit (P-RACE-1). Task 8: ignore the runner's FAIL/PASS
	// entirely (RunnerStateValid and RunnerLeakValid are false); compute
	// Template.ExceedsLimit over the attack exchanges (all exchanges after the
	// baseline): true = finding, false = no finding; inconclusive on any 5xx
	// or transport error.
	OracleAcceptedOverLimit OracleKind = "accepted_over_limit"

	// OracleForbiddenValues: the finding is a forbidden value (for example a
	// success status word) in the final attack response (P-STATE-2). Task 8:
	// yes if any of ForbiddenValues appears at any depth of the attack
	// response body (the runner reports this as forbidden-value exploitation,
	// grade FAIL); no if the response is 2xx and contains none
	// (CleanIsEnforced); a refusal of the setup step is no finding; ignore the
	// runner's canary-leak signal (RunnerLeakValid is false).
	OracleForbiddenValues OracleKind = "forbidden_values"
)

// TemplateCtx is everything a property may look at for one operation.
type TemplateCtx struct {
	Op         model.Operation
	Model      model.Model
	Fixture    fixture.Fixture
	Identities []model.Account
	// Workflow is the optional operator-declared flow description used by the
	// flow properties. Without it they return no templates.
	Workflow *Workflow
	// ReservedRoles maps an operation id to the minimum role allowed to call
	// it. Roles are ranked by their position in Model.Roles, lowest first.
	ReservedRoles map[string]string
	// Limits maps an operation id to how many concurrent requests may
	// legitimately succeed. The default is one (a once-only action).
	Limits map[string]int
	// OnMissing, when set, is called once for every candidate test that is
	// not produced because an account has no fixture object of the given
	// resource type.
	OnMissing func(resourceType string)
}

func (c TemplateCtx) missing(t string) {
	if c.OnMissing != nil && t != "" {
		c.OnMissing(t)
	}
}

// All returns every property in specification order.
func All() []Property {
	return []Property{
		own1{meta{"P-OWN-1", "OWN"}}, own2{meta{"P-OWN-2", "OWN"}}, own3{meta{"P-OWN-3", "OWN"}},
		role1{meta{"P-ROLE-1", "ROLE"}}, role2{meta{"P-ROLE-2", "ROLE"}},
		auth1{meta{"P-AUTH-1", "AUTH"}}, auth2{meta{"P-AUTH-2", "AUTH"}},
		mc1{meta{"P-MC-1", "MC"}},
		idem1{meta{"P-IDEM-1", "IDEM"}}, idem2{meta{"P-IDEM-2", "IDEM"}},
		state1{meta{"P-STATE-1", "STATE"}}, state2{meta{"P-STATE-2", "STATE"}},
		race1{meta{"P-RACE-1", "RACE"}},
	}
}

type meta struct{ id, class string }

func (m meta) ID() string    { return m.id }
func (m meta) Class() string { return m.class }

// objToken is the runner's placeholder for the fixture object's id.
const objToken = "{object}"

// Denied status sets. Authorization refusals are narrow so that a validation
// error is not mistaken for an ownership check; rule refusals (workflow,
// idempotency, limits) legitimately use conflict and validation codes.
func deniedAuthz() []int { return []int{401, 403, 404} }
func deniedRule() []int  { return []int{400, 401, 403, 404, 405, 409, 412, 422, 429} }

// IsSoftFailure reports whether a 2xx response is a refusal in disguise: its
// JSON object body has a non-null "error" key, "status" equal to "error",
// or "success" equal to false.
func IsSoftFailure(status int, body []byte) bool {
	if status < 200 || status > 299 {
		return false
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	if v, ok := doc["error"]; ok && v != nil && v != false {
		return true
	}
	if s, ok := doc["status"].(string); ok && strings.EqualFold(s, "error") {
		return true
	}
	if b, ok := doc["success"].(bool); ok && !b {
		return true
	}
	return false
}

// Denied reports whether a response counts as a refusal for this template:
// its status is in DeniedStatuses, or SoftFailure is set and the response is
// a soft failure.
func (t Template) Denied(status int, body []byte) bool {
	for _, d := range t.DeniedStatuses {
		if d == status {
			return true
		}
	}
	return t.SoftFailure && IsSoftFailure(status, body)
}

// idName mirrors the importer's rule for identifier-like names.
var idName = regexp.MustCompile(`(?i)(^id$|_id$|Id$|ref$|number$)`)

// ---- accounts, objects and pairs ----

func sortedAccounts(ctx TemplateCtx) []model.Account {
	var out []model.Account
	for _, a := range ctx.Identities {
		if _, ok := ctx.Fixture.Identity(a.Name); ok {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type pair struct {
	victim, attacker model.Account
	obj              fixture.Object
}

// pairs lists every ordered (victim with an object, other-customer attacker).
func pairs(ctx TemplateCtx) []pair {
	accts := sortedAccounts(ctx)
	var out []pair
	for _, v := range accts {
		objs := ownedOfType(ctx.Fixture, v, primaryType(ctx, ctx.Op))
		if len(objs) == 0 {
			for _, a := range accts {
				if a.CustomerID != v.CustomerID {
					ctx.missing(primaryType(ctx, ctx.Op))
				}
			}
			continue
		}
		for _, a := range accts {
			if a.CustomerID != v.CustomerID {
				out = append(out, pair{victim: v, attacker: a, obj: objs[0]})
			}
		}
	}
	return out
}

// ownersWithObject returns accounts that own an object, filtered by role
// when role is not empty. victim and attacker are the same account.
func ownersWithObject(ctx TemplateCtx, role string) []pair {
	var out []pair
	for _, a := range sortedAccounts(ctx) {
		if role != "" && a.Role != role {
			continue
		}
		if objs := ownedOfType(ctx.Fixture, a, primaryType(ctx, ctx.Op)); len(objs) > 0 {
			out = append(out, pair{victim: a, attacker: a, obj: objs[0]})
		} else {
			ctx.missing(primaryType(ctx, ctx.Op))
		}
	}
	return out
}

func confidence(o fixture.Object) string {
	if o.Protected["canary"] != "" {
		return "canary"
	}
	return "structural"
}

// leakValues is the response-side oracle for reads of another owner's object:
// the owner's customer id (the canary is matched by the runner itself).
func leakValues(victim model.Account) []string {
	if len(victim.CustomerID) >= 4 {
		return []string{victim.CustomerID}
	}
	return nil
}

// ---- request building ----

type idRef struct {
	loc  string // path, query or body
	name string
	path []string // body location
}

func (r idRef) key() string {
	if r.loc == "body" {
		return "body:" + strings.Join(r.path, ".")
	}
	return r.loc + ":" + r.name
}

func hasPathID(op model.Operation) bool {
	for _, p := range op.PathParams {
		if p.IsObjectID {
			return true
		}
	}
	return false
}

// idRefsOf lists the identifier-bearing fields of an operation: path, then
// query, then body (nested, sorted).
func idRefsOf(op model.Operation) []idRef {
	var out []idRef
	for _, p := range op.PathParams {
		if p.IsObjectID {
			out = append(out, idRef{loc: "path", name: p.Name})
		}
	}
	for _, p := range op.QueryParams {
		if p.IsObjectID {
			out = append(out, idRef{loc: "query", name: p.Name})
		}
	}
	var walk func(s *model.Schema, prefix []string, depth int)
	walk = func(s *model.Schema, prefix []string, depth int) {
		if s == nil || depth > 4 {
			return
		}
		for _, n := range s.PropertyNames() {
			p := s.Properties[n]
			path := append(append([]string{}, prefix...), n)
			switch {
			case p == nil:
			case len(p.Properties) > 0:
				walk(p, path, depth+1)
			case p.Type == "string" && len(p.Enum) == 0 && idName.MatchString(n):
				out = append(out, idRef{loc: "body", name: n, path: path})
			}
		}
	}
	walk(op.Body, nil, 0)
	return out
}

func hasNonPathID(op model.Operation) bool {
	for _, r := range idRefsOf(op) {
		if r.loc != "path" {
			return true
		}
	}
	return false
}

// buildRequest renders the path (with query) and body for an operation.
// vals overrides identifier fields by idRef key; everything else is a
// deterministic sample. variant shifts sampled values (used to make a
// different body).
func buildRequest(op model.Operation, vals map[string]string, variant int) (string, string) {
	path := op.Path
	for _, p := range op.PathParams {
		v, ok := vals["path:"+p.Name]
		if !ok {
			v = fmt.Sprint(sampleValue(p.Schema, p.Name, 0))
		}
		path = strings.ReplaceAll(path, "{"+p.Name+"}", v)
	}
	var q []string
	qp := append([]model.Param{}, op.QueryParams...)
	sort.Slice(qp, func(i, j int) bool { return qp[i].Name < qp[j].Name })
	for _, p := range qp {
		v, ok := vals["query:"+p.Name]
		if !ok {
			if !p.Required {
				continue
			}
			v = fmt.Sprint(sampleValue(p.Schema, p.Name, 0))
		}
		if v != objToken {
			v = url.QueryEscape(v)
		}
		q = append(q, url.QueryEscape(p.Name)+"="+v)
	}
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}
	if op.Method != "POST" && op.Method != "PATCH" {
		return path, ""
	}
	if op.Body == nil {
		return path, "{}"
	}
	raw, _ := json.Marshal(sampleObject(op.Body, nil, vals, variant, 0))
	return path, string(raw)
}

func sampleObject(s *model.Schema, prefix []string, vals map[string]string, variant, depth int) map[string]any {
	out := map[string]any{}
	if s == nil || depth > 4 {
		return out
	}
	for _, n := range s.PropertyNames() {
		p := s.Properties[n]
		path := append(append([]string{}, prefix...), n)
		if v, ok := vals["body:"+strings.Join(path, ".")]; ok {
			out[n] = v
			continue
		}
		if p != nil && len(p.Properties) > 0 {
			out[n] = sampleObject(p, path, vals, variant, depth+1)
			continue
		}
		out[n] = sampleValue(p, n, variant)
	}
	return out
}

func sampleValue(s *model.Schema, name string, variant int) any {
	if s == nil {
		return "sample"
	}
	if len(s.Enum) > 0 {
		return s.Enum[variant%len(s.Enum)]
	}
	switch s.Type {
	case "integer", "number":
		base := 1.0
		if s.Minimum != nil && *s.Minimum > base {
			base = *s.Minimum
		}
		v := base + float64(variant)
		if s.Maximum != nil && v > *s.Maximum {
			v = base
			if variant > 0 && base-float64(variant) >= valueOr(s.Minimum, base-float64(variant)) {
				v = base - float64(variant)
			}
		}
		if s.Type == "integer" {
			return int64(v)
		}
		return v
	case "boolean":
		return variant%2 == 1
	case "array":
		return []any{sampleValue(s.Items, name, variant)}
	case "object":
		return sampleObject(s, nil, nil, variant, 1)
	}
	switch s.Format {
	case "date-time":
		return "2026-01-01T00:00:00Z"
	case "date":
		return "2026-01-01"
	case "uuid":
		return "00000000-0000-4000-8000-000000000001"
	case "email":
		return "aleef@example.com"
	}
	v := "sample"
	if idName.MatchString(name) {
		v = "aleef-none"
	}
	if variant > 0 {
		v += fmt.Sprintf("-v%d", variant)
	}
	if s.MinLength != nil {
		for len(v) < *s.MinLength {
			v += "x"
		}
	}
	return v
}

func valueOr(p *float64, def float64) float64 {
	if p == nil {
		return def
	}
	return *p
}

// ownerHint matches identifier names that refer to a principal (owner,
// customer, tenant, user, holder, member) rather than to a resource.
var ownerHint = regexp.MustCompile(`(?i)(owner|customer|tenant|user|holder|member)`)

// principalRef reports whether a body field names a principal. Such a field
// (mass assignment of ownership) is filled with the victim's customer id; the
// other identifier fields get the object id.
func principalRef(r idRef) bool {
	return r.loc == "body" && ownerHint.MatchString(r.name)
}

// victimVals assigns the fixture object to every identifier field, and the
// object's owner to principal-naming body fields.
func victimVals(ctx TemplateCtx, op model.Operation, obj fixture.Object) map[string]string {
	vals := map[string]string{}
	for _, r := range idRefsOf(op) {
		vals[r.key()] = resolveRef(ctx, op, r, obj, true)
	}
	return vals
}

// literalVals is victimVals with every identifier written literally. A
// baseline names the owner's object of ITS operation's type, which need not be
// the test's "{object}", so it never uses the token.
func literalVals(ctx TemplateCtx, op model.Operation, obj fixture.Object) map[string]string {
	vals := map[string]string{}
	for _, r := range idRefsOf(op) {
		vals[r.key()] = resolveRef(ctx, op, r, obj, false)
	}
	return vals
}

// ---- steps and baselines ----

func mkStep(id, role, identity, method, path, body, hypothesis string) contract.Step {
	return contract.Step{ID: id, Role: role, Identity: identity, Auth: "valid", Method: method, Path: path, Body: body, Hypothesis: hypothesis}
}

func mutating(method string) bool { return method != "GET" }

func supportedMethod(m string) bool {
	return m == "GET" || m == "PATCH" || m == "POST" || m == "DELETE"
}

// sideEffectOf derives the contract class from the steps.
func sideEffectOf(steps []contract.Step) string {
	for _, s := range steps {
		if mutating(s.Method) {
			return "STATE_CHANGE_SANDBOX"
		}
	}
	return "READ_ONLY"
}

// baselineStep returns the owner's legitimate read of the object. A GET
// target is its own baseline; otherwise the best related GET operation is
// used (same path first, then the longest shared path prefix).
func baselineStep(ctx TemplateCtx, target model.Operation, owner model.Account, selfOK bool) (contract.Step, bool) {
	hyp := "The owner can read their own object. If this fails, the test is not applicable."
	if selfOK && target.Method == "GET" && requiredQueryOnlyIDs(target) {
		p, _ := buildRequest(target, literalVals(ctx, target, objectFor(ctx, owner, target)), 0)
		return mkStep("baseline-owner-read", "baseline", owner.Name, "GET", p, "", hyp), true
	}
	var best *model.Operation
	bestScore := -1
	for i := range ctx.Model.Operations {
		c := &ctx.Model.Operations[i]
		if c.Method != "GET" || c.Body != nil || !requiredQueryOnlyIDs(*c) || (!selfOK && c.ID == target.ID) {
			continue
		}
		score := sharedSegments(c.Path, target.Path)*4 + len(c.PathParams)
		if c.Path == target.Path {
			score += 100
		}
		if score > bestScore || (score == bestScore && best != nil && c.ID < best.ID) {
			best, bestScore = c, score
		}
	}
	if best == nil {
		return contract.Step{}, false
	}
	p, _ := buildRequest(*best, literalVals(ctx, *best, objectFor(ctx, owner, *best)), 0)
	return mkStep("baseline-owner-read", "baseline", owner.Name, "GET", p, "", hyp), true
}

// requiredQueryOnlyIDs reports whether every required query parameter is an
// identifier (so that the object token can fill it).
func requiredQueryOnlyIDs(op model.Operation) bool {
	for _, p := range op.QueryParams {
		if p.Required && !p.IsObjectID {
			return false
		}
	}
	return true
}

func sharedSegments(a, b string) int {
	as, bs := strings.Split(strings.Trim(a, "/"), "/"), strings.Split(strings.Trim(b, "/"), "/")
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] && !strings.HasPrefix(as[n], "{") {
		n++
	}
	return n
}

// baselineOrSelf is baselineStep, falling back to the operation itself when
// it is a non-DELETE write (a DELETE baseline would destroy the object).
func baselineOrSelf(ctx TemplateCtx, op model.Operation, owner model.Account, obj fixture.Object) (contract.Step, bool) {
	if b, ok := baselineStep(ctx, op, owner, true); ok {
		return b, true
	}
	if op.Method == "DELETE" || op.Method == "GET" {
		return contract.Step{}, false
	}
	p, body := buildRequest(op, victimVals(ctx, op, obj), 0)
	return mkStep("baseline-owner-call", "baseline", owner.Name, op.Method, p, body,
		"The owner can perform the operation on their own object. If this fails, the test is not applicable."), true
}

// finish fills the fields every template shares.
func finish(ctx TemplateCtx, t Template, obj fixture.Object, prop, claim string) Template {
	t.Property, t.Claim, t.SoftFailure = prop, claim, true
	// Defaults: the runner's leak signal is valid only when the actor is not
	// the object's owner; the state signal is valid unless a property clears it.
	t.RunnerLeakValid = claim == "cross_identity"
	t.RunnerStateValid = true
	var ids []string
	seen := map[string]bool{}
	for _, s := range t.Steps {
		if s.Identity != "anonymous" && !seen[s.Identity] {
			seen[s.Identity] = true
			ids = append(ids, s.Identity)
		}
	}
	t.Preconditions = contract.Preconditions{Fixture: ctx.Fixture.Name, Identities: ids, Object: obj.ID}
	t.SideEffect = sideEffectOf(t.Steps)
	return t
}

func opByID(m model.Model, id string) (model.Operation, bool) {
	for _, o := range m.Operations {
		if o.ID == id {
			return o, true
		}
	}
	return model.Operation{}, false
}
