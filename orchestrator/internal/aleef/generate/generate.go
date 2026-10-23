// Package generate turns the application model, the fixture and the property
// library into contract scenarios. Output is deterministic: the same input and
// seed give byte-identical results. The seed only decides which variation
// tests survive a MaxTests cut and in what order they appear; it never changes
// which ids a given variation produces.
//
// The generator applies exactly one safety filter: operations whose class is
// not read, setup_safe or reversible (unknown, money, notifying) produce no
// tests. They only generate once the operator has classified them. Beyond
// that the generator decides nothing about safety.
package generate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/novelty"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// Test is one generated test.
type Test struct {
	ID       string
	Scenario contract.Scenario
	// Template is the property template the scenario was assembled from. It
	// carries the typed oracle fields the executor needs to read the verdict.
	Template property.Template
	Property string
	Params   map[string]string
	// Covered is true when the existing catalogue already tests the same
	// thing (see package novelty).
	Covered bool
	// OwnerControl and NegativeControl are the verifier's controls (see the
	// "Controls" section of package property), assembled as full tests with
	// ids <ID>-OC and <ID>-NC. They are never top-level tests, never counted
	// toward MaxTests and never carry controls themselves. Variation tests
	// reuse the controls of the base template they were derived from: a
	// variation changes only the violating element of the attack, and the
	// controls prove the environment and the oracle against that same base.
	OwnerControl, NegativeControl *Test
	// ControlsBlocked is true when a control step is blocked by the safety
	// filter (or a control does not validate): the test carries no controls
	// and so can never be verified.
	ControlsBlocked bool
}

// Options controls generation.
type Options struct {
	Seed int64
	// MaxTests truncates the result to a stable prefix; zero means no limit.
	MaxTests int
	// Variations names the parameter mutations to apply on top of the base
	// tests (see AllVariations). Empty means base tests only.
	Variations []string

	// Operator declarations handed to the flow properties (see package
	// property).
	Workflow      *property.Workflow
	ReservedRoles map[string]string
	Limits        map[string]int

	// AllowedOps lists operations whose class is not runnable by default
	// (money, notifying) but which the engagement explicitly permits; the
	// caller derives it from the safety rules, generate never decides it.
	AllowedOps map[string]bool

	// Catalogue is the set of existing scenarios used for the novelty check.
	// Nil loads the embedded catalogue; an empty non-nil slice means nothing
	// is covered.
	Catalogue []contract.Scenario
}

// Report summarizes what a generation run did and did not do.
type Report struct {
	Operations int
	// SkippedByClass counts operations skipped for their class, keyed by the
	// class name ("unknown", "money", "notifying"). SkippedOps lists their ids.
	SkippedByClass map[string]int
	SkippedOps     []string
	// NoTemplates counts runnable operations for which no property applied or
	// produced a template.
	NoTemplates int
	BaseTests   int
	Variants    int
	// InvalidVariants counts variants dropped because they did not validate.
	InvalidVariants int
	// SkippedStepClass counts tests dropped because a step (baseline, setup or
	// attack) calls an operation that is not read, setup_safe or reversible;
	// SkippedStepUnknown counts tests dropped because a step matches no
	// operation of the model. Such tests are never emitted.
	SkippedStepClass, SkippedStepUnknown int
	// ControlsBlocked counts emitted tests left without controls (see
	// Test.ControlsBlocked). Controls do not count toward MaxTests.
	ControlsBlocked int
	// Truncated counts tests cut by MaxTests.
	Truncated int
	// NoFixture counts tests dropped because a step needs a fixture object
	// of a resource type the account does not have, keyed by resource type.
	// NoFixtureOps lists operations skipped outright because no account has
	// an object of their primary resource type (operation id -> type).
	// Such tests are never sent with a wrong id.
	NoFixture    map[string]int
	NoFixtureOps map[string]string
}

// NoFixtureReason is the human-readable reason for a resource type.
func NoFixtureReason(t string) string {
	return "no fixture object of resource type " + t
}

// Generate is GenerateWithReport without the report.
func Generate(m model.Model, fx fixture.Fixture, accts []model.Account, opt Options) ([]Test, error) {
	tests, _, err := GenerateWithReport(m, fx, accts, opt)
	return tests, err
}

func runnable(c model.OpClass) bool {
	return c == model.ClassRead || c == model.ClassSetupSafe || c == model.ClassReversible
}

// GenerateWithReport generates the tests and reports what was skipped.
func GenerateWithReport(m model.Model, fx fixture.Fixture, accts []model.Account, opt Options) ([]Test, Report, error) {
	rep := Report{SkippedByClass: map[string]int{}, NoFixture: map[string]int{}, NoFixtureOps: map[string]string{}}
	vars, err := resolveVariations(opt.Variations)
	if err != nil {
		return nil, rep, err
	}
	cat := opt.Catalogue
	if cat == nil {
		if cat, err = catalog.All(); err != nil {
			return nil, rep, fmt.Errorf("generate: load catalogue: %w", err)
		}
	}

	ops := append([]model.Operation(nil), m.Operations...)
	sort.Slice(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID })
	rep.Operations = len(ops)

	seen := map[string]bool{}
	var base, variants []Test
	vc := vctx{model: m, fx: fx, accts: accts}
	for _, op := range ops {
		if !runnable(op.Class) && !opt.AllowedOps[op.ID] {
			cls := string(op.Class)
			if cls == "" {
				cls = string(model.ClassUnknown)
			}
			rep.SkippedByClass[cls]++
			rep.SkippedOps = append(rep.SkippedOps, op.ID)
			continue
		}
		vc.op = op
		if t := property.PrimaryTypeOf(m, fx, op); t != "" {
			have := false
			for _, a := range accts {
				if _, ok := property.OwnedObject(fx, a, t); ok {
					have = true
					break
				}
			}
			if !have {
				rep.NoFixtureOps[op.ID] = t
				continue
			}
		}
		produced := false
		for _, p := range property.All() {
			if !p.Applies(op, m) {
				continue
			}
			ctx := property.TemplateCtx{
				Op: op, Model: m, Fixture: fx, Identities: accts,
				Workflow: opt.Workflow, ReservedRoles: opt.ReservedRoles, Limits: opt.Limits,
			}
			for _, tpl := range p.Templates(ctx) {
				tpl = clone(tpl)
				if tpl.Params == nil {
					tpl.Params = map[string]string{}
				}
				if tpl.Params["operation"] == "" {
					tpl.Params["operation"] = op.ID
				}
				if missing := unresolved(tpl); len(missing) > 0 {
					for _, t := range missing {
						rep.NoFixture[t]++
					}
					produced = true
					continue
				}
				if blocked := stepBlockWith(m, tpl.Steps, opt.AllowedOps); blocked != "" {
					rep.countBlocked(blocked)
					produced = true
					continue
				}
				t, err := assemble(tpl, op.ID, cat)
				if err != nil {
					return nil, rep, err
				}
				if seen[t.ID] {
					// The same property produced the same test twice: keep one.
					continue
				}
				seen[t.ID] = true
				attachControls(&t, m, tpl, opt.AllowedOps)
				base = append(base, t)
				produced = true
				for _, v := range vars {
					for _, vt := range v.fn(vc, tpl) {
						vt.Params["variation"] = v.name
						if blocked := stepBlockWith(m, vt.Steps, opt.AllowedOps); blocked != "" {
							rep.countBlocked(blocked)
							continue
						}
						t, err := assemble(vt, op.ID, cat)
						if err != nil {
							rep.InvalidVariants++
							continue
						}
						if seen[t.ID] {
							continue
						}
						seen[t.ID] = true
						attachControls(&t, m, vt, opt.AllowedOps)
						variants = append(variants, t)
					}
				}
			}
		}
		if !produced {
			rep.NoTemplates++
		}
	}
	sort.Strings(rep.SkippedOps)
	byID := func(ts []Test) func(i, j int) bool { return func(i, j int) bool { return ts[i].ID < ts[j].ID } }
	sort.Slice(base, byID(base))
	sort.Slice(variants, byID(variants))
	rng := rand.New(rand.NewSource(opt.Seed))
	rng.Shuffle(len(variants), func(i, j int) { variants[i], variants[j] = variants[j], variants[i] })
	rep.BaseTests, rep.Variants = len(base), len(variants)

	out := append(base, variants...)
	if opt.MaxTests > 0 && len(out) > opt.MaxTests {
		rep.Truncated = len(out) - opt.MaxTests
		out = out[:opt.MaxTests]
	}
	for _, t := range out {
		if t.ControlsBlocked {
			rep.ControlsBlocked++
		}
	}
	return out, rep, nil
}

func (r *Report) countBlocked(kind string) {
	if kind == blockedUnknown {
		r.SkippedStepUnknown++
	} else {
		r.SkippedStepClass++
	}
}

const (
	blockedClass   = "class"
	blockedUnknown = "unknown"
)

// stepBlock maps every step of a scenario back to the model's operations by
// effective method and path shape. It returns blockedUnknown when a step
// matches no operation, blockedClass when a step matches an operation that is
// not runnable, and "" when every step is safe to emit. A method-override
// header changes the effective method. A baseline that the property picked
// from a non-runnable operation therefore drops the test (it is not re-picked).
func stepBlock(m model.Model, steps []contract.Step) string {
	return stepBlockWith(m, steps, nil)
}

// unresolved lists the resource types a template (or either control) needs a
// fixture object for and does not have.
func unresolved(tpl property.Template) []string {
	set := map[string]bool{}
	for _, t := range property.UnresolvedTypes(tpl.Steps) {
		set[t] = true
	}
	for _, c := range []*property.Template{tpl.OwnerControl, tpl.NegativeControl} {
		if c != nil {
			for _, t := range property.UnresolvedTypes(c.Steps) {
				set[t] = true
			}
		}
	}
	var out []string
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func stepBlockWith(m model.Model, steps []contract.Step, allowed map[string]bool) string {
	result := ""
	for _, st := range steps {
		method := strings.ToUpper(st.Method)
		for k, v := range st.Headers {
			if strings.EqualFold(k, "X-HTTP-Method-Override") && v != "" {
				method = strings.ToUpper(v)
			}
		}
		path := trimQuery(st.Path)
		matched := false
		for _, op := range m.Operations {
			if op.Method != method || !pathMatches(op.Path, path) {
				continue
			}
			matched = true
			if !runnable(op.Class) && !allowed[op.ID] {
				result = blockedClass
			}
		}
		if !matched {
			return blockedUnknown
		}
	}
	return result
}

// testID is ALEEF-GEN-<property>-<hash8> where hash8 is the first 8 hex
// characters of sha256 over the property id, the operation id and the sorted
// parameters.
func testID(prop, op string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(prop))
	h.Write([]byte{0})
	h.Write([]byte(op))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k + "=" + params[k]))
	}
	return "ALEEF-GEN-" + prop + "-" + hex.EncodeToString(h.Sum(nil))[:8]
}

// attachControls assembles the template's controls onto t. If either control
// is missing, is blocked by the safety filter or does not validate, t carries
// no controls and is marked ControlsBlocked (Report.ControlsBlocked counts them
// among the tests finally emitted).
func attachControls(t *Test, m model.Model, tpl property.Template, allowed map[string]bool) {
	build := func(c *property.Template, suffix string) *Test {
		if c == nil || stepBlockWith(m, c.Steps, allowed) != "" {
			return nil
		}
		ct, err := assembleControl(*c, t.ID+suffix)
		if err != nil {
			return nil
		}
		return &ct
	}
	oc, nc := build(tpl.OwnerControl, "-OC"), build(tpl.NegativeControl, "-NC")
	if oc == nil || nc == nil {
		t.ControlsBlocked = true
		return
	}
	t.OwnerControl, t.NegativeControl = oc, nc
}

// assembleControl turns a control template into a validated test with the
// given id. The control's own controls (none) are not carried.
func assembleControl(tpl property.Template, id string) (Test, error) {
	// A within-limit control (at most MaxAccepted requests) cannot declare
	// max_accepted_attempts in the contract, which needs max < repeat. The
	// scenario omits it; the template keeps it, because the executor's oracle
	// reads the limit from the template.
	scen := tpl
	if last := tpl.Steps[len(tpl.Steps)-1]; tpl.MaxAccepted > 0 && last.Repeat <= tpl.MaxAccepted {
		scen.MaxAccepted = 0
	}
	t, err := assembleID(scen, id, nil, false)
	if err != nil {
		return Test{}, err
	}
	t.Template = tpl
	t.Scenario.ExpectedControl = "The legitimate request succeeds and the control's oracle does not fire (" + tpl.Property + " " + tpl.Params["control"] + " control)."
	if err := t.Scenario.Validate(); err != nil {
		return Test{}, fmt.Errorf("generate: %s: %w", id, err)
	}
	return t, nil
}

// assemble turns a template into a validated test.
func assemble(tpl property.Template, opID string, cat []contract.Scenario) (Test, error) {
	return assembleID(tpl, testID(tpl.Property, opID, tpl.Params), cat, true)
}

func assembleID(tpl property.Template, id string, cat []contract.Scenario, novel bool) (Test, error) {
	if len(tpl.Steps) == 0 {
		return Test{}, fmt.Errorf("generate: %s: template has no steps", id)
	}
	attacker := tpl.Steps[len(tpl.Steps)-1].Identity
	s := contract.Scenario{
		ID:              id,
		Name:            tpl.Property + ": " + tpl.Description,
		Category:        "ALEEF",
		Claim:           tpl.Claim,
		AttackObjective: tpl.Description,
		ThreatModel:     contract.ThreatModel{Attacker: attacker, Identity: attacker, Objective: tpl.Description},
		Preconditions:   tpl.Preconditions,
		Steps:           tpl.Steps,
		DeniedStatuses:  tpl.DeniedStatuses,
		ForbiddenValues: tpl.ForbiddenValues,
		CleanIsEnforced: tpl.CleanIsEnforced,
		ExpectedControl: "The application refuses the request and exposes or changes nothing (" + tpl.Property + ").",
		GroundTruth:     contract.GroundTruth{Adapters: []string{"state", "response"}},
		DetectionAssert: contract.DetectionAssertion{Status: "not_evaluated", Reason: "generated test; detection is not evaluated"},
		SideEffectClass: tpl.SideEffect,
	}
	s.MaxAcceptedAttempts = tpl.MaxAccepted
	if tpl.SideEffect == "STATE_CHANGE_SANDBOX" {
		s.Cleanup = []string{"reset"}
	}
	if err := s.Validate(); err != nil {
		return Test{}, fmt.Errorf("generate: %s: %w", id, err)
	}
	return Test{
		ID: id, Scenario: s, Template: tpl, Property: tpl.Property,
		Params:  copyMap(tpl.Params),
		Covered: novel && novelty.Covered(s, cat),
	}, nil
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// clone deep-copies a template so variations never alias their input.
func clone(t property.Template) property.Template {
	out := t
	out.Steps = make([]contract.Step, len(t.Steps))
	for i, s := range t.Steps {
		c := s
		if s.Headers != nil {
			c.Headers = copyMap(s.Headers)
		}
		c.ExtraHeaders = append([]contract.HeaderPair(nil), s.ExtraHeaders...)
		out.Steps[i] = c
	}
	out.Preconditions.Identities = append([]string(nil), t.Preconditions.Identities...)
	out.Preconditions.LabFaults = append([]string(nil), t.Preconditions.LabFaults...)
	out.DeniedStatuses = append([]int(nil), t.DeniedStatuses...)
	out.ForbiddenValues = append([]string(nil), t.ForbiddenValues...)
	out.Params = copyMap(t.Params)
	return out
}

func trimQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}
