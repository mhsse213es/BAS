# AD-M06 Lab Factory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `adlab` package: deterministic synthetic AD environments, the first environment-backed `adchain.ConditionResolver`, and a validation harness that runs `Fixture → adenv.Environment → EnvResolver → adchain.Plan → Expected result` end-to-end.

**Architecture:** New `orchestrator/internal/adlab` package depending one-way on `adenv` + `adprimitive` + `adchain`. `EnvResolver` resolves the M04 catalogs' condition keys (`acl_right_held:<Right>` via the attacker's transitive group set over `env.Authorization.ACLs`; `escN_*` via the existing `adenv` predicates, ESC1-3 enrollment-gated) against a synthetic `adenv.Environment`. A `Provider` seam yields labs (synthetic now, live-AD backend later). `Validate` runs `adchain.Plan` over a lab and reports expectation mismatches.

**Tech Stack:** Go (stdlib `strings`/`slices`/`sort` only; no new dependencies). No DB, no containers — pure deterministic in-memory, plain `go test`.

**Spec:** `docs/superpowers/specs/2026-10-08-ad-m06-lab-factory-design.md`

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adlab` depends on `adenv`, `adprimitive`, `adchain` only (one-way; nothing imports it back). `adbench` may appear only in a test file (full-catalog integration check).
- No change to `adenv`, `adprimitive`, or `adchain` — consume their existing exported surfaces only.
- `EnvResolver` resolves relative to a FIXED starting identity plus its transitive group memberships — not an evolving foothold (faithful to `adchain`'s static `Resolve(key) bool` contract).
- Unknown or malformed condition keys resolve `false` (fail-closed).
- `Provider.Labs()` returns `([]Lab, error)`; the synthetic provider always returns a nil error.

## Review Focus

- **Group-membership cycle** (A∈B, B∈A): the transitive-closure walk must terminate via a visited-set, never loop. → Task 1, Step 1.
- **Nested group grant** (attacker ∈ G1, G1 ∈ G2, ACL grants G2): the closure must reach G2 so the right resolves true. → Task 1, Step 1.
- **Attacker name absent from `env.Identity`**: `controlled` degrades to the bare name, conditions resolve `false`, no panic. → Task 1, Step 1.
- **Malformed key** (`acl_right_held:` empty suffix, or unknown prefix): `false`, no panic. → Task 1, Step 1.
- **Empty `env.PKI`**: every `escN_*` resolves `false`. → Task 1, Step 1.

---

### Task 1: `EnvResolver`

**Files:**
- Create: `orchestrator/internal/adlab/resolver.go`
- Test: `orchestrator/internal/adlab/resolver_test.go`

**Interfaces:**
- Consumes: `adenv.Environment`/`Group`/`ACLEntry`/`ACLRight`/`CertTemplate`, `adenv.IsESC1Vulnerable`/`IsESC2Vulnerable`/`IsESC3Vulnerable`/`HasTemplateWriteAccess`, `adchain.ConditionResolver`.
- Produces: `type EnvResolver`, `func NewEnvResolver(env adenv.Environment, attacker string) *EnvResolver`, `func (*EnvResolver) Resolve(key string) bool` (satisfies `adchain.ConditionResolver`).

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adlab/resolver_test.go
package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adenv"
)

// compile-time assertion that EnvResolver satisfies the interface.
var _ adchain.ConditionResolver = (*EnvResolver)(nil)

func TestResolve_ACLRightHeldDirectly(t *testing.T) {
	env := adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "attacker", Target: "victim", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "attacker")
	if !r.Resolve("acl_right_held:GenericAll") {
		t.Error("expected true: attacker directly holds GenericAll")
	}
	if r.Resolve("acl_right_held:WriteDACL") {
		t.Error("expected false: attacker holds no WriteDACL")
	}
}

func TestResolve_ACLRightHeldViaNestedGroups(t *testing.T) {
	// attacker -> G1 -> G2, and the ACL grants G2.
	env := adenv.Environment{
		Identity: adenv.Identity{Groups: []adenv.Group{
			{Name: "G1", Members: []string{"attacker"}},
			{Name: "G2", Members: []string{"G1"}},
		}},
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "G2", Target: "victim", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "attacker")
	if !r.Resolve("acl_right_held:GenericAll") {
		t.Error("expected true: attacker reaches G2 transitively, G2 holds GenericAll")
	}
}

func TestResolve_GroupCycleTerminates(t *testing.T) {
	// A membership cycle must not loop forever.
	env := adenv.Environment{
		Identity: adenv.Identity{Groups: []adenv.Group{
			{Name: "A", Members: []string{"attacker", "B"}},
			{Name: "B", Members: []string{"A"}},
		}},
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "A", Target: "victim", Right: adenv.ACLAddMember},
		}},
	}
	done := make(chan bool, 1)
	go func() {
		r := NewEnvResolver(env, "attacker")
		done <- r.Resolve("acl_right_held:AddMember")
	}()
	select {
	case got := <-done:
		if !got {
			t.Error("expected true: attacker is in A (which holds AddMember) despite the A<->B cycle")
		}
	case <-timeAfter():
		t.Fatal("NewEnvResolver/Resolve did not terminate on a membership cycle")
	}
}

func TestResolve_AttackerAbsentResolvesFalse(t *testing.T) {
	env := adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "someone-else", Target: "victim", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "ghost")
	if r.Resolve("acl_right_held:GenericAll") {
		t.Error("expected false: the ghost attacker holds nothing")
	}
}

func TestResolve_ESC1EnrollmentGated(t *testing.T) {
	vulnerable := adenv.CertTemplate{
		Name:                    "VulnWebAuth",
		EKUs:                    []string{"Client Authentication"},
		EnrolleeSuppliesSubject: true,
		ManagerApprovalRequired: false,
		PublishedToCA:           true,
		EnrollmentRights:        []string{"Domain Users"},
	}
	env := adenv.Environment{
		Identity: adenv.Identity{Groups: []adenv.Group{
			{Name: "Domain Users", Members: []string{"attacker"}},
		}},
		PKI: adenv.PKI{Templates: []adenv.CertTemplate{vulnerable}},
	}
	if !NewEnvResolver(env, "attacker").Resolve("esc1_vulnerable_template") {
		t.Error("expected true: template is ESC1-vulnerable and attacker's group can enroll")
	}

	// Same template, attacker NOT in EnrollmentRights -> gated false.
	envNoEnroll := env
	envNoEnroll.Identity = adenv.Identity{} // attacker belongs to no group
	if NewEnvResolver(envNoEnroll, "attacker").Resolve("esc1_vulnerable_template") {
		t.Error("expected false: template is vulnerable but attacker cannot enroll")
	}
}

func TestResolve_ESC4TemplateWriteAccess(t *testing.T) {
	env := adenv.Environment{
		PKI: adenv.PKI{Templates: []adenv.CertTemplate{
			{Name: "T", WriteRights: []string{"attacker"}},
		}},
	}
	if !NewEnvResolver(env, "attacker").Resolve("esc4_template_write_access") {
		t.Error("expected true: attacker holds write access on a template")
	}
}

func TestResolve_EmptyPKIAllESCFalse(t *testing.T) {
	r := NewEnvResolver(adenv.Environment{}, "attacker")
	for _, key := range []string{"esc1_vulnerable_template", "esc2_vulnerable_template", "esc3_vulnerable_template", "esc4_template_write_access"} {
		if r.Resolve(key) {
			t.Errorf("expected false for %s with empty PKI", key)
		}
	}
}

func TestResolve_MalformedAndUnknownKeysFalse(t *testing.T) {
	env := adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "attacker", Target: "v", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "attacker")
	for _, key := range []string{"acl_right_held:", "acl_right_held", "totally_unknown_key", ""} {
		if r.Resolve(key) {
			t.Errorf("expected false for malformed/unknown key %q", key)
		}
	}
}
```

Add a tiny timeout helper at the bottom of the test file (keeps the cycle test readable):

```go
import "time" // add to the import block

func timeAfter() <-chan time.Time { return time.After(2 * time.Second) }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adlab/... -v`
Expected: FAIL — `undefined: EnvResolver` / `undefined: NewEnvResolver`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adlab/resolver.go

// Package adlab is AD-M06's Lab Factory: deterministic synthetic AD
// environments, the first environment-backed adchain.ConditionResolver,
// and a harness that validates the adenv model + M04 predicates + the
// adchain planner end-to-end. Pure Go, no DB, no live AD. Depends one-way
// on adenv, adprimitive, and adchain.
package adlab

import (
	"strings"

	"github.com/audspect/bas/internal/adenv"
)

const aclRightPrefix = "acl_right_held:"

// EnvResolver answers adchain's Prerequisites.Conditions keys by reading an
// adenv.Environment relative to a fixed attacker foothold (the attacker
// principal plus its transitive group memberships). It satisfies
// adchain.ConditionResolver.
type EnvResolver struct {
	env        adenv.Environment
	controlled map[string]bool // attacker + every group it transitively belongs to
}

// NewEnvResolver precomputes the attacker's transitive principal set.
func NewEnvResolver(env adenv.Environment, attacker string) *EnvResolver {
	controlled := map[string]bool{attacker: true}
	// Fixed-point: keep adding any group whose Members includes a principal
	// already controlled, until a pass adds nothing. The map doubles as the
	// visited-set, so a membership cycle terminates.
	for {
		added := false
		for _, g := range env.Identity.Groups {
			if controlled[g.Name] {
				continue
			}
			for _, m := range g.Members {
				if controlled[m] {
					controlled[g.Name] = true
					added = true
					break
				}
			}
		}
		if !added {
			break
		}
	}
	return &EnvResolver{env: env, controlled: controlled}
}

// Resolve implements adchain.ConditionResolver. Unknown or malformed keys
// return false (fail-closed).
func (r *EnvResolver) Resolve(key string) bool {
	if right, ok := strings.CutPrefix(key, aclRightPrefix); ok {
		if right == "" {
			return false
		}
		return r.holdsACLRight(adenv.ACLRight(right))
	}
	switch key {
	case "esc1_vulnerable_template":
		return r.hasEnrollableVulnerableTemplate(adenv.IsESC1Vulnerable)
	case "esc2_vulnerable_template":
		return r.hasEnrollableVulnerableTemplate(adenv.IsESC2Vulnerable)
	case "esc3_vulnerable_template":
		return r.hasEnrollableVulnerableTemplate(adenv.IsESC3Vulnerable)
	case "esc4_template_write_access":
		return r.hasWritableTemplate()
	default:
		return false
	}
}

func (r *EnvResolver) holdsACLRight(right adenv.ACLRight) bool {
	for _, ace := range r.env.Authorization.ACLs {
		if ace.Right == right && r.controlled[ace.Principal] {
			return true
		}
	}
	return false
}

func (r *EnvResolver) hasEnrollableVulnerableTemplate(vulnerable func(adenv.CertTemplate) bool) bool {
	for _, t := range r.env.PKI.Templates {
		if vulnerable(t) && r.canEnroll(t) {
			return true
		}
	}
	return false
}

func (r *EnvResolver) canEnroll(t adenv.CertTemplate) bool {
	for _, p := range t.EnrollmentRights {
		if r.controlled[p] {
			return true
		}
	}
	return false
}

func (r *EnvResolver) hasWritableTemplate() bool {
	for _, t := range r.env.PKI.Templates {
		for p := range r.controlled {
			if adenv.HasTemplateWriteAccess(t, p) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adlab/... -v`
Expected: PASS — all resolver tests.

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adlab/ && go vet ./internal/adlab/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adlab/resolver.go orchestrator/internal/adlab/resolver_test.go
git commit -m "$(cat <<'EOF'
feat(adlab): add environment-backed EnvResolver (AD-M06 task 1 of 3)

First real adchain.ConditionResolver: resolves acl_right_held:<Right>
against env.Authorization.ACLs via the attacker's transitive group set
(fixed-point closure, cycle-safe), and escN_* via the existing adenv
predicates (ESC1-3 enrollment-gated on the attacker's groups, ESC4 via
HasTemplateWriteAccess). Unknown/malformed keys fail closed to false.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `Lab`, `Provider` seam, and `Validate` harness

**Files:**
- Create: `orchestrator/internal/adlab/lab.go` (`Lab`, `Provider`)
- Create: `orchestrator/internal/adlab/harness.go` (`Case`, `Expectation`, `Failure`, `Validate`)
- Test: `orchestrator/internal/adlab/harness_test.go`

**Interfaces:**
- Consumes: `adenv.Environment`, `adprimitive.Primitive`/`Capability`/`CapDomainUser`/`CapControlledAccount`/`ACLAbuseCatalog`, `adchain.Plan`, `EnvResolver` (Task 1).
- Produces: `type Lab`, `type Provider interface{ Labs() ([]Lab, error) }`, `type Case`, `type Expectation`, `type Failure`, `func Validate(c Case) []Failure`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/adlab/harness_test.go
package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adprimitive"
)

// A minimal lab: attacker's group holds GenericAll -> CapControlledAccount
// reachable via acl-genericall-takeover.
func minimalACLLab() Lab {
	return Lab{
		Name:     "harness-min",
		Attacker: "attacker",
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Helpdesk", Members: []string{"attacker"}},
			}},
			Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
				{Principal: "Helpdesk", Target: "svc-admin", Right: adenv.ACLGenericAll},
			}},
		},
	}
}

func TestValidate_ReportsReachableWithExpectedPath(t *testing.T) {
	c := Case{
		Lab:       minimalACLLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		Expectations: []Expectation{{
			Target:        adprimitive.Capability{Kind: adprimitive.CapControlledAccount},
			WantReachable: true,
			WantPathIDs:   []string{"acl-genericall-takeover"},
		}},
	}
	if fails := Validate(c); len(fails) != 0 {
		t.Fatalf("expected no failures, got %+v", fails)
	}
}

func TestValidate_ReportsFailureOnWrongExpectation(t *testing.T) {
	// Assert UNreachable when it is in fact reachable -> one Failure.
	c := Case{
		Lab:       minimalACLLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		Expectations: []Expectation{{
			Target:        adprimitive.Capability{Kind: adprimitive.CapControlledAccount},
			WantReachable: false,
		}},
	}
	fails := Validate(c)
	if len(fails) != 1 {
		t.Fatalf("expected exactly 1 failure, got %d: %+v", len(fails), fails)
	}
}

func TestValidate_PathMismatchIsAFailure(t *testing.T) {
	c := Case{
		Lab:       minimalACLLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		Expectations: []Expectation{{
			Target:        adprimitive.Capability{Kind: adprimitive.CapControlledAccount},
			WantReachable: true,
			WantPathIDs:   []string{"some-other-primitive"}, // wrong
		}},
	}
	if fails := Validate(c); len(fails) != 1 {
		t.Fatalf("expected 1 failure for path mismatch, got %+v", fails)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlab/... -run TestValidate -v`
Expected: FAIL — `undefined: Lab` / `undefined: Case` / `undefined: Validate`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adlab/lab.go
package adlab

import "github.com/audspect/bas/internal/adenv"

// Lab is one reproducible, controlled AD environment plus the attacker's
// starting foothold in it.
type Lab struct {
	Name        string
	Description string
	Env         adenv.Environment
	Attacker    string // principal name present in Env.Identity — the starting foothold
}

// Provider yields labs. The synthetic implementation returns deterministic
// built-in labs and a nil error; a future live-AD backend provisions real
// environments (via the SharpHound -> attackpath -> adenv.FromGraph
// pipeline) and returns them behind this same interface — hence the error
// return, which only the live backend will use.
type Provider interface {
	Labs() ([]Lab, error)
}
```

```go
// orchestrator/internal/adlab/harness.go
package adlab

import (
	"slices"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// Expectation is one target capability and what the planner should do with
// it for a given lab. WantPathIDs is checked only when WantReachable.
type Expectation struct {
	Target        adprimitive.Capability
	WantReachable bool
	WantPathIDs   []string
}

// Case pairs a lab with the in-scope primitive catalog, the attacker's
// starting capabilities, and the expectations to assert.
type Case struct {
	Lab          Lab
	Catalog      []adprimitive.Primitive
	StartHeld    []adprimitive.Capability
	Expectations []Expectation
}

// Failure is one expectation that did not hold. Empty slice from Validate
// means every expectation passed.
type Failure struct {
	Target adprimitive.Capability
	Reason string
}

// Validate runs the full Fixture -> Environment -> EnvResolver -> Plan ->
// Expected chain for every expectation in c.
func Validate(c Case) []Failure {
	resolver := NewEnvResolver(c.Lab.Env, c.Lab.Attacker)
	var fails []Failure
	for _, exp := range c.Expectations {
		path, ok := adchain.Plan(c.Catalog, c.StartHeld, exp.Target, resolver)
		if ok != exp.WantReachable {
			fails = append(fails, Failure{
				Target: exp.Target,
				Reason: reachabilityReason(exp.WantReachable, ok),
			})
			continue
		}
		if exp.WantReachable {
			gotIDs := primitiveIDs(path)
			if !slices.Equal(gotIDs, exp.WantPathIDs) {
				fails = append(fails, Failure{
					Target: exp.Target,
					Reason: "path mismatch: want " + joinIDs(exp.WantPathIDs) + ", got " + joinIDs(gotIDs),
				})
			}
		}
	}
	return fails
}

func reachabilityReason(want, got bool) string {
	if want {
		return "expected target reachable, but planner found no path"
	}
	return "expected target unreachable, but planner found a path"
}

func primitiveIDs(path []adprimitive.Primitive) []string {
	ids := make([]string, 0, len(path))
	for _, p := range path {
		ids = append(ids, p.ID)
	}
	return ids
}

func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "[]"
	}
	return "[" + strings.Join(ids, " ") + "]"
}
```

Add `"strings"` to `harness.go`'s import block (used by `joinIDs`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adlab/... -v`
Expected: PASS — all tests (Task 1's plus the 3 harness tests).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adlab/ && go vet ./internal/adlab/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adlab/lab.go orchestrator/internal/adlab/harness.go orchestrator/internal/adlab/harness_test.go
git commit -m "$(cat <<'EOF'
feat(adlab): add Lab, Provider seam, and Validate harness (AD-M06 task 2 of 3)

Lab carries a synthetic adenv.Environment + a named attacker foothold.
Provider.Labs() ([]Lab, error) is the seam a future live-AD backend
plugs into. Validate runs adchain.Plan over a lab via EnvResolver and
reports one Failure per reachability-or-path mismatch (empty = pass).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `SyntheticProvider` + built-in labs + validation tests

**Files:**
- Create: `orchestrator/internal/adlab/labs.go` (`SyntheticProvider` + the three built-in lab constructors)
- Test: `orchestrator/internal/adlab/labs_test.go`

**Interfaces:**
- Consumes: `Lab`/`Provider`/`Case`/`Expectation`/`Validate` (Task 2), `EnvResolver` (Task 1), `adenv.*`, `adprimitive.ACLAbuseCatalog`/`ADCSCatalog`/`CapDomainUser`/`CapControlledAccount`.
- Produces: `type SyntheticProvider`, `func (SyntheticProvider) Labs() ([]Lab, error)`, and the built-in labs `aclGenericAllTakeoverLab()`, `adcsESC1EnrollableLab()`, `adcsESC1NotEnrollableLab()`, `noFootholdSafeLab()`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adlab/labs_test.go
package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// SyntheticProvider satisfies Provider.
var _ Provider = SyntheticProvider{}

func controlledAccount() adprimitive.Capability {
	return adprimitive.Capability{Kind: adprimitive.CapControlledAccount}
}
func domainUserHeld() []adprimitive.Capability {
	return []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
}

func TestSyntheticProvider_ReturnsAllBuiltInLabsNoError(t *testing.T) {
	labs, err := SyntheticProvider{}.Labs()
	if err != nil {
		t.Fatalf("synthetic provider must not error: %v", err)
	}
	if len(labs) != 4 {
		t.Fatalf("expected 4 built-in labs, got %d", len(labs))
	}
	seen := map[string]bool{}
	for _, l := range labs {
		if seen[l.Name] {
			t.Fatalf("duplicate lab name %q", l.Name)
		}
		seen[l.Name] = true
	}
}

func TestLab_ACLGenericAllTakeoverReachable(t *testing.T) {
	c := Case{
		Lab:       aclGenericAllTakeoverLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: true,
			WantPathIDs:   []string{"acl-genericall-takeover"},
		}},
	}
	if fails := Validate(c); len(fails) != 0 {
		t.Fatalf("expected clean validation, got %+v", fails)
	}
}

func TestLab_ADCSESC1EnrollmentGatePositiveAndNegative(t *testing.T) {
	pos := Case{
		Lab:       adcsESC1EnrollableLab(),
		Catalog:   adprimitive.ADCSCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: true,
			WantPathIDs:   []string{"adcs-esc1"},
		}},
	}
	if fails := Validate(pos); len(fails) != 0 {
		t.Fatalf("positive ESC1 lab should validate clean, got %+v", fails)
	}

	neg := Case{
		Lab:       adcsESC1NotEnrollableLab(),
		Catalog:   adprimitive.ADCSCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: false, // same vulnerable template, attacker can't enroll
		}},
	}
	if fails := Validate(neg); len(fails) != 0 {
		t.Fatalf("negative ESC1 lab should validate clean (target unreachable), got %+v", fails)
	}
}

func TestLab_NoFootholdSafeUnreachable(t *testing.T) {
	c := Case{
		Lab:       noFootholdSafeLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: false,
		}},
	}
	if fails := Validate(c); len(fails) != 0 {
		t.Fatalf("safe lab should validate clean (target unreachable), got %+v", fails)
	}
}

// Integration: the ACL takeover lab also validates against the FULL catalog,
// confirming the resolver doesn't spuriously enable unrelated primitives.
func TestLab_FullCatalogIntegration(t *testing.T) {
	lab := aclGenericAllTakeoverLab()
	resolver := NewEnvResolver(lab.Env, lab.Attacker)
	full := append(append([]adprimitive.Primitive{}, adprimitive.ACLAbuseCatalog...), adprimitive.ADCSCatalog...)
	_, ok := adchain.Plan(full, domainUserHeld(), controlledAccount(), resolver)
	if !ok {
		t.Fatal("expected CapControlledAccount reachable under the full catalog")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adlab/... -run "TestSyntheticProvider|TestLab_" -v`
Expected: FAIL — `undefined: SyntheticProvider` / `undefined: aclGenericAllTakeoverLab`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adlab/labs.go
package adlab

import "github.com/audspect/bas/internal/adenv"

// SyntheticProvider returns the deterministic built-in labs. It never errors.
type SyntheticProvider struct{}

func (SyntheticProvider) Labs() ([]Lab, error) {
	return []Lab{
		aclGenericAllTakeoverLab(),
		adcsESC1EnrollableLab(),
		adcsESC1NotEnrollableLab(),
		noFootholdSafeLab(),
	}, nil
}

// aclGenericAllTakeoverLab: the attacker's group holds GenericAll over a
// target account, so acl-genericall-takeover yields CapControlledAccount.
func aclGenericAllTakeoverLab() Lab {
	return Lab{
		Name:        "acl-genericall-takeover",
		Description: "Attacker's group holds GenericAll over a service account.",
		Attacker:    "attacker",
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Helpdesk", Members: []string{"attacker"}},
			}},
			Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
				{Principal: "Helpdesk", Target: "svc-admin", Right: adenv.ACLGenericAll},
			}},
		},
	}
}

// adcsESC1EnrollableLab: a published ESC1-vulnerable template the attacker's
// group can enroll in.
func adcsESC1EnrollableLab() Lab {
	return Lab{
		Name:        "adcs-esc1-enrollable",
		Description: "ESC1-vulnerable template; attacker's group has enrollment rights.",
		Attacker:    "attacker",
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Domain Users", Members: []string{"attacker"}},
			}},
			PKI: adenv.PKI{Templates: []adenv.CertTemplate{{
				Name:                    "VulnWebAuth",
				EKUs:                    []string{"Client Authentication"},
				EnrolleeSuppliesSubject: true,
				ManagerApprovalRequired: false,
				PublishedToCA:           true,
				EnrollmentRights:        []string{"Domain Users"},
			}}},
		},
	}
}

// adcsESC1NotEnrollableLab: the SAME vulnerable template, but the attacker
// belongs to no group with enrollment rights -> ESC1 gated off.
func adcsESC1NotEnrollableLab() Lab {
	return Lab{
		Name:        "adcs-esc1-not-enrollable",
		Description: "ESC1-vulnerable template, but attacker cannot enroll in it.",
		Attacker:    "attacker",
		Env: adenv.Environment{
			PKI: adenv.PKI{Templates: []adenv.CertTemplate{{
				Name:                    "VulnWebAuth",
				EKUs:                    []string{"Client Authentication"},
				EnrolleeSuppliesSubject: true,
				ManagerApprovalRequired: false,
				PublishedToCA:           true,
				EnrollmentRights:        []string{"PKI Admins"}, // attacker not a member
			}}},
		},
	}
}

// noFootholdSafeLab: attacker holds no abusable ACL right and there is no
// vulnerable template -> nothing reachable.
func noFootholdSafeLab() Lab {
	return Lab{
		Name:        "no-foothold-safe",
		Description: "Attacker has a domain-user foothold but no abusable rights.",
		Attacker:    "attacker",
		Env: adenv.Environment{
			Identity: adenv.Identity{Users: []adenv.User{{Name: "attacker", Enabled: true}}},
		},
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adlab/... -v`
Expected: PASS — the entire package (resolver + harness + labs).

- [ ] **Step 5: Run gofmt, go vet, and the full build; confirm no existing package was touched**

Run: `cd orchestrator && gofmt -l internal/adlab/ && go vet ./internal/adlab/... && go build ./... && git status --short internal/adenv internal/adprimitive internal/adchain`
Expected: gofmt/vet print nothing, build succeeds, `git status` on the three consumed packages prints nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adlab/labs.go orchestrator/internal/adlab/labs_test.go
git commit -m "$(cat <<'EOF'
feat(adlab): add SyntheticProvider and built-in labs (AD-M06 task 3 of 3)

Four deterministic labs validated end-to-end through
Fixture -> Environment -> EnvResolver -> adchain.Plan -> Expected:
acl-genericall-takeover (reachable), adcs-esc1 enrollable (reachable)
and its not-enrollable twin (unreachable -- proves the enrollment
gate), and no-foothold-safe (unreachable). Plus a full-catalog
integration check. Closes AD-M06 v1: the library layer is now
demonstrably correct against controlled synthetic environments; live
provisioning stays deferred behind the Provider seam.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing "Inline Over Subagents" preference — already decided, not asking the user to choose.** 3 sequential tasks building one cohesive package; Task 2 consumes Task 1's `EnvResolver`, Task 3 consumes both. Proceeding via `superpowers:executing-plans`.
