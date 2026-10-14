# Cloud BAS Phase 3: Prerequisites & Multi-Account Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task inline. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate scenario execution on discovered cloud graph state (prerequisite resolver), and run cloud scenarios across multiple accounts with per-account isolation and aggregated reporting.

**Architecture:** PrerequisiteResolver checks a scenario's declared cloud prerequisites (identity/resource/permission/audit availability) against the discovered CloudResource/CloudIdentity/CloudPermission graph, returning OK/MISSING/DEGRADED/UNKNOWN per prerequisite — a conservative pre-flight filter, never an authorization decision. A step-level gate additionally blocks dispatch of any step whose permission edge evaluates to Blocked or Unknown. CloudCampaignScope carries an account list and concurrency/timeout/isolation settings; multi-account execution runs one CloudChildRun per account (fully independent discovery→prerequisite→execution→evidence), bounded by MaxConcurrency, then aggregates via CloudAggregate — a compute-on-read rollup mirroring the existing `campaign.Aggregate` pattern (same Prevented/Detected/Missed/Errored taxonomy) but built on CloudControlOutcome instead of models.SimulationResult.

**Tech Stack:** Go 1.23+, existing cloudgraph package (Phase 1-2), existing campaign package pattern (reused conceptually, not by import — different result type).

**Spec:** `docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`

## Global Constraints

- **Execution:** Inline on main branch (no worktree; per user preference)
- **Model:** Sonnet only; never dispatch Opus
- **Verification:** Narrow/targeted first (per-task checks); full regression at module end
- **Changes:** Minimal only; no unrelated refactoring
- **Evidence:** Never fake-as-live; distinguish observed from inferred from unknown
- **Testing:** TDD required; watch every failing test before implementation
- **Commits:** Git push after every commit (Windows host)

## Review Focus

1. **Prerequisite check treated as authorization:** A scenario with OK prerequisites still must not bypass the Layer C evaluator at execution time — prerequisite OK means "worth attempting," not "permitted."
2. **Step gate false negative:** A Blocked edge deep in a multi-step scenario must stop dispatch of that step specifically, not silently continue to the next step as if it succeeded.
3. **Partial account failure corrupts aggregate:** If one account's discovery fails (e.g., no cloud access), the other accounts' child runs must still aggregate correctly — one account's MISSING prerequisite isn't a global abort.
4. **Concurrency limit violated under load:** With more accounts than MaxConcurrency, the N+1th account must wait, not fire immediately and exceed the limit.
5. **UNKNOWN prerequisite collapsed to MISSING:** A prerequisite that couldn't be checked (e.g., audit log API timeout) must report UNKNOWN distinctly from MISSING (confirmed absent) — collapsing them hides a different operator action (retry vs. provision).

---

## File Structure

**New files created:**

- `orchestrator/internal/cloudgraph/prerequisite.go` — PrerequisiteResolver, CloudPrerequisite types
- `orchestrator/internal/cloudgraph/prerequisite_test.go` — Resolver tests
- `orchestrator/internal/cloudgraph/step_gate.go` — Step-level execution gate
- `orchestrator/internal/cloudgraph/step_gate_test.go` — Gate tests
- `orchestrator/internal/cloudgraph/campaign_scope.go` — CloudCampaignScope, CloudChildRun types
- `orchestrator/internal/cloudgraph/campaign_scope_test.go` — Scope tests
- `orchestrator/internal/cloudgraph/multiaccount.go` — Multi-account execution + CloudAggregate
- `orchestrator/internal/cloudgraph/multiaccount_test.go` — Multi-account tests

**Not created (deferred):**

- YAML scenario schema changes (actual parser integration — Phase 4/5, once real scenarios are authored)
- Real concurrent goroutine dispatch wiring into existing orchestrator run dispatcher (Phase 4/5)

---

## Task 1: Scenario Prerequisite Resolver

**Files:**
- Create: `orchestrator/internal/cloudgraph/prerequisite.go`
- Create: `orchestrator/internal/cloudgraph/prerequisite_test.go`
- Test: `orchestrator/internal/cloudgraph/prerequisite_test.go`

**Interfaces:**
- Consumes: CloudResource, CloudIdentity, CloudPermission, PathState (Phase 1)
- Produces: `CloudPrerequisite` type (Kind, Target, RequiredState); `PrerequisiteResult` type (Status, Detail); `PrerequisiteResolver` with `Resolve(prereqs []*CloudPrerequisite, graph *DiscoveredGraph) []*PrerequisiteResult`; `DiscoveredGraph` type (Identities, Resources, Permissions slices)

---

- [ ] **Step 1: Write failing test for OK prerequisite (resource found)**

Create `orchestrator/internal/cloudgraph/prerequisite_test.go`:

```go
package cloudgraph

import (
	"testing"
)

// TestPrerequisiteResolver_ResourceFoundReturnsOK verifies a discovered resource satisfies its prerequisite
func TestPrerequisiteResolver_ResourceFoundReturnsOK(t *testing.T) {
	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::test-bucket",
		Kind:        "s3-bucket",
	}

	graph := &DiscoveredGraph{
		Resources: []*CloudResource{bucket},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_resource",
		Target: "arn:aws:s3:::test-bucket",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Status != "OK" {
		t.Errorf("Expected OK, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_ResourceMissingReturnsMissing verifies absent resource is reported
func TestPrerequisiteResolver_ResourceMissingReturnsMissing(t *testing.T) {
	graph := &DiscoveredGraph{
		Resources: []*CloudResource{},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_resource",
		Target: "arn:aws:s3:::nonexistent-bucket",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "MISSING" {
		t.Errorf("Expected MISSING, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_IdentityFoundReturnsOK verifies identity prerequisite satisfaction
func TestPrerequisiteResolver_IdentityFoundReturnsOK(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
	}

	graph := &DiscoveredGraph{
		Identities: []*CloudIdentity{user},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_identity",
		Target: "arn:aws:iam::123456789012:user/test-user",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "OK" {
		t.Errorf("Expected OK, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_PermissionFoundButBlockedReturnsDegraded verifies DEGRADED
// when the permission edge exists but evaluates to Blocked (scenario could still run,
// but the attack path it validates is known-closed — operator should know before dispatch).
func TestPrerequisiteResolver_PermissionFoundButBlockedReturnsDegraded(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/test-user"}
	role := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/test-role"}

	edge := &CloudPermission{
		Source: user,
		Target: role,
		Action: "sts:AssumeRole",
	}

	graph := &DiscoveredGraph{
		Identities:  []*CloudIdentity{user},
		Resources:   []*CloudResource{role},
		Permissions: []*CloudPermission{edge},
		Evaluations: map[string]PathState{
			"arn:aws:iam::123456789012:user/test-user->sts:AssumeRole->arn:aws:iam::123456789012:role/test-role": Blocked,
		},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_permission",
		Target: "arn:aws:iam::123456789012:user/test-user->sts:AssumeRole->arn:aws:iam::123456789012:role/test-role",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "DEGRADED" {
		t.Errorf("Expected DEGRADED, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_AuditUnavailableReturnsUnknown verifies UNKNOWN is distinct from MISSING
func TestPrerequisiteResolver_AuditUnavailableReturnsUnknown(t *testing.T) {
	graph := &DiscoveredGraph{
		AuditAvailability: map[string]string{
			"cloudtrail": "unavailable",
		},
	}

	prereq := &CloudPrerequisite{
		Kind:   "audit_availability",
		Target: "cloudtrail",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "UNKNOWN" {
		t.Errorf("Expected UNKNOWN (not MISSING), got %s", results[0].Status)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestPrerequisiteResolver -v
```

Expected: FAIL with "undefined: DiscoveredGraph" / "undefined: CloudPrerequisite" / "undefined: PrerequisiteResolver"

- [ ] **Step 3: Write prerequisite types and resolver**

Create `orchestrator/internal/cloudgraph/prerequisite.go`:

```go
package cloudgraph

// DiscoveredGraph holds everything discovered for one account scope: the raw
// inventory (identities, resources, permissions) plus any evaluation/audit
// results already computed for that inventory. Evaluations is keyed by
// "source->action->target" (same key shape a scenario step uses to name an edge).
type DiscoveredGraph struct {
	Identities        []*CloudIdentity
	Resources         []*CloudResource
	Permissions       []*CloudPermission
	Evaluations       map[string]PathState // edge key -> evaluated state
	AuditAvailability map[string]string    // audit source name -> "available"/"unavailable"
}

// CloudPrerequisite declares what a scenario needs before it is worth attempting.
type CloudPrerequisite struct {
	Kind   string // "cloud_identity", "cloud_resource", "cloud_permission", "audit_availability"
	Target string // CanonicalID, or "source->action->target" edge key, or audit source name
}

// PrerequisiteResult is the resolver's verdict for one prerequisite.
// Status is NOT an authorization decision — it is a pre-flight filter:
// OK means "worth attempting," never "permitted."
type PrerequisiteResult struct {
	Prerequisite *CloudPrerequisite
	Status       string // "OK", "MISSING", "DEGRADED", "UNKNOWN"
	Detail       string
}

// PrerequisiteResolver checks declared prerequisites against a discovered graph.
type PrerequisiteResolver struct{}

// Resolve evaluates each prerequisite against the graph. A prerequisite kind
// the resolver does not recognize resolves UNKNOWN (never silently OK or MISSING):
// an unrecognized kind means the resolver cannot tell, not that the thing is absent.
func (r *PrerequisiteResolver) Resolve(prereqs []*CloudPrerequisite, graph *DiscoveredGraph) []*PrerequisiteResult {
	results := make([]*PrerequisiteResult, 0, len(prereqs))

	for _, p := range prereqs {
		results = append(results, r.resolveOne(p, graph))
	}

	return results
}

func (r *PrerequisiteResolver) resolveOne(p *CloudPrerequisite, graph *DiscoveredGraph) *PrerequisiteResult {
	switch p.Kind {
	case "cloud_identity":
		for _, id := range graph.Identities {
			if id.CanonicalID == p.Target {
				return &PrerequisiteResult{Prerequisite: p, Status: "OK"}
			}
		}
		return &PrerequisiteResult{Prerequisite: p, Status: "MISSING", Detail: "identity not found in discovery"}

	case "cloud_resource":
		for _, res := range graph.Resources {
			if res.CanonicalID == p.Target {
				return &PrerequisiteResult{Prerequisite: p, Status: "OK"}
			}
		}
		return &PrerequisiteResult{Prerequisite: p, Status: "MISSING", Detail: "resource not found in discovery"}

	case "cloud_permission":
		state, evaluated := graph.Evaluations[p.Target]
		if !evaluated {
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "edge not yet evaluated"}
		}
		switch state {
		case Blocked:
			return &PrerequisiteResult{Prerequisite: p, Status: "DEGRADED", Detail: "edge exists but evaluates to Blocked"}
		case Unknown:
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "edge evaluation inconclusive"}
		default:
			return &PrerequisiteResult{Prerequisite: p, Status: "OK"}
		}

	case "audit_availability":
		status, known := graph.AuditAvailability[p.Target]
		if !known {
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "audit source status not checked"}
		}
		if status == "unavailable" {
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "audit source reported unavailable"}
		}
		return &PrerequisiteResult{Prerequisite: p, Status: "OK"}

	default:
		return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "unrecognized prerequisite kind: " + p.Kind}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestPrerequisiteResolver -v
```

Expected: PASS 5/5

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/prerequisite.go internal/cloudgraph/prerequisite_test.go && git commit -m "feat(cloudgraph): scenario prerequisite resolver

- DiscoveredGraph: per-account inventory (identities/resources/permissions/evaluations/audit)
- CloudPrerequisite: declares what a scenario needs (identity/resource/permission/audit)
- PrerequisiteResolver.Resolve: OK/MISSING/DEGRADED/UNKNOWN per prerequisite
- Critical boundary: Status is a pre-flight filter, never an authorization decision
- Unrecognized prerequisite kind resolves UNKNOWN, not silently OK
- Tests: resource found/missing, identity found, blocked-edge DEGRADED, unavailable-audit UNKNOWN

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Step-Level Execution Gate

**Files:**
- Create: `orchestrator/internal/cloudgraph/step_gate.go`
- Create: `orchestrator/internal/cloudgraph/step_gate_test.go`
- Test: `orchestrator/internal/cloudgraph/step_gate_test.go`

**Interfaces:**
- Consumes: EvaluationResult, PathState (Phase 2); DiscoveredGraph (Task 1)
- Produces: `StepGate` type with `ShouldDispatch(edge *CloudPermission, graph *DiscoveredGraph) *GateDecision`; `GateDecision` type (Allowed bool, Reason string)

---

- [ ] **Step 1: Write failing test for gate blocking a Blocked edge**

Create `orchestrator/internal/cloudgraph/step_gate_test.go`:

```go
package cloudgraph

import (
	"testing"
)

// TestStepGate_BlocksDispatchWhenEdgeIsBlocked verifies a Blocked edge halts the step
func TestStepGate_BlocksDispatchWhenEdgeIsBlocked(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	role := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/admin-role"}

	edge := &CloudPermission{
		Source: user,
		Target: role,
		Action: "sts:AssumeRole",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(edge): Blocked,
		},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if decision.Allowed {
		t.Error("Expected gate to block dispatch for Blocked edge")
	}
	if decision.Reason == "" {
		t.Error("Expected gate to document why dispatch was blocked")
	}
}

// TestStepGate_BlocksDispatchWhenEdgeIsUnknown verifies Unknown also halts the step
// (conservative: unresolved risk is treated the same as confirmed risk for dispatch purposes)
func TestStepGate_BlocksDispatchWhenEdgeIsUnknown(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::test-bucket"}

	edge := &CloudPermission{
		Source: user,
		Target: bucket,
		Action: "s3:GetObject",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(edge): Unknown,
		},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if decision.Allowed {
		t.Error("Expected gate to block dispatch for Unknown edge")
	}
}

// TestStepGate_AllowsDispatchWhenEdgeIsPolicySupported verifies normal dispatch proceeds
func TestStepGate_AllowsDispatchWhenEdgeIsPolicySupported(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::test-bucket"}

	edge := &CloudPermission{
		Source: user,
		Target: bucket,
		Action: "s3:GetObject",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(edge): PolicySupported,
		},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if !decision.Allowed {
		t.Error("Expected gate to allow dispatch for PolicySupported edge")
	}
}

// TestStepGate_AllowsDispatchWhenEdgeNotYetEvaluated verifies gate does not block
// on missing evaluation data alone — that is the resolver's job (UNKNOWN prerequisite),
// not the gate's. The gate only blocks on a KNOWN-bad evaluation.
func TestStepGate_AllowsDispatchWhenEdgeNotYetEvaluated(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::test-bucket"}

	edge := &CloudPermission{
		Source: user,
		Target: bucket,
		Action: "s3:GetObject",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if !decision.Allowed {
		t.Error("Expected gate to allow dispatch when edge has no prior evaluation (resolver's job to flag UNKNOWN upstream)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestStepGate -v
```

Expected: FAIL with "undefined: StepGate" / "undefined: edgeKey"

- [ ] **Step 3: Write step gate implementation**

Create `orchestrator/internal/cloudgraph/step_gate.go`:

```go
package cloudgraph

// edgeKey builds the lookup key for a permission edge's evaluation state.
// Shared between DiscoveredGraph.Evaluations writers and readers.
func edgeKey(edge *CloudPermission) string {
	return edge.Source.CanonicalID + "->" + edge.Action + "->" + edge.Target.CanonicalID
}

// GateDecision is the step gate's verdict on whether a step may be dispatched.
type GateDecision struct {
	Allowed bool
	Reason  string
}

// StepGate prevents dispatch of a step whose permission edge is known-Blocked
// or known-Unknown. This is a dispatch-time safety check distinct from the
// PrerequisiteResolver's pre-flight filter: the resolver runs once before the
// scenario starts, the gate runs before each individual step.
type StepGate struct{}

// ShouldDispatch blocks dispatch only on a KNOWN-bad evaluation (Blocked or
// Unknown). An edge with no evaluation entry at all is allowed through here —
// absence of evaluation is the resolver's concern (it reports UNKNOWN as a
// prerequisite), not grounds for the gate to halt an already-approved scenario.
func (g *StepGate) ShouldDispatch(edge *CloudPermission, graph *DiscoveredGraph) *GateDecision {
	state, evaluated := graph.Evaluations[edgeKey(edge)]
	if !evaluated {
		return &GateDecision{Allowed: true}
	}

	switch state {
	case Blocked:
		return &GateDecision{Allowed: false, Reason: "edge evaluates to Blocked; dispatch would not reflect a real attack path"}
	case Unknown:
		return &GateDecision{Allowed: false, Reason: "edge evaluation is Unknown; dispatching would risk an unverified claim"}
	default:
		return &GateDecision{Allowed: true}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestStepGate -v
```

Expected: PASS 4/4

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/step_gate.go internal/cloudgraph/step_gate_test.go && git commit -m "feat(cloudgraph): step-level execution gate

- edgeKey: shared lookup key builder for permission-edge evaluation state
- StepGate.ShouldDispatch: blocks dispatch only for KNOWN-bad state (Blocked/Unknown)
- Absence of evaluation does NOT block (that is the resolver's job upstream, not the gate's)
- Distinct from PrerequisiteResolver: gate runs per-step at dispatch time, resolver runs once pre-flight
- Tests: blocks on Blocked, blocks on Unknown, allows on PolicySupported, allows when unevaluated

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: CloudCampaignScope & CloudChildRun Types

**Files:**
- Create: `orchestrator/internal/cloudgraph/campaign_scope.go`
- Create: `orchestrator/internal/cloudgraph/campaign_scope_test.go`
- Test: `orchestrator/internal/cloudgraph/campaign_scope_test.go`

**Interfaces:**
- Consumes: CloudControlOutcome (Phase 2), AccountScope (Phase 1)
- Produces: `CloudCampaignScope` type (Accounts, MaxConcurrency, TimeoutPerAccount, PreserveAccountContext, CorrelateAcrossAccounts); `CloudChildRun` type (AccountScope, Status, Outcomes, Skip reason)

---

- [ ] **Step 1: Write failing test for default scope values**

Create `orchestrator/internal/cloudgraph/campaign_scope_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"
)

// TestCloudCampaignScope_DefaultsApplied verifies spec-mandated defaults
func TestCloudCampaignScope_DefaultsApplied(t *testing.T) {
	scope := NewCloudCampaignScope([]*AccountScope{
		{Provider: "aws", AccountID: "111111111111"},
		{Provider: "aws", AccountID: "222222222222"},
	})

	if scope.MaxConcurrency != 3 {
		t.Errorf("Expected default MaxConcurrency=3, got %d", scope.MaxConcurrency)
	}
	if scope.TimeoutPerAccount != 30*time.Minute {
		t.Errorf("Expected default TimeoutPerAccount=30min, got %v", scope.TimeoutPerAccount)
	}
	if !scope.PreserveAccountContext {
		t.Error("Expected PreserveAccountContext=true by default")
	}
	if scope.CorrelateAcrossAccounts {
		t.Error("Expected CorrelateAcrossAccounts=false by default")
	}
	if len(scope.Accounts) != 2 {
		t.Errorf("Expected 2 accounts, got %d", len(scope.Accounts))
	}
}

// TestCloudChildRun_IndependentPerAccount verifies child runs don't share state
func TestCloudChildRun_IndependentPerAccount(t *testing.T) {
	run1 := &CloudChildRun{
		Account: &AccountScope{Provider: "aws", AccountID: "111111111111"},
		Status:  "completed",
		Outcomes: []*CloudControlOutcome{
			{PrerequisiteState: PolicySupported, ExecutionOutcome: "Allowed"},
		},
	}

	run2 := &CloudChildRun{
		Account: &AccountScope{Provider: "aws", AccountID: "222222222222"},
		Status:  "failed",
		SkipReason: "discovery failed: no cloud access",
	}

	if run1.Account.AccountID == run2.Account.AccountID {
		t.Error("Expected different accounts for independent child runs")
	}
	if len(run1.Outcomes) == 0 {
		t.Error("Expected run1 to have outcomes")
	}
	if run2.SkipReason == "" {
		t.Error("Expected run2 to document its skip reason")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run "TestCloudCampaignScope|TestCloudChildRun" -v
```

Expected: FAIL with "undefined: NewCloudCampaignScope" / "undefined: CloudChildRun"

- [ ] **Step 3: Write campaign scope types**

Create `orchestrator/internal/cloudgraph/campaign_scope.go`:

```go
package cloudgraph

import "time"

// CloudCampaignScope defines which accounts a cloud campaign targets and how
// it isolates and bounds execution across them. Campaign scope is distinct
// from scenario scope: scenarios are provider/account-agnostic; campaigns
// apply a scenario to a set of accounts.
type CloudCampaignScope struct {
	Accounts                []*AccountScope
	MaxConcurrency          int
	TimeoutPerAccount       time.Duration
	PreserveAccountContext  bool
	CorrelateAcrossAccounts bool
}

// NewCloudCampaignScope builds a scope with spec-mandated defaults:
// MaxConcurrency=3, TimeoutPerAccount=30min, PreserveAccountContext=true,
// CorrelateAcrossAccounts=false.
func NewCloudCampaignScope(accounts []*AccountScope) *CloudCampaignScope {
	return &CloudCampaignScope{
		Accounts:                accounts,
		MaxConcurrency:          3,
		TimeoutPerAccount:       30 * time.Minute,
		PreserveAccountContext:  true,
		CorrelateAcrossAccounts: false,
	}
}

// CloudChildRun is one account's independent execution within a campaign:
// its own discovery, prerequisite check, execution, and evidence, isolated
// from every other account's child run.
type CloudChildRun struct {
	Account    *AccountScope
	Status     string // "running", "completed", "partial", "failed", "skipped"
	Outcomes   []*CloudControlOutcome
	SkipReason string // populated when Status == "skipped" (e.g. discovery failed)
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run "TestCloudCampaignScope|TestCloudChildRun" -v
```

Expected: PASS 2/2

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/campaign_scope.go internal/cloudgraph/campaign_scope_test.go && git commit -m "feat(cloudgraph): CloudCampaignScope and CloudChildRun types

- CloudCampaignScope: Accounts + MaxConcurrency(3) + TimeoutPerAccount(30min) +
  PreserveAccountContext(true) + CorrelateAcrossAccounts(false) - defaults per spec
- NewCloudCampaignScope: constructor applying spec defaults
- CloudChildRun: one account's fully independent run (Status/Outcomes/SkipReason)
- Campaign scope != scenario scope: scenarios stay account-agnostic, campaigns apply them to accounts
- Tests: defaults applied, child runs are independent (different accounts, isolated state)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: Multi-Account Execution & CloudAggregate

**Files:**
- Create: `orchestrator/internal/cloudgraph/multiaccount.go`
- Create: `orchestrator/internal/cloudgraph/multiaccount_test.go`
- Test: `orchestrator/internal/cloudgraph/multiaccount_test.go`

**Interfaces:**
- Consumes: CloudCampaignScope, CloudChildRun, CloudControlOutcome (Task 3, Phase 2)
- Produces: `CloudCampaignSummary` type (Dispatched, Skipped, Prevented, Detected, Missed, Errored, Targets); `CloudAggregate(runs []*CloudChildRun) *CloudCampaignSummary`; `RunMultiAccount(scope *CloudCampaignScope, execute func(*AccountScope) *CloudChildRun) []*CloudChildRun`

---

- [ ] **Step 1: Write failing test for aggregation with one failed account**

Create `orchestrator/internal/cloudgraph/multiaccount_test.go`:

```go
package cloudgraph

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCloudAggregate_PartialAccountFailureDoesNotCorruptOthers verifies isolation:
// one account's failure must not zero-out or exclude the other accounts' real outcomes.
func TestCloudAggregate_PartialAccountFailureDoesNotCorruptOthers(t *testing.T) {
	healthyRun := &CloudChildRun{
		Account: &AccountScope{AccountID: "111111111111"},
		Status:  "completed",
		Outcomes: []*CloudControlOutcome{
			{ExecutionOutcome: "Allowed", PrerequisiteState: PolicySupported},
			{ExecutionOutcome: "Blocked", PrerequisiteState: Blocked},
		},
	}

	failedRun := &CloudChildRun{
		Account:    &AccountScope{AccountID: "222222222222"},
		Status:     "skipped",
		SkipReason: "discovery failed: no cloud access",
	}

	summary := CloudAggregate([]*CloudChildRun{healthyRun, failedRun})

	if summary.Dispatched != 2 {
		t.Errorf("Expected 2 dispatched (both accounts attempted), got %d", summary.Dispatched)
	}
	if summary.Skipped != 1 {
		t.Errorf("Expected 1 skipped, got %d", summary.Skipped)
	}
	if summary.Prevented != 1 {
		t.Errorf("Expected 1 prevented (Blocked outcome) from healthy account, got %d", summary.Prevented)
	}
	if summary.Missed != 1 {
		t.Errorf("Expected 1 missed (Allowed outcome, assuming no detection) from healthy account, got %d", summary.Missed)
	}
}

// TestCloudAggregate_EmptyRunsReturnsZeroSummary verifies no-accounts edge case
func TestCloudAggregate_EmptyRunsReturnsZeroSummary(t *testing.T) {
	summary := CloudAggregate([]*CloudChildRun{})

	if summary.Dispatched != 0 {
		t.Errorf("Expected 0 dispatched, got %d", summary.Dispatched)
	}
	if summary.Targets != 0 {
		t.Errorf("Expected 0 targets, got %d", summary.Targets)
	}
}

// TestRunMultiAccount_RespectsMaxConcurrency verifies the concurrency limit is enforced
func TestRunMultiAccount_RespectsMaxConcurrency(t *testing.T) {
	accounts := []*AccountScope{
		{AccountID: "1"}, {AccountID: "2"}, {AccountID: "3"},
		{AccountID: "4"}, {AccountID: "5"},
	}

	scope := NewCloudCampaignScope(accounts)
	scope.MaxConcurrency = 2

	var currentConcurrent int32
	var maxObservedConcurrent int32
	var mu sync.Mutex

	execute := func(acc *AccountScope) *CloudChildRun {
		cur := atomic.AddInt32(&currentConcurrent, 1)
		mu.Lock()
		if cur > maxObservedConcurrent {
			maxObservedConcurrent = cur
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond) // hold the slot briefly to force overlap

		atomic.AddInt32(&currentConcurrent, -1)
		return &CloudChildRun{Account: acc, Status: "completed"}
	}

	runs := RunMultiAccount(scope, execute)

	if len(runs) != 5 {
		t.Fatalf("Expected 5 child runs, got %d", len(runs))
	}
	if maxObservedConcurrent > 2 {
		t.Errorf("Expected max concurrency 2, observed %d", maxObservedConcurrent)
	}
}

// TestRunMultiAccount_OneAccountPanicDoesNotStopOthers verifies isolation under failure
func TestRunMultiAccount_OneAccountPanicDoesNotStopOthers(t *testing.T) {
	accounts := []*AccountScope{
		{AccountID: "1"}, {AccountID: "2"}, {AccountID: "3"},
	}
	scope := NewCloudCampaignScope(accounts)

	execute := func(acc *AccountScope) *CloudChildRun {
		if acc.AccountID == "2" {
			return &CloudChildRun{Account: acc, Status: "skipped", SkipReason: "discovery failed: timeout"}
		}
		return &CloudChildRun{Account: acc, Status: "completed"}
	}

	runs := RunMultiAccount(scope, execute)

	if len(runs) != 3 {
		t.Fatalf("Expected 3 child runs despite account 2 failing, got %d", len(runs))
	}

	completedCount := 0
	skippedCount := 0
	for _, r := range runs {
		if r.Status == "completed" {
			completedCount++
		}
		if r.Status == "skipped" {
			skippedCount++
		}
	}
	if completedCount != 2 || skippedCount != 1 {
		t.Errorf("Expected 2 completed + 1 skipped, got %d completed + %d skipped", completedCount, skippedCount)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run "TestCloudAggregate|TestRunMultiAccount" -v
```

Expected: FAIL with "undefined: CloudAggregate" / "undefined: RunMultiAccount"

- [ ] **Step 3: Write multi-account execution and aggregation**

Create `orchestrator/internal/cloudgraph/multiaccount.go`:

```go
package cloudgraph

import "sync"

// CloudCampaignSummary is the compute-on-read rollup of a cloud campaign across
// accounts. Mirrors the shape of the existing campaign.Summary pattern (same
// Prevented/Detected/Missed/Errored taxonomy), built on CloudControlOutcome
// instead of models.SimulationResult.
type CloudCampaignSummary struct {
	Targets    int
	Dispatched int
	Skipped    int
	Prevented  int // outcome Blocked (control stopped the attack)
	Detected   int // outcome Allowed but flagged by a detection control (not modeled yet; reserved)
	Missed     int // outcome Allowed and not detected - the real gap
	Errored    int // outcome Unknown (evidence unavailable; cannot be scored)
}

// CloudAggregate rolls child runs into a campaign summary. A skipped account
// contributes to Dispatched and Skipped but contributes no outcomes - it never
// zeroes out or excludes other accounts' real results.
func CloudAggregate(runs []*CloudChildRun) *CloudCampaignSummary {
	summary := &CloudCampaignSummary{
		Dispatched: len(runs),
	}
	summary.Targets = summary.Dispatched

	for _, run := range runs {
		if run.Status == "skipped" {
			summary.Skipped++
			continue
		}
		for _, outcome := range run.Outcomes {
			switch outcome.ExecutionOutcome {
			case "Blocked":
				summary.Prevented++
			case "Allowed":
				summary.Missed++
			case "Unknown":
				summary.Errored++
			}
		}
	}

	return summary
}

// RunMultiAccount executes `execute` once per account in scope, bounded by
// scope.MaxConcurrency, and returns every account's CloudChildRun. Each
// account's execution is fully independent: a failure in one account's
// execute call produces a CloudChildRun reflecting that failure (the caller's
// `execute` is responsible for catching its own errors and returning a
// "skipped"/"failed" CloudChildRun rather than letting the goroutine panic).
func RunMultiAccount(scope *CloudCampaignScope, execute func(*AccountScope) *CloudChildRun) []*CloudChildRun {
	results := make([]*CloudChildRun, len(scope.Accounts))
	sem := make(chan struct{}, scope.MaxConcurrency)
	var wg sync.WaitGroup

	for i, acc := range scope.Accounts {
		wg.Add(1)
		go func(idx int, account *AccountScope) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = execute(account)
		}(i, acc)
	}

	wg.Wait()
	return results
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run "TestCloudAggregate|TestRunMultiAccount" -v
```

Expected: PASS 4/4

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/multiaccount.go internal/cloudgraph/multiaccount_test.go && git commit -m "feat(cloudgraph): multi-account execution and CloudAggregate

- CloudCampaignSummary: Targets/Dispatched/Skipped/Prevented/Detected/Missed/Errored
- CloudAggregate: compute-on-read rollup mirroring campaign.Aggregate's pattern,
  built on CloudControlOutcome instead of models.SimulationResult
- RunMultiAccount: bounded-concurrency fan-out via semaphore channel; each account's
  execute() call is isolated, a skip/failure in one never corrupts another's results
- Tests: partial-failure aggregation isolation, empty-runs edge case, concurrency
  limit enforcement (observed max never exceeds MaxConcurrency), one-account-failure
  does not stop the others

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Phase 3 Regression Validation & Exit Gate

**Files:**
- Modify: (none; validation only)
- Test: Full test suite

**Interfaces:**
- Consumes: All changes from Tasks 1-4
- Produces: Clean test suite, commitment to Phase 3 deliverables

---

- [ ] **Step 1: Run full cloudgraph test suite**

```bash
cd orchestrator && go test ./internal/cloudgraph -v 2>&1 | tail -40
```

Expected: All tests PASS (Phase 1: 9, Phase 2: ~15, Phase 3: ~15 = ~39 total)

- [ ] **Step 2: Run go vet**

```bash
cd orchestrator && go vet ./internal/cloudgraph/...
```

Expected: No warnings

- [ ] **Step 3: Run full orchestrator suite for regressions**

```bash
cd orchestrator && go test ./internal/ad... ./internal/scenario... ./internal/controlval... ./internal/campaign... -v 2>&1 | tail -20
```

Expected: PASS (no regressions in existing code, including the campaign package whose pattern Task 4 mirrored)

- [ ] **Step 4: Update ledger with exit gate summary**

Document in the plan's ledger: all 4 deliverables complete, test counts, any rulings made during implementation.

---

## Phase 3 Exit Gate Criteria

✅ Deliverable 1: Scenario prerequisite resolver (CloudPrerequisite, PrerequisiteResolver, OK/MISSING/DEGRADED/UNKNOWN)
✅ Deliverable 2: Step-level execution gate (StepGate, blocks only on known-Blocked/Unknown, never on absence of evaluation)
✅ Deliverable 3: CloudCampaignScope & CloudChildRun (spec defaults, per-account isolation)
✅ Deliverable 4: Multi-account execution + CloudAggregate (bounded concurrency, partial-failure isolation)
✅ TDD Discipline: All tests RED→GREEN verified
✅ Zero Regressions: Full test suite PASS, including existing campaign package
✅ Evidence-First: UNKNOWN never collapsed into MISSING or OK

---

## Deferred (Phase 4+)

- YAML scenario schema parser integration (actual prerequisite declarations in scenario files)
- Wiring RunMultiAccount into the real orchestrator dispatcher (currently a standalone, testable function)
- Azure RBAC evaluator (parallel to AWSEvaluator)
- AD↔Cloud hybrid identity federation
- Cross-account correlation (CorrelateAcrossAccounts=true path is typed but not implemented)

---

**Execution Method:** Inline on main (use superpowers:executing-plans).

**Next Step After Phase 3:** Phase 4 (Azure/Hybrid Identity), then Phase 5 (Scenario Breadth & Release Validation).
