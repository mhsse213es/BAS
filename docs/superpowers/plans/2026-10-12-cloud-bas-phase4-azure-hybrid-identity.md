# Cloud BAS Phase 4: Azure RBAC & AD-Cloud Hybrid Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task inline. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Azure RBAC evaluator alongside AWSEvaluator, and compose AD identity reachability with cloud identity reachability through evidence-backed federation edges, so a hybrid attack path (on-prem AD → synced cloud identity → cloud resource) can be queried end to end.

**Architecture:** AzureEvaluator implements the same `AuthorizationEvaluator`-shaped contract as AWSEvaluator (`EvaluatePermission(edge, ctx) -> EvaluationResult`) but with Azure-specific semantics: role assignments carry a scope (subscription/resource-group/resource) that inherits downward, and deny assignments — not implicit-deny-by-default-with-explicit-Deny-statements like AWS — take precedence. FederationEdge links an AD identity reference to a CloudIdentity CanonicalID, carrying Provenance that must show real sync evidence (source + timestamp), never inferred from name matching. Hybrid composition is a thin orchestration layer: it calls the existing `adchain.Reachable`/`adchain.Plan` functions (capability-based, confirmed by inspection — AD exposes no traversable graph) to get a binary AD-side verdict, crosses a FederationEdge only if its Provenance is fresh, then runs the cloud-side CloudPermission edges through AWSEvaluator/AzureEvaluator. Each hop's PathState is kept and reported separately — an AD-side failure is never laundered into a cloud-side Candidate/PolicySupported.

**Tech Stack:** Go 1.23+, existing cloudgraph package (Phases 1-3), existing adchain/adprimitive packages (read-only reuse, no modifications).

**Spec:** `docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`

## Global Constraints

- **Execution:** Inline on main branch (no worktree; per user preference)
- **Model:** Sonnet only; never dispatch Opus
- **Verification:** Narrow/targeted first (per-task checks); full regression at module end
- **Changes:** Minimal only; no unrelated refactoring; adchain/adprimitive are read-only dependencies, never modified
- **Evidence:** Never fake-as-live; distinguish observed from inferred from unknown
- **Testing:** TDD required; watch every failing test before implementation
- **Commits:** Git push after every commit (Windows host)

## Review Focus

1. **Azure scope inheritance mistaken for AWS resource matching:** A role assignment scoped at the subscription level must grant access to resources in any resource group beneath it — treating scope as an exact-match string (like AWS ARN matching) would wrongly deny a valid inherited grant.
2. **Deny assignment ignored:** Azure deny assignments are rare but absolute — if the evaluator only checks role assignments (allow-only) and never checks for a deny assignment, a scenario could report PolicySupported when Azure would actually block it.
3. **Federation edge inferred from name similarity:** An AD user "alice@corp.local" and a cloud identity "alice@corp.onmicrosoft.com" must never be linked without explicit sync Provenance — matching on display name or UPN substring is exactly the kind of inference the spec prohibits.
4. **Stale federation evidence treated as current:** A FederationEdge whose Provenance is days old must degrade the hybrid path's confidence, not be treated identically to a freshly-synced edge.
5. **AD-side Blocked silently become cloud-side Candidate:** If the AD hop fails (user not reachable to the capability representing sync eligibility), the composer must report the whole hybrid path as blocked at the AD hop — never proceed to evaluate the cloud side as if the AD hop had succeeded.

---

## File Structure

**New files created:**

- `orchestrator/internal/cloudgraph/azure_evaluator.go` — AzureEvaluator (Layer C, Azure RBAC)
- `orchestrator/internal/cloudgraph/azure_evaluator_test.go` — Evaluator tests
- `orchestrator/internal/cloudgraph/federation.go` — FederationEdge type + validation
- `orchestrator/internal/cloudgraph/federation_test.go` — Federation tests
- `orchestrator/internal/cloudgraph/hybrid_composition.go` — Hybrid reachability composer
- `orchestrator/internal/cloudgraph/hybrid_composition_test.go` — Composition tests (5 Review Focus scenarios)

**Not created (deferred):**

- Real Entra ID / Azure Graph API integration (synthetic fixtures only, same as AWS in Phase 2)
- GCP IAM evaluator
- Real AD LDAP/adchain wiring into live directories (adchain itself stays untouched; composer calls it with synthetic catalogs/capabilities in tests)

---

## Task 1: Azure RBAC Evaluator (Layer C)

**Files:**
- Create: `orchestrator/internal/cloudgraph/azure_evaluator.go`
- Create: `orchestrator/internal/cloudgraph/azure_evaluator_test.go`
- Test: `orchestrator/internal/cloudgraph/azure_evaluator_test.go`

**Interfaces:**
- Consumes: CloudPermission, CloudIdentity, CloudResource, RequestContext, EvaluationResult, PathState (Phase 1-2)
- Produces: `AzureEvaluator` type with `EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult` — same method shape as AWSEvaluator, independent implementation

---

- [ ] **Step 1: Write failing test for scope-inherited role assignment**

Create `orchestrator/internal/cloudgraph/azure_evaluator_test.go`:

```go
package cloudgraph

import (
	"testing"
)

// TestAzureEvaluator_SubscriptionScopeRoleInheritsToResourceGroup verifies that a
// role assignment at subscription scope grants access to a resource nested in a
// resource group under that subscription — Azure's scope-inheritance semantic,
// which has no AWS equivalent (AWS matches ARNs, not hierarchical scope).
func TestAzureEvaluator_SubscriptionScopeRoleInheritsToResourceGroup(t *testing.T) {
	identity := &CloudIdentity{
		CanonicalID: "/subscriptions/sub-1/users/alice",
		Kind:        "entra-user",
	}

	storageAccount := &CloudResource{
		CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1",
		Kind:        "storage-account",
	}

	edge := &CloudPermission{
		Source:     identity,
		Target:     storageAccount,
		Action:     "Microsoft.Storage/storageAccounts/read",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":     "/subscriptions/sub-1",
			"role_actions":   "Microsoft.Storage/storageAccounts/read,Microsoft.Storage/storageAccounts/write",
			"assignment_kind": "role-assignment",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != PolicySupported {
		t.Errorf("Expected PolicySupported (subscription scope inherits to RG resource), got %s", result.State)
	}
	if result.AllowedBy != "role-assignment" {
		t.Errorf("Expected AllowedBy=role-assignment, got %s", result.AllowedBy)
	}
}

// TestAzureEvaluator_ResourceGroupScopeDoesNotGrantSiblingResourceGroup verifies
// scope inheritance is downward-only: an RG-scoped role does not reach resources
// in a DIFFERENT resource group under the same subscription.
func TestAzureEvaluator_ResourceGroupScopeDoesNotGrantSiblingResourceGroup(t *testing.T) {
	identity := &CloudIdentity{CanonicalID: "/subscriptions/sub-1/users/alice"}

	resourceInOtherRG := &CloudResource{
		CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-other/providers/Microsoft.Storage/storageAccounts/sa2",
	}

	edge := &CloudPermission{
		Source:     identity,
		Target:     resourceInOtherRG,
		Action:     "Microsoft.Storage/storageAccounts/read",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":   "/subscriptions/sub-1/resourceGroups/rg-data",
			"role_actions": "Microsoft.Storage/storageAccounts/read",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (RG-scoped role must not reach a sibling RG), got %s", result.State)
	}
}

// TestAzureEvaluator_DenyAssignmentOverridesRoleAssignment verifies Azure's
// explicit deny-assignment mechanism takes precedence over an otherwise-valid
// role assignment — distinct from AWS's statement-level Deny.
func TestAzureEvaluator_DenyAssignmentOverridesRoleAssignment(t *testing.T) {
	identity := &CloudIdentity{CanonicalID: "/subscriptions/sub-1/users/alice"}
	resource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}

	edge := &CloudPermission{
		Source:     identity,
		Target:     resource,
		Action:     "Microsoft.Storage/storageAccounts/delete",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":        "/subscriptions/sub-1",
			"role_actions":      "Microsoft.Storage/storageAccounts/delete",
			"deny_assignment":   "true",
			"deny_scope":        "/subscriptions/sub-1/resourceGroups/rg-data",
			"deny_actions":      "Microsoft.Storage/storageAccounts/delete",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (deny assignment overrides role assignment), got %s", result.State)
	}
	if result.BlockedBy != "deny-assignment" {
		t.Errorf("Expected BlockedBy=deny-assignment, got %s", result.BlockedBy)
	}
}

// TestAzureEvaluator_NoMatchingRoleReturnsImplicitDeny verifies default-deny
func TestAzureEvaluator_NoMatchingRoleReturnsImplicitDeny(t *testing.T) {
	identity := &CloudIdentity{CanonicalID: "/subscriptions/sub-1/users/bob"}
	resource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}

	edge := &CloudPermission{
		Source:     identity,
		Target:     resource,
		Action:     "Microsoft.Storage/storageAccounts/delete",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":   "/subscriptions/sub-1",
			"role_actions": "Microsoft.Storage/storageAccounts/read",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (no role grants delete), got %s", result.State)
	}
	if result.BlockedBy != "implicit-deny" {
		t.Errorf("Expected BlockedBy=implicit-deny, got %s", result.BlockedBy)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestAzureEvaluator -v
```

Expected: FAIL with "undefined: AzureEvaluator"

- [ ] **Step 3: Write Azure evaluator implementation**

Create `orchestrator/internal/cloudgraph/azure_evaluator.go`:

```go
package cloudgraph

import "strings"

// AzureEvaluator implements authorization evaluation for Azure RBAC.
// Independent from AWSEvaluator: Azure's scope-inheritance and deny-assignment
// semantics have no AWS equivalent, so this is a separate implementation, not
// a shared one parameterized by provider.
type AzureEvaluator struct{}

// EvaluatePermission determines if a permission edge is allowed, denied, or
// conditional under Azure RBAC. Evaluation order: a matching deny assignment
// always wins, then a role assignment whose scope covers the target and whose
// actions include the requested action, else implicit deny.
func (e *AzureEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	if isDenyAssignmentMatch(edge) {
		return &EvaluationResult{
			State:            Blocked,
			BlockedBy:        "deny-assignment",
			EvaluationMethod: "hand-coded-rules",
		}
	}

	if isRoleAssignmentMatch(edge) {
		return &EvaluationResult{
			State:            PolicySupported,
			AllowedBy:        edge.SourceType,
			EvaluationMethod: "hand-coded-rules",
		}
	}

	return &EvaluationResult{
		State:            Blocked,
		BlockedBy:        "implicit-deny",
		EvaluationMethod: "hand-coded-rules",
	}
}

// isDenyAssignmentMatch checks for a deny assignment whose scope covers the
// target and whose actions include the requested action.
func isDenyAssignmentMatch(edge *CloudPermission) bool {
	if edge.Attributes["deny_assignment"] != "true" {
		return false
	}
	denyScope := edge.Attributes["deny_scope"]
	denyActions := edge.Attributes["deny_actions"]
	return scopeCovers(denyScope, edge.Target.CanonicalID) && actionListContains(denyActions, edge.Action)
}

// isRoleAssignmentMatch checks for a role assignment whose scope covers the
// target and whose actions include the requested action.
func isRoleAssignmentMatch(edge *CloudPermission) bool {
	roleScope, hasScope := edge.Attributes["role_scope"]
	roleActions, hasActions := edge.Attributes["role_actions"]
	if !hasScope || !hasActions {
		return false
	}
	return scopeCovers(roleScope, edge.Target.CanonicalID) && actionListContains(roleActions, edge.Action)
}

// scopeCovers reports whether a role/deny assignment scope covers a target
// resource ID. Azure scope inheritance is prefix-based and downward-only:
// "/subscriptions/sub-1" covers everything under it; "/subscriptions/sub-1/
// resourceGroups/rg-data" covers only resources in that resource group, never
// a sibling resource group even under the same subscription.
func scopeCovers(scope, resourceID string) bool {
	if scope == "" {
		return false
	}
	return strings.HasPrefix(resourceID, scope+"/") || resourceID == scope
}

// actionListContains checks a comma-separated action list for an exact action match.
func actionListContains(actionList, action string) bool {
	for _, a := range strings.Split(actionList, ",") {
		if strings.TrimSpace(a) == action {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestAzureEvaluator -v
```

Expected: PASS 4/4

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/azure_evaluator.go internal/cloudgraph/azure_evaluator_test.go && git commit -m "feat(cloudgraph): Azure RBAC evaluator (Layer C)

- AzureEvaluator: independent implementation of the EvaluatePermission(edge, ctx)
  contract already used by AWSEvaluator - NOT a shared/parameterized evaluator,
  because Azure scope inheritance and deny assignments have no AWS equivalent
- scopeCovers: prefix-based downward scope inheritance (subscription -> resource
  group -> resource), sibling resource groups are NOT covered
- Deny assignment always wins over a matching role assignment
- Tests: subscription-scope inherits to RG resource, RG-scope does NOT reach a
  sibling RG, deny assignment overrides role assignment, no-match implicit deny

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Federation Edge Type & Validation

**Files:**
- Create: `orchestrator/internal/cloudgraph/federation.go`
- Create: `orchestrator/internal/cloudgraph/federation_test.go`
- Test: `orchestrator/internal/cloudgraph/federation_test.go`

**Interfaces:**
- Consumes: CloudIdentity, Provenance (Phase 1)
- Produces: `FederationEdge` type (ADIdentityRef, CloudIdentityCanonicalID, Provenance); `IsFresh(maxAge time.Duration) bool` method; `ValidateFederationEdge(edge *FederationEdge) error`

---

- [ ] **Step 1: Write failing test for federation edge requiring evidence**

Create `orchestrator/internal/cloudgraph/federation_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"
)

// TestFederationEdge_ValidRequiresProvenanceSource verifies a federation edge
// without sync evidence is rejected — it must never be constructed from name
// matching alone.
func TestFederationEdge_ValidRequiresProvenanceSource(t *testing.T) {
	edge := &FederationEdge{
		ADIdentityRef:            "S-1-5-21-DOMAIN-500",
		CloudIdentityCanonicalID: "azure:user_alice@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:     "", // no sync evidence
			ObservedAt: time.Now(),
		},
	}

	err := ValidateFederationEdge(edge)
	if err == nil {
		t.Error("Expected validation error for federation edge with no Provenance.Source")
	}
}

// TestFederationEdge_ValidWithSyncEvidence verifies a properly-evidenced edge passes
func TestFederationEdge_ValidWithSyncEvidence(t *testing.T) {
	edge := &FederationEdge{
		ADIdentityRef:            "S-1-5-21-DOMAIN-500",
		CloudIdentityCanonicalID: "azure:user_alice@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:     "entra-ad-connect-sync",
			ObservedAt: time.Now(),
		},
	}

	err := ValidateFederationEdge(edge)
	if err != nil {
		t.Errorf("Expected no validation error, got %v", err)
	}
}

// TestFederationEdge_IsFreshWithinMaxAge verifies freshness check
func TestFederationEdge_IsFreshWithinMaxAge(t *testing.T) {
	edge := &FederationEdge{
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			ObservedAt:    time.Now().Add(-1 * time.Hour),
			CollectionAge: 1 * time.Hour,
		},
	}

	if !edge.IsFresh(24 * time.Hour) {
		t.Error("Expected edge synced 1 hour ago to be fresh within a 24-hour max age")
	}
}

// TestFederationEdge_IsFreshFalseWhenStale verifies stale evidence is flagged
func TestFederationEdge_IsFreshFalseWhenStale(t *testing.T) {
	edge := &FederationEdge{
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			ObservedAt:    time.Now().Add(-72 * time.Hour),
			CollectionAge: 72 * time.Hour,
		},
	}

	if edge.IsFresh(24 * time.Hour) {
		t.Error("Expected edge synced 72 hours ago to be stale against a 24-hour max age")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestFederationEdge -v
```

Expected: FAIL with "undefined: FederationEdge" / "undefined: ValidateFederationEdge"

- [ ] **Step 3: Write federation edge implementation**

Create `orchestrator/internal/cloudgraph/federation.go`:

```go
package cloudgraph

import (
	"errors"
	"time"
)

// FederationEdge links an on-prem AD identity to a synced cloud identity.
// It must always carry real sync evidence in Provenance — never be inferred
// from display-name or UPN similarity, which is exactly the shortcut that
// produces false cross-domain links.
type FederationEdge struct {
	ADIdentityRef            string // AD SID or other AD-native identifier
	CloudIdentityCanonicalID string // CloudIdentity.CanonicalID on the synced side
	Provenance               *Provenance
}

// IsFresh reports whether this edge's sync evidence is within maxAge.
// A nil Provenance or missing CollectionAge is never fresh.
func (f *FederationEdge) IsFresh(maxAge time.Duration) bool {
	if f.Provenance == nil {
		return false
	}
	return f.Provenance.CollectionAge <= maxAge
}

// ValidateFederationEdge rejects a federation edge that lacks real sync
// evidence. Provenance.Source is the evidence: an AD-Connect sync log entry,
// an Entra federation API response, etc. An empty Source means the edge was
// constructed without checking a real sync event, which this function refuses.
func ValidateFederationEdge(edge *FederationEdge) error {
	if edge.Provenance == nil || edge.Provenance.Source == "" {
		return errors.New("federation edge requires Provenance.Source naming real sync evidence; name/UPN matching alone is not sufficient")
	}
	if edge.ADIdentityRef == "" || edge.CloudIdentityCanonicalID == "" {
		return errors.New("federation edge requires both ADIdentityRef and CloudIdentityCanonicalID")
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestFederationEdge -v
```

Expected: PASS 4/4

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/federation.go internal/cloudgraph/federation_test.go && git commit -m "feat(cloudgraph): federation edge type with evidence-required validation

- FederationEdge: links AD identity ref to cloud identity CanonicalID via Provenance
- ValidateFederationEdge: rejects any edge without Provenance.Source - a federation
  link must come from real sync evidence (AD-Connect log, Entra federation API),
  never from inferring a match on display name or UPN similarity
- IsFresh(maxAge): freshness check using Provenance.CollectionAge; nil Provenance
  is never fresh
- Tests: rejects empty Source, accepts evidenced edge, fresh-within-maxAge,
  stale-beyond-maxAge

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: Hybrid Reachability Composition

**Files:**
- Create: `orchestrator/internal/cloudgraph/hybrid_composition.go`
- Test: (written together with Task 4's test file, since composition and its test suite are co-developed — see Task 4)

**Interfaces:**
- Consumes: FederationEdge (Task 2), AzureEvaluator/AWSEvaluator (Task 1/Phase 2), adchain.Reachable (external, read-only), adprimitive.Capability (external, read-only)
- Produces: `HybridPathQuery` type (ADHeldCapabilities, ADTargetCapability, ADCatalog, ADResolver, FederationEdges, CloudEdges); `HybridPathResult` type (ADHop PathState-like string, FederationHop string, CloudHops []EvaluationResult, OverallState string); `ComposeHybridPath(query *HybridPathQuery) *HybridPathResult`

---

- [ ] **Step 1: Write the composition function (test-first in Task 4; this task lands the implementation file with its first test inline per the TDD cycle described in Task 4, Step 1 below)**

This task and Task 4 are developed as one TDD cycle: Task 4's test file drives this file's implementation. Proceed directly to Task 4 — do not write `hybrid_composition.go` before Task 4 Step 1 produces a failing test against it.

---

## Task 4: Hybrid Path Evaluation Test Suite (5 Review Focus Scenarios)

**Files:**
- Create: `orchestrator/internal/cloudgraph/hybrid_composition_test.go`
- Create: `orchestrator/internal/cloudgraph/hybrid_composition.go` (implementation, written after the test fails)
- Test: `orchestrator/internal/cloudgraph/hybrid_composition_test.go`

**Interfaces:**
- Consumes: adchain.Reachable, adprimitive.Capability, adprimitive.Primitive, adchain.ConditionResolver (external AD packages, read-only); FederationEdge (Task 2); AzureEvaluator (Task 1); CloudPermission/EvaluationResult (Phase 1-2)
- Produces: `HybridPathQuery`, `HybridPathResult`, `ComposeHybridPath` (as described in Task 3)

---

- [ ] **Step 1: Write failing test for the match scenario (AD reachable + fresh federation + cloud PolicySupported)**

Create `orchestrator/internal/cloudgraph/hybrid_composition_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// TestComposeHybridPath_FullMatch verifies the happy path: AD user is reachable
// to the capability tied to sync eligibility, the federation edge is fresh, and
// the cloud-side edge is PolicySupported. OverallState should reflect success
// end to end.
func TestComposeHybridPath_FullMatch(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "alice"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "alice-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}},
			Postconditions: []adprimitive.Capability{targetCap},
		},
	}

	fedEdge := &FederationEdge{
		ADIdentityRef:            "alice-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_alice@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 1 * time.Hour,
		},
	}

	cloudIdentity := &CloudIdentity{CanonicalID: "azure:user_alice@corp.onmicrosoft.com"}
	cloudResource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}

	cloudEdge := &CloudPermission{
		Source:     cloudIdentity,
		Target:     cloudResource,
		Action:     "Microsoft.Storage/storageAccounts/read",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":   "/subscriptions/sub-1",
			"role_actions": "Microsoft.Storage/storageAccounts/read",
		},
	}

	query := &HybridPathQuery{
		ADCatalog:         catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:        adchain.MapResolver{},
		FederationEdges:   []*FederationEdge{fedEdge},
		FederationMaxAge:  24 * time.Hour,
		CloudEdges:        []*CloudPermission{cloudEdge},
		CloudEvaluator:    &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.OverallState != "reachable" {
		t.Errorf("Expected overall reachable, got %s", result.OverallState)
	}
	if !result.ADReachable {
		t.Error("Expected AD hop to be reachable")
	}
	if result.FederationHop != "fresh" {
		t.Errorf("Expected federation hop fresh, got %s", result.FederationHop)
	}
	if len(result.CloudHops) != 1 || result.CloudHops[0].State != PolicySupported {
		t.Error("Expected cloud hop to be PolicySupported")
	}
}

// TestComposeHybridPath_NoFederationMatch verifies the no-match case: the AD
// identity has no FederationEdge at all, so the composer cannot cross domains
// and must report unknown, never infer a cloud path exists.
func TestComposeHybridPath_NoFederationMatch(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "bob"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "bob-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{Prerequisites: adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}}, Postconditions: []adprimitive.Capability{targetCap}},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{}, // no edge for bob
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.OverallState != "unknown" {
		t.Errorf("Expected unknown (no federation edge to cross), got %s", result.OverallState)
	}
	if result.FederationHop != "no-match" {
		t.Errorf("Expected federation hop no-match, got %s", result.FederationHop)
	}
}

// TestComposeHybridPath_StaleFederationEvidence verifies a federation edge that
// exists but is stale degrades the path rather than being trusted as current.
func TestComposeHybridPath_StaleFederationEvidence(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "carol"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "carol-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{Prerequisites: adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}}, Postconditions: []adprimitive.Capability{targetCap}},
	}

	staleFedEdge := &FederationEdge{
		ADIdentityRef:            "carol-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_carol@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 72 * time.Hour, // stale against a 24h max age
		},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{staleFedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.FederationHop != "stale" {
		t.Errorf("Expected federation hop stale, got %s", result.FederationHop)
	}
	if result.OverallState != "degraded" {
		t.Errorf("Expected overall degraded (stale evidence, not trusted as current), got %s", result.OverallState)
	}
}

// TestComposeHybridPath_ADBlockedStopsAtADHop verifies an AD-side failure is
// never laundered into a cloud-side Candidate — the composer must stop and
// report the AD hop as the blocking point, without evaluating cloud edges at all.
func TestComposeHybridPath_ADBlockedStopsAtADHop(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "dave"}
	unrelatedCap := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin, Target: "some-other-host"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "dave-sync-eligible"}

	// Catalog has no primitive producing targetCap from heldCap -- dave cannot reach it.
	catalog := []adprimitive.Primitive{
		{Prerequisites: adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}}, Postconditions: []adprimitive.Capability{unrelatedCap}},
	}

	fedEdge := &FederationEdge{
		ADIdentityRef:            "dave-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_dave@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 1 * time.Hour,
		},
	}

	cloudIdentity := &CloudIdentity{CanonicalID: "azure:user_dave@corp.onmicrosoft.com"}
	cloudResource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}
	cloudEdge := &CloudPermission{
		Source: cloudIdentity, Target: cloudResource, Action: "Microsoft.Storage/storageAccounts/read",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": "Microsoft.Storage/storageAccounts/read"},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{fedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{cloudEdge},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.ADReachable {
		t.Error("Expected AD hop to be unreachable")
	}
	if result.OverallState != "blocked" {
		t.Errorf("Expected overall blocked (stopped at AD hop), got %s", result.OverallState)
	}
	if len(result.CloudHops) != 0 {
		t.Error("Expected zero cloud hops evaluated -- composer must stop at the AD hop, never evaluate the cloud side as if AD had succeeded")
	}
}

// TestComposeHybridPath_CloudSideMissingTelemetryReturnsUnknown verifies that
// when the AD hop and federation hop both succeed but the cloud side has no
// edges to evaluate (e.g. discovery found no permissions for this identity),
// the overall result is unknown — never inferred as reachable.
func TestComposeHybridPath_CloudSideMissingTelemetryReturnsUnknown(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "erin"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "erin-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{Prerequisites: adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}}, Postconditions: []adprimitive.Capability{targetCap}},
	}

	fedEdge := &FederationEdge{
		ADIdentityRef:            "erin-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_erin@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 1 * time.Hour,
		},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{fedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{}, // nothing discovered on the cloud side
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.OverallState != "unknown" {
		t.Errorf("Expected unknown (AD+federation succeeded but no cloud evidence), got %s", result.OverallState)
	}
	if !result.ADReachable {
		t.Error("Expected AD hop to be reachable")
	}
	if result.FederationHop != "fresh" {
		t.Errorf("Expected federation hop fresh, got %s", result.FederationHop)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestComposeHybridPath -v
```

Expected: FAIL with "undefined: HybridPathQuery" / "undefined: ComposeHybridPath"

- [ ] **Step 3: Write the hybrid composition implementation**

Create `orchestrator/internal/cloudgraph/hybrid_composition.go`:

```go
package cloudgraph

import (
	"time"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// HybridPathQuery describes one hybrid reachability question: can the AD
// identity holding ADHeldCapabilities reach ADTargetCapability (the capability
// that represents sync eligibility, e.g. holding valid credential material for
// the identity a FederationEdge names), and if so, does crossing a fresh
// FederationEdge into the cloud side find a supported path across CloudEdges?
type HybridPathQuery struct {
	ADCatalog          []adprimitive.Primitive
	ADHeldCapabilities []adprimitive.Capability
	ADTargetCapability adprimitive.Capability
	ADResolver         adchain.ConditionResolver

	FederationEdges  []*FederationEdge
	FederationMaxAge time.Duration

	CloudEdges     []*CloudPermission
	CloudEvaluator interface {
		EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult
	}
}

// HybridPathResult reports each hop's outcome independently. OverallState
// summarizes the composed path but never collapses a hop's own state into
// another hop's meaning.
type HybridPathResult struct {
	ADReachable   bool
	FederationHop string // "fresh", "stale", "no-match"
	CloudHops     []*EvaluationResult
	OverallState  string // "reachable", "blocked", "degraded", "unknown"
}

// ComposeHybridPath runs the three hops in order, stopping early whenever an
// earlier hop fails — it never evaluates the cloud side after the AD hop or
// federation hop has already failed.
func ComposeHybridPath(query *HybridPathQuery) *HybridPathResult {
	result := &HybridPathResult{}

	reachable := adchain.Reachable(query.ADCatalog, query.ADHeldCapabilities, query.ADResolver)
	result.ADReachable = containsCapability(reachable, query.ADTargetCapability)

	if !result.ADReachable {
		result.OverallState = "blocked"
		return result
	}

	fedEdge := findFederationEdgeByADRef(query.FederationEdges, query.ADTargetCapability.Target)
	if fedEdge == nil {
		result.FederationHop = "no-match"
		result.OverallState = "unknown"
		return result
	}

	if !fedEdge.IsFresh(query.FederationMaxAge) {
		result.FederationHop = "stale"
		result.OverallState = "degraded"
		return result
	}
	result.FederationHop = "fresh"

	if len(query.CloudEdges) == 0 {
		result.OverallState = "unknown"
		return result
	}

	allSupported := true
	for _, edge := range query.CloudEdges {
		eval := query.CloudEvaluator.EvaluatePermission(edge, &RequestContext{})
		result.CloudHops = append(result.CloudHops, eval)
		if eval.State != PolicySupported {
			allSupported = false
		}
	}

	if allSupported {
		result.OverallState = "reachable"
	} else {
		result.OverallState = "blocked"
	}
	return result
}

// findFederationEdgeByADRef finds the federation edge naming this AD identity
// reference, or nil if none exists -- a missing edge is "no-match", never an error.
func findFederationEdgeByADRef(edges []*FederationEdge, adRef string) *FederationEdge {
	for _, e := range edges {
		if e.ADIdentityRef == adRef {
			return e
		}
	}
	return nil
}

// containsCapability checks whether target appears in the reachable set.
// Capability equality is Kind+Target, matching adprimitive's own comparison.
func containsCapability(reachable []adprimitive.Capability, target adprimitive.Capability) bool {
	for _, c := range reachable {
		if c.Kind == target.Kind && c.Target == target.Target {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestComposeHybridPath -v
```

Expected: PASS 5/5. Field names already verified against `orchestrator/internal/adprimitive/types.go` and `orchestrator/internal/adchain/resolver.go` at plan-writing time (`Primitive.Prerequisites.Capabilities` / `Primitive.Postconditions`, not `Requires`/`Produces`; `adchain.MapResolver` confirmed exported). If execution still finds a mismatch, fix to match the actual exported API and record the correction as a ledger ruling.

- [ ] **Step 5: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/hybrid_composition.go internal/cloudgraph/hybrid_composition_test.go && git commit -m "feat(cloudgraph): hybrid AD-to-cloud reachability composition

- HybridPathQuery/HybridPathResult/ComposeHybridPath: composes AD capability
  reachability (via existing adchain.Reachable, called read-only) with a
  FederationEdge crossing and cloud-side CloudPermission evaluation
- Each hop's state is kept independently (ADReachable, FederationHop, CloudHops)
  -- OverallState summarizes but never launders one hop's failure into another
  hop's success
- Composer stops at the first failing hop: an AD-side block means zero cloud
  edges are ever evaluated
- Tests cover all 5 Review Focus scenarios: full match, no federation match,
  stale federation evidence, AD-blocked stops before cloud evaluation,
  cloud-side missing evidence returns unknown (never inferred reachable)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Phase 4 Regression Validation & Exit Gate

**Files:**
- Modify: (none; validation only)
- Test: Full test suite

**Interfaces:**
- Consumes: All changes from Tasks 1-4
- Produces: Clean test suite, commitment to Phase 4 deliverables

---

- [ ] **Step 1: Run full cloudgraph test suite**

```bash
cd orchestrator && go test ./internal/cloudgraph -v 2>&1 | tail -60
```

Expected: All tests PASS (Phases 1-3 total ~41, Phase 4 adds ~13 = ~54 total)

- [ ] **Step 2: Run go vet**

```bash
cd orchestrator && go vet ./internal/cloudgraph/...
```

Expected: No warnings

- [ ] **Step 3: Run full orchestrator suite for regressions, including the AD packages this phase reads from**

```bash
cd orchestrator && go test ./internal/ad... ./internal/scenario... ./internal/controlval... ./internal/campaign... -v 2>&1 | tail -25
```

Expected: PASS (zero regressions; adchain/adprimitive untouched, confirmed by this run)

- [ ] **Step 4: Update ledger with exit gate summary**

Document in the plan's ledger: all 4 deliverables complete, test counts, any rulings made (especially any adprimitive.Primitive field-name corrections from Task 4 Step 2/4).

---

## Phase 4 Exit Gate Criteria

✅ Deliverable 1: Azure RBAC evaluator (AzureEvaluator; scope inheritance, deny assignments, independent from AWSEvaluator)
✅ Deliverable 2: FederationEdge type (evidence-required validation, freshness check)
✅ Deliverable 3: Hybrid composition (ComposeHybridPath calling real adchain.Reachable read-only)
✅ Deliverable 4: Hybrid path test suite (5 Review Focus scenarios, each with a dedicated test)
✅ TDD Discipline: All tests RED→GREEN verified
✅ Zero Regressions: Full test suite PASS, adchain/adprimitive packages unmodified
✅ Evidence-First: Federation edges require real Provenance; stale evidence degrades rather than being trusted

---

## Deferred (Phase 5+)

- Real Entra ID Graph API / Azure Resource Manager integration
- GCP IAM evaluator
- Real AD-Connect sync log ingestion (FederationEdge construction from real sync events)
- Wiring ComposeHybridPath into actual scenario dispatch / YAML schema
- Cloud ransomware scenarios, multi-cloud scenario breadth (Phase 5)

---

**Execution Method:** Inline on main (use superpowers:executing-plans).

**Next Step After Phase 4:** Phase 5 (Scenario Breadth & Release Validation) — the final phase.
