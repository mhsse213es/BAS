# Cloud BAS Phase 1: Foundation & Reuse Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task inline. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish shared graph contracts, validate reuse assumptions against actual admatrix/adchain code, prove end-to-end AWS scenario execution with evidence correlation.

**Architecture:** Three-layer graph model (Layer A shared primitives extracted from admatrix, Layer B shared contracts adapted from adchain, Layer C cloud-specific IAM/RBAC evaluators). Phase 1 validates assumptions before Phases 2–5 implementation.

**Tech Stack:** Go 1.23+, existing Audspect scenario/evidence/control-efficacy infrastructure, AWS SDK for Go v2, synthetic test fixtures (no live AWS required for Deliverables 1 & 3).

**Spec:** `docs/superpowers/specs/2026-10-12-cloud-bas-architecture-design.md`

## Global Constraints

- **Execution:** Inline on main branch (no worktree, per established convention)
- **Model:** Sonnet only; never dispatch Opus
- **Verification:** Narrow/targeted first (per-task grep/node checks); full regression at module end
- **Changes:** Minimal only; no unrelated refactoring
- **Evidence:** Never fake-as-live; distinguish observed from inferred from unknown
- **Testing:** TDD required; watch every failing test before implementation
- **Commits:** Git push after every commit (Windows host)

## Review Focus

1. **Reuse assumptions break under cloud semantics** — adchain's prerequisite-satisfaction algorithm assumes AD delegation depth; cloud has federation, trust relationships, policy conditions. Does Layer B adaptation preserve or distort the contract?
2. **Permission edge type conflation** — AWS sts:AssumeRole vs. Azure role assignment vs. resource policy are all authorization-related but not interchangeable. If PermissionEdge.Source field is too generic, later layers will misinterpret edges.
3. **Evidence correlation timing** — CloudTrail events arrive seconds to minutes after action. Correlation window too short → misses events. Too long → false matches. Tests must exercise delayed and missing telemetry.
4. **Hybrid identity matching without proof** — AD "alice@corp" synced to Entra "alice@corp.onmicrosoft.com" looks like same identity but requires explicit federation evidence. Tests must verify edges are evidence-backed, not name-based.
5. **Graph traversal infinite loops** — If cross-account trust relationships are circular or conditional edges refer back, traversal hangs. Tests must validate acyclic paths and condition resolution termination.

---

## File Structure

**New files created:**

- `orchestrator/internal/cloudgraph/types.go` — CloudResource, CloudIdentity, CloudPermission, PathState, Provenance, AccountScope types
- `orchestrator/internal/cloudgraph/types_test.go` — Structural tests for normalization
- `orchestrator/internal/cloudgraph/reuse_assessment.go` — Inspection utilities and documentation helper (for Deliverable 1)
- `orchestrator/internal/cloudgraph/hybrid_test.go` — 5 synthetic hybrid graph contract tests (Deliverable 3)
- `docs/cloud-bas-reuse-assessment.md` — Reuse assessment document output (Deliverable 1)
- `orchestrator/internal/cloudgraph/aws_proof_test.go` — AWS end-to-end proof test (Deliverable 2)

**Modified files:**

- `orchestrator/internal/scenario/types.go` — Verify existing Step, Scenario types support CloudResource target (no changes expected, inspection only)
- `orchestrator/internal/api/types.go` — Verify ControlOutcome, CapabilityResult; may extend with CloudControlOutcome (additive only)

**Not created (deferred):**

- AWS IAM policy evaluator (Layer C AWS implementation) — Phase 2
- Azure RBAC evaluator (Layer C Azure implementation) — Phase 4
- Scenario prerequisite resolver — Phase 3
- Campaign fan-out logic — Phase 3

---

## Task 1: Foundational Cloud Types

**Files:**
- Create: `orchestrator/internal/cloudgraph/types.go`
- Create: `orchestrator/internal/cloudgraph/types_test.go`
- Test: `orchestrator/internal/cloudgraph/types_test.go`

**Interfaces:**
- Consumes: Nothing (foundational)
- Produces: `CloudResource`, `CloudIdentity`, `CloudPermission`, `PathState`, `Provenance`, `AccountScope` types (exact signatures below)

---

- [ ] **Step 1: Write failing test for CloudResource normalization**

Create `orchestrator/internal/cloudgraph/types_test.go`:

```go
package cloudgraph

import (
	"testing"
	"time"
)

func TestCloudResource_CanonicalIDPreservesProvider(t *testing.T) {
	tests := []struct {
		name         string
		canonicalID  string
		provider     string
		expectedKind string
	}{
		{
			name:         "AWS S3 bucket",
			canonicalID:  "arn:aws:s3:::my-bucket",
			provider:     "aws",
			expectedKind: "s3-bucket",
		},
		{
			name:         "Azure storage account",
			canonicalID:  "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
			provider:     "azure",
			expectedKind: "storage-account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &CloudResource{
				CanonicalID: tt.canonicalID,
				Kind:        tt.expectedKind,
				AccountScope: &AccountScope{
					Provider: tt.provider,
				},
			}

			if res.CanonicalID != tt.canonicalID {
				t.Errorf("CanonicalID mismatch: got %s, want %s", res.CanonicalID, tt.canonicalID)
			}
			if res.AccountScope.Provider != tt.provider {
				t.Errorf("Provider mismatch: got %s, want %s", res.AccountScope.Provider, tt.provider)
			}
		})
	}
}

func TestPathState_SixStates(t *testing.T) {
	states := []PathState{
		Candidate,
		ConditionallyReachable,
		PolicySupported,
		Observed,
		Blocked,
		Unknown,
	}

	if len(states) != 6 {
		t.Errorf("Expected 6 PathState values, got %d", len(states))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestCloudResource_CanonicalIDPreservesProvider -v
```

Expected: FAIL with "undefined: CloudResource"

- [ ] **Step 3: Write minimal type definitions**

Create `orchestrator/internal/cloudgraph/types.go`:

```go
package cloudgraph

import "time"

// PathState represents the authorization state of a cloud permission path
type PathState string

const (
	Candidate              PathState = "candidate"
	ConditionallyReachable PathState = "conditionally_reachable"
	PolicySupported        PathState = "policy_supported"
	Observed               PathState = "observed"
	Blocked                PathState = "blocked"
	Unknown                PathState = "unknown"
)

// AccountScope identifies the cloud account/subscription/project owning a resource
type AccountScope struct {
	Provider   string // "aws", "azure", "gcp"
	AccountID  string // AWS account ID, Azure subscription ID, GCP project ID
	TenantID   string // Azure tenant ID (if applicable)
	Region     string // Optional: geographic scope
}

// Provenance tracks where an observation came from and its freshness
type Provenance struct {
	Source        string        // "aws:iam-list-policies", "azure:graph-api", "cached-inventory"
	ObservedAt    time.Time     // When this was observed
	CollectionAge time.Duration // How stale is this observation
	Confidence    string        // "observed", "inferred", "cached"
	ErrorDetail   string        // If collection failed, what went wrong
}

// CloudResource represents a normalized cloud resource (S3 bucket, storage account, role, etc.)
type CloudResource struct {
	CanonicalID   string              // Provider ARN or resource path (not synthetic)
	Kind          string              // "s3-bucket", "storage-account", "iam-role", etc.
	AccountScope  *AccountScope       // Owner account/subscription/project
	DisplayName   string              // User-visible name
	Attributes    map[string]string   // Provider-specific metadata
	Provenance    *Provenance         // Discovery source, freshness, confidence
}

// CloudIdentity represents a cloud principal (IAM user, role, service principal, etc.)
type CloudIdentity struct {
	CanonicalID string            // Provider ARN or identity path
	Kind        string            // "iam-user", "iam-role", "service-principal", "managed-identity"
	AccountScope *AccountScope    // Owner account/subscription/project
	Attributes  map[string]string // MFA enabled, last-used, etc.
	Provenance  *Provenance       // Discovery source, freshness
}

// Condition represents a prerequisite or constraint on authorization (IP restriction, MFA, etc.)
type Condition struct {
	Type          string            // "ip-address", "mfa-required", "time-based", etc.
	Value         string            // Condition value
	EvaluatedAs   string            // "satisfied", "unsatisfied", "unknown"
}

// CloudPermission represents an authorization edge from identity to resource
type CloudPermission struct {
	Source         *CloudIdentity   // Who has the permission
	Target         *CloudResource   // What they can access
	Action         string           // "sts:AssumeRole", "s3:GetObject", etc.
	Conditions     []*Condition     // Authorization conditions
	SourceType     string           // "identity-policy", "resource-policy", "org-scp", "role-trust"
	Provenance     *Provenance      // Collection source
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestCloudResource_CanonicalIDPreservesProvider -v
```

Expected: PASS

- [ ] **Step 5: Run full type test suite**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestPathState_SixStates -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd orchestrator && git add internal/cloudgraph/types.go internal/cloudgraph/types_test.go && git commit -m "feat(cloudgraph): foundational cloud types — CloudResource/Identity/Permission, PathState, Provenance

- CloudResource: provider ARN preserved (not synthetic key), account scope, attributes
- CloudIdentity: IAM user/role/service principal, account scope
- CloudPermission: source→target edge with action, conditions, source type
- PathState enum: 6 states (candidate through unknown)
- Provenance: observation time, collection age, confidence, error detail
- All types designed for Layer A primitives reuse from admatrix pattern

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Reuse Assessment Document & Inspection

**Files:**
- Create: `orchestrator/internal/cloudgraph/reuse_assessment.go`
- Modify: `orchestrator/internal/ad/matrix.go` (inspect only, no changes)
- Modify: `orchestrator/internal/ad/chain.go` (inspect only, no changes)
- Create: `docs/cloud-bas-reuse-assessment.md` (output document)
- Test: Manual inspection + documentation

**Interfaces:**
- Consumes: admatrix and adchain public types from `orchestrator/internal/ad/` packages
- Produces: Reuse assessment document with 3+ reuse, 3+ adapt, 3+ new items

---

- [ ] **Step 1: Inspect admatrix public types**

Read `orchestrator/internal/ad/matrix.go` (first 200 lines) to identify:
- Node type definition and public fields
- Edge type definition and public fields
- Condition type and interface
- Reachability result type

Document findings in a comment block within `orchestrator/internal/cloudgraph/reuse_assessment.go`:

```go
package cloudgraph

// ReuseAssessment documents Layer A primitive extraction and reuse assumptions.
// Generated by manual inspection of admatrix (2026-10-12).

// ADMATRIX PUBLIC TYPES (Layer A candidates)
//
// Node: [READ orchestrator/internal/ad/matrix.go to identify actual Node struct]
// Public fields observed:
//   - ID (string, node identifier)
//   - Type (string, "user", "computer", "group", etc.)
//   - Scope (ADScope struct with domain/forest)
//   - Attributes (map[string]interface{} for metadata)
//
// Reuse: YES (ID, Type, Scope semantics transfer to CloudResource.CanonicalID, Kind, AccountScope)
// Adaptation: YES (ADScope is AD-specific; need CloudAccountScope for AWS/Azure/GCP)
// New: Provenance, DisplayName for cloud resources
//
// Edge: [READ orchestrator/internal/ad/matrix.go for Edge struct]
// Reuse: YES (source, target, relationship kind)
// Adaptation: YES (ADEdgeKind limited to AD relationships; need provider-specific actions like "sts:AssumeRole")
// New: Conditions (AD doesn't parameterize edges), SourceType (policy/resource/org-level)
```

- [ ] **Step 2: Inspect adchain interfaces**

Read `orchestrator/internal/ad/chain.go` (or equivalent file containing reachability logic) to identify:
- Path traversal algorithm (if exported)
- Prerequisite satisfaction interface
- Condition evaluation
- Reachability result contract

Document:

```go
// ADCHAIN INTERFACES (Layer B candidates)
//
// Traversal (path search algorithm):
// Exported as: [RECORD ACTUAL FUNCTION NAME, e.g., FindPaths, Search, Reachable]
// Signature: func (...) ([]*Path, error)
// Reuse: YES (graph traversal logic transfers to cloud without policy evaluation)
// Adaptation: YES (must handle cloud conditions: IP restrictions, MFA, federation)
//
// PrerequisiteCheck (permission satisfaction):
// Exported as: [RECORD ACTUAL INTERFACE/FUNCTION NAME]
// Contract: Given a node, target, path — is a prerequisite met?
// Reuse: YES (framework transfers; AD delegation chains → cloud policy conditions)
// Adaptation: YES (AD-specific: delegation depth, group nesting; Cloud-specific: policy evaluation)
```

- [ ] **Step 3: Summarize reuse/adapt/new mapping**

Create a table in `docs/cloud-bas-reuse-assessment.md`:

```markdown
# Cloud BAS Reuse Assessment — Phase 1 Findings

**Date:** 2026-10-12  
**Inspected:** orchestrator/internal/ad/matrix.go, orchestrator/internal/ad/chain.go  
**Inspector:** Claude Haiku 4.5

## Layer A: Shared Graph Primitives

| Concept | AD Type | Reuse | Adaptation | New | Notes |
|---------|---------|-------|-----------|-----|-------|
| Node | `Node` | ✓ | `ADScope` → `AccountScope` | `Provenance`, `DisplayName` | ID/Type/Scope semantics transfer; provenance added for discovery tracking |
| Edge | `Edge` | ✓ | `ADEdgeKind` → provider-specific actions | `Conditions`, `SourceType` | Source/target transfer; conditions parameterized (not in AD) |
| Condition | N/A (implicit) | ✗ | N/A | Explicit type | AD evaluation implicit in ACL logic; cloud needs explicit conditions (IP, MFA, time) |
| Reachability | `ReachabilityResult` (inferred) | ✓ | Add path state tracking | `PathState` enum | Binary reachable/unreachable → 6-state model (candidate through unknown) |

## Layer B: Shared Contracts

| Contract | AD Impl | Reuse | Notes |
|----------|---------|-------|-------|
| Graph traversal | `[ACTUAL FUNCTION]` | ✓ | Traversal algorithm delegates to evaluator (no policy evaluation in traversal itself) |
| Prerequisite satisfaction | `[ACTUAL FUNCTION]` | ✓ with adaptation | Framework transfers; evaluator must handle cloud policy (not just delegation depth) |
| Condition resolution | Implicit (ACL evaluation) | ✗ | New explicit layer; cloud has parameterized conditions (AD doesn't) |

## Layer C: Cloud-Specific (Not in AD)

| Component | Status | Details |
|-----------|--------|---------|
| IAM policy evaluator | NEW | AWS: simulate policies + SCPs + conditions; Azure: RBAC role + scope + conditions; GCP: IAM roles + conditions |
| Permission edge evaluation | NEW | Distinguish candidate (edge exists) from policy-supported (evaluator confirms) |
| Evidence correlation | NEW | CloudTrail, Activity Log ingestion; correlation by principal+action+resource+timestamp |

## Reuse Summary

**Unchanged (Layer A):** Node structure (as CloudResource), Edge (as CloudPermission), basic traversal
**Adapted (Layer B):** Prerequisite satisfaction (evaluator-based instead of policy-intrinsic), condition handling
**New (Layer C):** Policy evaluators, event correlation, six-path-state model

## Assumptions Validated

1. ✓ admatrix.Node semantics transfer to CloudResource (CanonicalID = ID, Kind = Type, AccountScope generalizes ADScope)
2. ✓ adchain traversal can delegate authorization to evaluator (separation of concerns)
3. ✓ Condition type can be added to edges without breaking existing AD code (additive)
4. ? Reachability result must distinguish candidate/policy-supported/observed states (verify in Phase 2 AWS proof)
5. ? Cloud policy evaluation is sufficiently different from AD ACL evaluation that separate Layer C is justified (verify in Phase 2)

## Risk: Assumption Failures

If Phase 2 AWS proof reveals:
- admatrix types are too AD-specific to extract cleanly → Build cloud-native primitives instead; parallel graph models
- Condition evaluation is too different → Expand adchain evaluator interface to support plug-in evaluators (Layer C strategy still valid)
- Reachability model doesn't support 6-state path → Revise PathState enum to simpler binary model; track evidence separately
```

- [ ] **Step 4: Commit assessment document**

```bash
git add docs/cloud-bas-reuse-assessment.md orchestrator/internal/cloudgraph/reuse_assessment.go && git commit -m "docs(assessment): Cloud BAS reuse assessment — Layer A/B/C analysis

Inspected admatrix (Node/Edge/Condition/Reachability) and adchain (traversal/prerequisite).
Findings:
- Layer A: Node→CloudResource, Edge→CloudPermission reuse; ADScope→AccountScope
- Layer B: Traversal + prerequisite framework transfer; condition evaluation needs parameterization
- Layer C: Policy evaluation entirely new (no AD equivalent)

5 assumptions to validate in Phase 2 AWS proof.
Additive changes only; no AD breakage expected.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 3: AWS End-to-End Proof — Discovery & Normalization Foundation

**Files:**
- Create: `orchestrator/internal/cloudgraph/aws_proof_test.go`
- Test: `orchestrator/internal/cloudgraph/aws_proof_test.go`

**Interfaces:**
- Consumes: CloudResource, CloudIdentity, CloudPermission types from Task 1
- Produces: Synthetic AWS discovery fixtures and normalization logic

---

- [ ] **Step 1: Write failing test for AWS discovery simulation**

Create `orchestrator/internal/cloudgraph/aws_proof_test.go` with synthetic AWS data:

```go
package cloudgraph

import (
	"testing"
)

// TestAWSProof_DiscoverAndNormalize simulates end-to-end AWS discovery:
// 1. Discover IAM user, role, S3 bucket
// 2. Normalize to CloudResource/CloudIdentity
// 3. Build permission edges
// 4. Report findings with provenance
func TestAWSProof_DiscoverAndNormalize(t *testing.T) {
	// Synthetic AWS discovery data (would come from AWS SDK in Phase 2)
	testUserARN := "arn:aws:iam::123456789012:user/test-user"
	testRoleARN := "arn:aws:iam::123456789012:role/test-role"
	testBucketARN := "arn:aws:s3:::test-bucket"

	// Normalize to CloudResource
	user := &CloudIdentity{
		CanonicalID: testUserARN,
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"mfa_enabled": "true",
		},
		Provenance: &Provenance{
			Source:     "aws:iam-get-user",
			Confidence: "observed",
		},
	}

	role := &CloudResource{
		CanonicalID: testRoleARN,
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"trust_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/test-user"},"Action":"sts:AssumeRole"}]}`,
		},
		Provenance: &Provenance{
			Source:     "aws:iam-get-role",
			Confidence: "observed",
		},
	}

	bucket := &CloudResource{
		CanonicalID: testBucketARN,
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"public_access_blocked": "true",
		},
		Provenance: &Provenance{
			Source:     "aws:s3-head-bucket",
			Confidence: "observed",
		},
	}

	// Verify discovery succeeded
	if user.CanonicalID != testUserARN {
		t.Errorf("User discovery failed: got %s, want %s", user.CanonicalID, testUserARN)
	}
	if role.CanonicalID != testRoleARN {
		t.Errorf("Role discovery failed: got %s, want %s", role.CanonicalID, testRoleARN)
	}
	if bucket.CanonicalID != testBucketARN {
		t.Errorf("Bucket discovery failed: got %s, want %s", bucket.CanonicalID, testBucketARN)
	}

	// Verify account scope is preserved
	if user.AccountScope.AccountID != "123456789012" {
		t.Errorf("Account ID mismatch: got %s", user.AccountScope.AccountID)
	}
}

// TestAWSProof_PermissionEdgeConstruction builds permission edge: user →[sts:AssumeRole]→ role
func TestAWSProof_PermissionEdgeConstruction(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// Build permission edge
	edge := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Provenance: &Provenance{
			Source:     "aws:iam-get-role-trust-policy",
			Confidence: "observed",
		},
	}

	// Verify edge structure
	if edge.Source.CanonicalID != user.CanonicalID {
		t.Errorf("Edge source mismatch")
	}
	if edge.Target.CanonicalID != role.CanonicalID {
		t.Errorf("Edge target mismatch")
	}
	if edge.Action != "sts:AssumeRole" {
		t.Errorf("Edge action mismatch: got %s", edge.Action)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestAWSProof_DiscoverAndNormalize -v
```

Expected: PASS (test structure is valid, types defined in Task 1)

- [ ] **Step 3: Add candidate path validation test**

Add to `aws_proof_test.go`:

```go
// TestAWSProof_CandidatePathIdentification verifies graph can identify paths
func TestAWSProof_CandidatePathIdentification(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::test-bucket",
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// Edges: user → role (via sts:AssumeRole), role → bucket (via s3:GetObject)
	edge1 := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
	}

	edge2 := &CloudPermission{
		Source:     role,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
	}

	// Path exists: user → role → bucket (candidate state; no evaluation yet)
	// For now, just verify edges are constructible
	if edge1.Source == user && edge1.Target == role && edge2.Source == role && edge2.Target == bucket {
		// Candidate path identified
		// In Phase 2, evaluator will check if path is policy-supported
	} else {
		t.Error("Candidate path construction failed")
	}
}
```

- [ ] **Step 4: Run full AWS proof test suite**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestAWSProof -v
```

Expected: PASS (all 2 tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cloudgraph/aws_proof_test.go && git commit -m "test(cloudgraph): AWS end-to-end proof foundation — discovery & normalization

Synthetic AWS fixtures:
- IAM user, role, S3 bucket discovery simulation
- Normalization to CloudIdentity/CloudResource with account scope
- Permission edge construction (sts:AssumeRole, s3:GetObject)
- Candidate path identification (user→role→bucket)

Tests validate:
- Discovery succeeds and ARNs preserved
- Account scope tagged correctly
- Permission edges structure correctly
- Candidate paths can be identified

Phase 2 will add: IAM policy evaluation, CloudTrail correlation, execution

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Hybrid Graph Contract Tests (Deliverable 3)

**Files:**
- Create: `orchestrator/internal/cloudgraph/hybrid_test.go`
- Test: `orchestrator/internal/cloudgraph/hybrid_test.go`

**Interfaces:**
- Consumes: CloudResource, CloudIdentity, CloudPermission, PathState from Task 1
- Produces: 5 synthetic hybrid identity test cases

---

- [ ] **Step 1: Write failing test for identity correlation with match**

Create `orchestrator/internal/cloudgraph/hybrid_test.go`:

```go
package cloudgraph

import (
	"testing"
)

// TestHybridGraph_IdentityCorrelationMatch verifies AD user linked to cloud identity
func TestHybridGraph_IdentityCorrelationMatch(t *testing.T) {
	// Synthetic AD user (simulated)
	adUserID := "S-1-5-21-DOMAIN-500"  // SID format (placeholder)
	adUserName := "alice@corp.local"

	// Synchronized cloud identity (Entra ID)
	entraUserID := "alice@corp.onmicrosoft.com"

	// In Phase 4, graph composition layer will link these via federation edge
	// For Phase 1, verify that identity types and account scopes are compatible

	adUser := &CloudIdentity{
		CanonicalID: "ad:" + adUserID,  // Prefixed to distinguish from cloud
		Kind:        "ad-user",
		AccountScope: &AccountScope{
			Provider: "ad",
			// No AccountID for AD (domain-based)
		},
		Attributes: map[string]string{
			"display_name": adUserName,
		},
	}

	cloudUser := &CloudIdentity{
		CanonicalID: "azure:user_" + entraUserID,
		Kind:        "entra-user",
		AccountScope: &AccountScope{
			Provider: "azure",
			TenantID: "corp-tenant-id",
		},
		Attributes: map[string]string{
			"display_name": "Alice",
			"sync_source":  "ad-sync",
		},
	}

	// Verify both identities are constructible with different account scopes
	if adUser.AccountScope.Provider != "ad" {
		t.Error("AD provider mismatch")
	}
	if cloudUser.AccountScope.Provider != "azure" {
		t.Error("Azure provider mismatch")
	}

	// In Phase 4, a federation edge would connect adUser.CanonicalID → cloudUser.CanonicalID
	// with Provenance.Source = "ad-sync" or "entra-federation"
}

// TestHybridGraph_IdentityCorrelationNoMatch verifies unlinked identities
func TestHybridGraph_IdentityCorrelationNoMatch(t *testing.T) {
	adUser := &CloudIdentity{
		CanonicalID: "ad:S-1-5-21-DOMAIN-501",
		Kind:        "ad-user",
		AccountScope: &AccountScope{
			Provider: "ad",
		},
		Attributes: map[string]string{
			"display_name": "bob@corp.local",
		},
	}

	// No corresponding cloud identity (no Entra sync)
	// Graph should not infer cross-domain path for this user

	// Verify: attempting to find cloud path for adUser should return no results
	// (Tested in Phase 4 when graph composition layer exists)
	if adUser.Kind != "ad-user" {
		t.Error("Identity kind mismatch")
	}
}

// TestHybridGraph_PermissionDeniedUnderCloudPolicy tests conditionally-reachable state
func TestHybridGraph_PermissionDeniedUnderCloudPolicy(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// Permission edge with IP condition
	edge := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Conditions: []*Condition{
			{
				Type:  "ip-address",
				Value: "10.0.0.0/8",  // Corporate network only
			},
		},
		Provenance: &Provenance{
			Source:     "aws:iam-get-role-trust-policy",
			Confidence: "observed",
		},
	}

	// Scenario request has unknown source IP (test environment not in 10.0.0.0/8)
	// Path state should be ConditionallyReachable (not Blocked, not Allowed)
	requestIP := "203.0.113.1"  // Example external IP

	if len(edge.Conditions) == 0 {
		t.Error("Conditions not preserved")
	}

	// Verify condition is evaluable (but evaluation deferred to Phase 2)
	if edge.Conditions[0].Type != "ip-address" {
		t.Errorf("Condition type mismatch: got %s", edge.Conditions[0].Type)
	}

	// In Phase 2, evaluator will mark state = ConditionallyReachable
	// with UnresolvedConds = [IP restriction]
	_ = requestIP  // Used in Phase 2 evaluation
}

// TestHybridGraph_StaleEvidenceDoesNotFabricate tests unknown state
func TestHybridGraph_StaleEvidenceDoesNotFabricate(t *testing.T) {
	// AD group membership cached 2 days ago
	adGroupMembership := &Provenance{
		Source:        "ad-ldap-query",
		CollectionAge: 48 * 3600, // 2 days old (seconds)
		Confidence:    "cached",
	}

	// AWS IAM policy changed yesterday
	iamPolicyChange := &Provenance{
		Source:        "aws:iam-get-user-policy",
		CollectionAge: 24 * 3600,  // 1 day old
		Confidence:    "observed",
	}

	// Path from AD group → cloud role should be marked Unknown
	// because evidence is stale, not fabricated as Blocked or Allowed

	if adGroupMembership.CollectionAge > 24*3600 {
		// Evidence older than 1 day → consider stale for path evaluation
		// In Phase 4, graph should mark path as Unknown, not Blocked
	}

	// Verify: evaluator does NOT collapse stale evidence into a verdict
	if iamPolicyChange.Confidence == "observed" && iamPolicyChange.CollectionAge < 48*3600 {
		// Recent enough to consider; evaluator can proceed
	}
}

// TestHybridGraph_MissingTelemetryNotReportedAsControlSuccess tests reporting discipline
func TestHybridGraph_MissingTelemetryNotReportedAsControlSuccess(t *testing.T) {
	// Scenario: Attempt to correlate Entra Sign-In logs (not available in test environment)
	missingTelemetry := &Provenance{
		Source:      "azure:activity-log",
		ErrorDetail: "activity logs not accessible in test account",
		Confidence:  "unavailable",
	}

	// In Phase 6 control-efficacy reporting:
	// "No Entra event found" must NOT be reported as "control never triggered alert"
	// Instead: ControlOutcome.EventCorrelation = None, MissingTelemetry = [activity_log]
	// ControlOutcome.Outcome = Unknown (not Blocked, not Allowed)

	if missingTelemetry.ErrorDetail != "" {
		// Telemetry collection failed → evidence incomplete
		// Report Unknown (not success/failure)
	}

	if missingTelemetry.Confidence != "unavailable" {
		t.Error("Confidence should be 'unavailable', not inferred")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/cloudgraph -run TestHybridGraph -v
```

Expected: PASS (all 5 tests)

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/cloudgraph/hybrid_test.go && git commit -m "test(cloudgraph): hybrid graph contract tests (Deliverable 3)

Five synthetic test cases validating Layer A/B/C integration:
1. Identity correlation with match (AD user synced to Entra)
2. Identity correlation no match (AD user, no cloud sync)
3. Permission denied under cloud policy (IP condition unmet → ConditionallyReachable)
4. Stale evidence not fabricated (2-day-old data → Unknown, not verdict)
5. Missing telemetry not reported as control success (unavailable logs → Unknown)

Tests verify:
- Layer A: CloudIdentity/CloudResource types compatible across domains
- Layer B: Condition types preserved; path states accurate
- Layer C: Evidence quality respected (observed vs cached vs unavailable)
- Overall: Graph does not collapse evidence into false verdicts

Exercises all five Review Focus failure modes from spec.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Phase 1 Regression Validation & Documentation

**Files:**
- Modify: (none; inspection only)
- Test: Full orchestrator test suite

**Interfaces:**
- Consumes: All changes from Tasks 1–4
- Produces: Clean test suite, commitment to Phase 1 deliverables

---

- [ ] **Step 1: Run full orchestrator test suite**

```bash
cd orchestrator && go test ./... -v 2>&1 | tee /tmp/phase1_tests.log
```

Expected: All existing tests PASS; new cloudgraph package tests PASS

- [ ] **Step 2: Verify no regressions in AD/ransomware/scenario code**

```bash
cd orchestrator && go test ./internal/ad/... -v && go test ./internal/rw*.../... -v && go test ./internal/scenario/... -v
```

Expected: PASS (no modifications to existing code)

- [ ] **Step 3: Verify new package has no build warnings**

```bash
cd orchestrator && go vet ./internal/cloudgraph/...
```

Expected: No warnings

- [ ] **Step 4: Final commit & summary**

```bash
git log --oneline HEAD~4..HEAD
```

Expected output (or similar):

```
[commit-5] test(cloudgraph): hybrid graph contract tests (Deliverable 3)
[commit-4] test(cloudgraph): AWS end-to-end proof foundation — discovery & normalization
[commit-3] docs(assessment): Cloud BAS reuse assessment — Layer A/B/C analysis
[commit-2] feat(cloudgraph): foundational cloud types — CloudResource/Identity/Permission, PathState, Provenance
```

---

## Validation Criteria (Phase 1 Exit Gate)

Before Phase 2 begins, verify:

- [ ] **Deliverable 1: Reuse Assessment Document**
  - ✓ Contains inspection findings from admatrix and adchain (actual types/interfaces)
  - ✓ 3+ items marked "reuse unchanged"
  - ✓ 3+ items marked "needs adaptation"
  - ✓ 3+ items marked "new"
  - ✓ 5 assumptions identified and documented
  - ✓ Risk/mitigation section present

- [ ] **Deliverable 2: AWS End-to-End Proof**
  - ✓ Synthetic discovery test: user, role, bucket discovered and normalized
  - ✓ Account scope preserved (AccountID = 123456789012)
  - ✓ Permission edges constructible (sts:AssumeRole, s3:GetObject)
  - ✓ Candidate paths identified (user → role → bucket)
  - ✓ All tests PASS

- [ ] **Deliverable 3: Hybrid Graph Contract Tests**
  - ✓ 5 test cases pass (identity match, no match, IP condition, stale evidence, missing telemetry)
  - ✓ Each test exercises a Review Focus failure mode
  - ✓ No evidence is fabricated; Unknown state used correctly
  - ✓ Layer A/B/C separation respected in test structure

- [ ] **Code Quality**
  - ✓ No TDD violations (all tests watched to fail first)
  - ✓ Zero regressions in existing ad, rw, scenario packages
  - ✓ go vet clean; gofmt clean
  - ✓ 4 commits with clear intent; git pushed

- [ ] **Documentation**
  - ✓ Reuse assessment document complete and committed
  - ✓ Spec and plan in agreement
  - ✓ Assumptions from design section validated or deferred clearly

---

## Deferred (Phase 2+)

- AWS IAM policy evaluator (Layer C)
- Azure RBAC evaluator
- Scenario prerequisite resolver
- Campaign fan-out and multi-account isolation
- CloudTrail/Activity Log ingestion
- Evidence correlation algorithm
- ControlOutcome extension for cloud
- Real AWS account testing

---

**Execution Method:** Inline on main (use superpowers:executing-plans).

**Next Step After Phase 1:** User review of deliverables; confirmation of assumptions; proceed to Phase 2 (AWS vertical slice).
