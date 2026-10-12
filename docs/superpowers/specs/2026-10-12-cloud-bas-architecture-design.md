# Cloud BAS Mastery: Architecture Design

**Date:** 2026-10-12  
**Author:** Claude Haiku 4.5  
**Status:** Design Approved (Awaiting Implementation Plan)

---

## Executive Summary

Audspect Cloud BAS Mastery is a cloud security control validation platform that proves whether deployed controls prevent, detect, investigate, and respond to realistic attack paths across AWS, Azure, Microsoft 365, Kubernetes, and hybrid on-premises Active Directory environments.

**Architectural Approach:**
- Extend Audspect's existing scenario execution, evidence correlation, and control-efficacy architecture to cloud providers
- Build shared graph primitives (Layer A) and prerequisite-satisfaction contracts (Layer B), reusing proven AD mastery patterns where semantics align
- Keep cloud-specific authorization evaluation (Layer C) isolated from shared infrastructure
- Maintain YAML as the scenario contract; add graph modeling for cloud relationships and path discovery
- Preserve evidence-first control efficacy: distinguish observed events from inferred paths and unresolved conditions

**Timeline:** 16 weeks (5 phases), contingent on AWS vertical slice validation and measured reuse

**Key Decision:** Shared graph contracts + domain-specific authorization semantics + composition at canonical layer. No separate graph execution engine. YAML remains the execution contract.

---

## 1. Architectural Overview & Layered Model

### The 8 Layers

Cloud BAS decomposes into 8 connected layers, with explicit reuse and extension boundaries:

#### Layer 1: Cloud Inventory & Normalization (New)
- AWS/Azure/GCP account and subscription discovery
- Normalize identities, resources, roles, permissions into canonical model
- Preserve provider-specific IDs, scope, and provenance
- Read-only operations; no state changes

#### Layer 2: Cloud Graph & Authorization (New + Layer A Reuse)
- **Layer A (Shared Primitives, extracted from admatrix):** Node, Edge, Condition, Reachability result types
- **Layer C (Cloud-Specific Semantics, new):** IAM/RBAC policy evaluators; authorization verdict derivation
- Candidate path identification; distinguish possible paths from authorized paths
- No universal permission evaluator; each provider has its own evaluation logic

#### Layer 3: Hybrid Identity & Trust (New + Integration Point)
- AD graph + cloud graph brought together at canonical layer
- Identity correlation (AD sync, federation, service principals)
- Cross-domain edge discovery without merging identities

#### Layer 4: Scenario Planning & Prerequisites (Extend Existing)
- YAML scenarios continue to describe test intent and steps
- **Prerequisite resolver** checks scenario applicability against observed resources and permissions
- Reuse adchain's prerequisite-satisfaction framework (Layer B) where cloud semantics permit
- Do not execute a scenario unless all prerequisites pass

#### Layer 5: Controlled Execution Adapters (New Cloud Adapters)
- AWS, Azure, GCP provider-specific implementations behind common contract
- Reuse existing Step framework for dispatch
- Bounded execution: explicit scope, time limits, cleanup behavior

#### Layer 6: Evidence & Control-Efficacy Engine (Extend Existing)
- Cloud event ingestion (CloudTrail, Activity Log, Cloud Logging)
- Extend ControlOutcome to preserve provider-specific denial reasons
- Six-state path mapping (candidate, conditionally-reachable, policy-supported, observed, blocked, unknown)
- Distinguish what was observed from what was inferred from what remains unknown

#### Layer 7: Risk & Business Impact (Extend Existing)
- Prioritize validated paths by affected asset, control failure, recovery dependency
- Cloud-specific: account blast radius, data-residency impact, compliance exposure
- Reuse existing risk model; add cloud-native dimensions

#### Layer 8: Campaigns, Reporting & Remediation (Extend Existing)
- Multi-account, multi-subscription, multi-tenant campaign fanning
- Child-run isolation and aggregated reporting
- Evidence packs with path state, control verdicts, limitations, and remediation verification

### Reuse + Extension Strategy

| Component | Reuse | Extend | New |
|-----------|-------|--------|-----|
| Scenario execution | ✓ Existing dispatch framework | Add cloud adapters | CloudEvent ingestion |
| Evidence model | ✓ CapabilityResult + CorrelationKey | Handle async events | CloudEvent type, PathState enum |
| Control outcomes | ✓ Outcome enum | Preserve provider reasons | Six-state mapping, GraphVsExecutionMatch |
| Campaign aggregation | ✓ Child-run isolation | Add account dimension | AccountScope, ChildRunSummary |
| Graph primitives | ✓ Extract from admatrix | Support multi-account scope | CloudResource, CloudIdentity, CloudPermission |
| Authorization logic | ✗ Separate | N/A | Layer C evaluators (AWS, Azure, GCP) |
| Graph traversal | ✓ Reuse adchain | Add cloud-specific conditions | Prerequisite gate, path state tracking |

---

## 2. Phase 1 Deliverables (Weeks 1–2)

Before proceeding to implementation, Phase 1 delivers three concrete outputs that validate reuse assumptions and establish architectural contracts.

### Deliverable 1: Reuse Assessment Document

**Output:** `docs/cloud-bas-reuse-assessment.md`

**Contents:**
- Actual admatrix public types (Node, Edge, Condition, Reachability result); which reuse unchanged, which need adapters, which are new
- Actual adchain interfaces (traversal, prerequisite satisfaction, path search); which assumptions break under cloud semantics
- Evidence binding audit (can ControlOutcome, CapabilityResult, Provenance represent async CloudTrail events?)
- Explicit mapping: 3+ reuse items (unchanged), 3+ adapter items (modified), 3+ new items

**Acceptance:** Each item grounded in type inspection and documented assumptions. No "assume this works" statements.

### Deliverable 2: Minimal AWS End-to-End Proof (Lab-Gated)

**Executable test with authorized AWS test account:**

1. **Discover:** IAM ListUsers, ListRoles, GetUser, ListAttachedUserPolicies from test account
2. **Normalize:** Convert to canonical {Identity, Role, Permission} tuple
3. **Graph:** Build candidate path: TestUser → sts:AssumeRole → TestRole → s3:GetObject → S3Bucket
4. **Evaluate:** Check AWS IAM policy evaluation (candidate vs. policy-supported)
5. **Correlate:** Simulate read attempt or mock CloudTrail event; correlate to evidence
6. **Report:** Output {path state, supporting evidence, control verdicts, limitations} with provenance

**Acceptance Criteria:**
- Discovers ≥1 identity, ≥1 role, ≥1 resource from AWS
- Evaluates permissions correctly (allowed/denied by policy)
- Distinguishes candidate path from policy-supported path
- Correlates evidence with timestamps and source IDs
- Reports result with explicit provenance (observed vs. inferred)
- Cleanup verified (no lingering resources)

**Scope:** Single AWS account, bounded IAM/S3 scenario, no ransomware, no multi-account, no vendor SIEM. Proof that contract + reuse + evidence work for one bounded case.

### Deliverable 3: Hybrid Graph Contract Tests (Synthetic Fixtures)

**Test suite:** `orchestrator/internal/cloudgraph/hybrid_test.go`

**Five test cases (synthetic AD + cloud identities):**

1. **Identity correlation — match found:** AD user synced to Entra; cloud graph links them; reachability test works
2. **Identity correlation — no match:** AD user with no Entra sync; no cross-domain path inferred
3. **Permission denied under cloud policy:** Candidate path with IP condition unmet; path state = ConditionallyReachable (not Blocked)
4. **Stale evidence:** AD group cached 2 days ago; AWS policy changed yesterday; path marked Unknown (not fabricated as Blocked)
5. **Missing telemetry:** Scenario attempts to correlate Entra Sign-In logs (not available); result reports evidence unavailable (not "control never triggered alert")

**Acceptance:** All 5 tests pass using Layer A contracts, Layer C semantics, and Layer B composition. No live cloud required; synthetic fixtures only.

---

## 3. Cloud Resource Normalization & Canonical Model

### Core Types

**CloudResource** (normalized across AWS/Azure/GCP)
- `CanonicalID`: Provider ARN or resource path (not synthetic key)
- `Kind`: "s3-bucket", "storage-account", "iam-role", etc.
- `AccountScope`: AWS account ID, Azure subscription+tenant, or GCP project
- `DisplayName`, `Attributes`: User-visible name and provider-specific metadata
- `Provenance`: Discovery source, timestamp, confidence

**CloudIdentity** (user, role, service principal, workload identity)
- `CanonicalID`: Provider ARN or identity path
- `Kind`: "iam-user", "iam-role", "service-principal", "managed-identity", etc.
- `AccountScope`, `Attributes`, `Provenance`: Ownership account/tenant and metadata

**CloudPermission** (authorization edge)
- `Source`: CloudIdentity
- `Target`: CloudResource
- `Action`: "sts:AssumeRole", "s3:GetObject", etc.
- `Conditions`: IP restrictions, MFA requirement, time-based constraints
- `SourceType`: "identity-policy", "resource-policy", "org-scp", "role-trust" (observable fact, not evaluation result)
- `Provenance`: Collection source, observation time, age, confidence

**Provenance** (existing, reuse/extend)
- `Source`: "aws:iam-list-policies", "azure:graph-api", "cached-inventory", etc.
- `ObservedAt`, `CollectionAge`: When observed and how stale
- `Confidence`: "observed", "inferred", "cached"
- `ErrorDetail`: If collection failed

### Design Decisions

1. **CanonicalID = provider ARN/path:** Preserves provider semantics; enables audit trail linking
2. **AccountScope as metadata:** Enables per-account filtering without hierarchical nesting
3. **CloudPermission.SourceType as observable tag:** "which policy granted this?" not "did this work?"
4. **Conditions as structured data:** Deferred evaluation; Layer C evaluator handles semantics

---

## 4. IAM Permission Graph & Authorization Evaluation (Layer C)

### AuthorizationEvaluator Interface

Each cloud provider implements an evaluator that determines whether a permission edge is authoritative given a request context:

```
EvaluatePermission(edge, requestContext) → AuthorizationResult {
  State: Allowed | Blocked | ConditionallyReachable | Unknown
  AllowedBy: policy ARN (if Allowed)
  BlockedBy: deny rule or control (if Blocked)
  UnresolvedConds: conditions we cannot evaluate
  Evidence: Provenance of this decision
  EvaluationMethod: "policy-simulation" | "live-test" | "cached-decision" | "inference"
}
```

### PathState Enum (Six States)

1. **Candidate:** Relationships exist; authorization unknown
2. **ConditionallyReachable:** Some conditions unresolved (e.g., IP restriction without request source)
3. **PolicySupported:** Policies permit under stated assumptions
4. **Observed:** Test or trustworthy telemetry confirmed
5. **Blocked:** Known control prevents the path
6. **Unknown:** Evidence insufficient or stale

### Graph Construction

Traverse permission edges (Layer A primitives) using Layer B reachability, checking each edge with Layer C evaluator. Preserve per-edge path state. Do not collapse edges into binary reachable/blocked.

### Evidence Binding

When scenario step executes:
1. Prerequisite gate checks graph (can run if PolicySupported)
2. Dispatcher executes actual AWS API call or mock
3. CloudTrail event collected and correlated
4. ControlOutcome reports both graph prediction and execution result
5. Mismatch detection: "Graph predicted Allowed but execution was Blocked" signals policy gap or inventory staleness

---

## 5. Scenario Prerequisites & Execution Gating

### Prerequisite Schema (YAML Extension)

Scenarios declare prerequisites:
- `cloud_identity`: Required test user/role exists in account
- `cloud_resource`: Required resource (role, S3 bucket, etc.) exists
- `cloud_permission`: Required permission edge exists (at least Candidate state)
- `audit_availability`: CloudTrail, Activity Log available for correlation

### PrerequisiteResolver

Checks whether scenario can run in observed environment:
- Status OK → dispatch scenario
- Status MISSING → skip; account missing required identity
- Status DEGRADED → dispatch; CloudTrail unavailable but execution continues
- Status UNKNOWN → skip; insufficient inventory

**Prerequisite ≠ Execution Authorization:**
- Prerequisite gate filters applicability (conservative: skip if unsure)
- Execution authorization comes from user provision + control checking
- Step-level gate prevents dispatch only if prerequisite explicitly unmet (e.g., permission edge is Blocked state)

### Step-Level Gating

Before dispatching a step:
```
if step.Prerequisites.cloud_permission_reachable:
  edge = graph.FindPermissionEdge(source, target, action)
  state = edge.State()
  if state in [Blocked, Unknown]:
    return false  // Don't dispatch
```

---

## 6. Evidence Correlation & Control-Efficacy

### CloudEvent Type

Extend CapabilityResult to collect:
- `CorrelatedEvents`: CloudTrail, Activity Log events matching the step execution
- `EventSearchWindow`: How far after step we searched (e.g., 5 minutes)
- `EventsFound`: Count of matched events
- `SearchStatus`: "complete", "timeout", "partial"

### CloudControlOutcome (Extend ControlOutcome)

```
PrerequisiteState: PathState (what graph predicted)
ExecutionOutcome: Allowed | Blocked | MFAChallenged | Terminated | Unknown
ControlName: AWS S3 Block Public Access | Azure Resource Policy | IP Restriction
ControlVerdictReason: Exact deny reason or allow condition
GraphVsExecutionMatch: Did graph prediction match execution? (bool)
Mismatch: If no match, what diverged
EventCorrelation: Perfect | Partial | None | Delayed
TelemetryDelay: How long after action did event appear
MissingTelemetry: Which audit logs were unavailable
```

### Correlation Algorithm

After execution:
1. Build search criteria from scenario step (principal, resource, action, time window)
2. Query audit logs (CloudTrail, Activity Log)
3. Match events to execution attempt (timestamp ±30s, principal, action, resource)
4. Assess correlation quality (immediate, delayed, missing)
5. Build ControlOutcome preserving both prediction and observation

### Design Decision: Evidence Quality Matters

- Event found + outcome confirmed → High confidence
- Event delayed (5+ min) → Note delay; don't fabricate real-time response
- Event missing → Mark Unknown (not Allowed/Blocked without evidence)
- Multiple conflicting events → Preserve all; report contradiction

---

## 7. Multi-Account Campaign Scope & Isolation

### Campaign Model Extension

```
CloudCampaignScope {
  Accounts: [AWS account A, Azure subscription B, GCP project C, ...]
  MaxConcurrency: 3 (parallel child runs)
  TimeoutPerAccount: 30 minutes
  PreserveAccountContext: true (tag all evidence with account ID)
  CorrelateAcrossAccounts: false (default; optional later)
}
```

### Child Run Isolation

Each account gets independent scenario runs:
- Separate discovery (DiscoveryEvidence)
- Separate prerequisite check (PrerequisiteCheckResult)
- Separate execution (CapabilityResults, ControlOutcomes, Events)
- Separate summary (ChildRunSummary)

All evidence tagged with AccountTarget; never merged or collapsed.

### Campaign Execution Flow

1. **Enumerate targets:** Campaign → 5 ChildRun instances (one per account)
2. **Per-account discovery:** Assume role, discover IAM/resources, build CloudInventory
3. **Prerequisite gating:** Per-account; decision: dispatch, skip (missing), or degrade (telemetry gap)
4. **Scenario execution:** Up to MaxConcurrency parallel; each step tagged with account ID
5. **Aggregation:** Collect per-account summaries; optionally analyze patterns ("control failed in >50% of accounts")

### Campaign Reporting

- **Per-account breakdown:** ChildRunSummary per account
- **Aggregated metrics:** Total accounts, completed, skipped
- **Control aggregation:** Which controls failed in which accounts; failure rate
- **Default: Isolation before correlation** — each account evaluated independently

### Design Decision: Campaign Scope ≠ Scenario Scope

Scenarios remain provider-agnostic and account-agnostic. Campaigns apply scenarios to specific accounts. No scenario logic changes per account.

---

## 8. Reuse Assessment & Timeline

### Reuse Assumptions

1. **admatrix Layer A:** Node, Edge, Condition, Reachability contracts can be extracted and reused for cloud primitives without distorting AD semantics
2. **adchain Layer B:** Prerequisite-satisfaction algorithm and path traversal transfer to cloud with conditional edge support
3. **Evidence model:** CapabilityResult + CorrelationKey can represent async CloudTrail events with provenance preservation
4. **Control outcomes:** Outcome enum extensible to include provider-specific denial reasons without breaking existing ransomware/AD code
5. **Campaign aggregation:** Child-run isolation + summary rollup pattern transfers directly to multi-account scope

**Validation:** Phase 1 deliverables (reuse assessment, AWS proof, hybrid tests) confirm or revise these assumptions before implementation begins.

### 16-Week Timeline (5 Phases)

| Phase | Weeks | Deliverable | Exit Criteria |
|-------|-------|---|---|
| 1 | 1–2 | Foundation contracts, reuse assessment, AWS proof, hybrid tests | Reuse assumptions validated; shared/domain-specific boundaries locked |
| 2 | 3–6 | AWS vertical slice: discovery, IAM graph, CloudTrail correlation, controlled scenarios | End-to-end AWS flow proven; evidence correlates correctly; 1 scenario executes and reports |
| 3 | 7–9 | Prerequisites & campaigns: scenario applicability, multi-account fan-out, cloud backup observers | Multi-account isolation working; per-account evidence preserved; campaign aggregation proven |
| 4 | 10–12 | Azure, hybrid identity, composed paths: Azure/Entra discovery, AD-cloud federation, real cross-domain paths | Hybrid identity model working; cross-domain edges discovered; AD-to-cloud and cloud-to-AD paths validated |
| 5 | 13–16 | Scenario breadth & release validation: cloud ransomware, backup assurance, data-access, detection scenarios; remediation re-testing; error handling; deployment | Release-ready; evidence integrity proven; failure handling robust; deployable to real customer cloud environments |

**Contingencies:**
- AWS proof fails to validate reuse → Revise Phases 2–3 scope; extend Phase 1
- Multi-account isolation proves difficult → Defer Phase 3 campaign work to Phase 4; narrow Phase 3 scope
- Azure federation complex → Defer full hybrid support to Phase 5; focus Phase 4 on single-tenant Azure

**Assumption:** Team has access to authorized AWS test account (Phase 2) and Azure test tenant (Phase 4). If not available, shift to mock-backed testing and mark results as Phase 6+ candidates.

---

## 9. Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| admatrix/adchain reuse breaks cloud semantics | Timeline slip (Phases 2–3 rework) | Reuse assessment (Phase 1) validates before implementation; Layer B adaptation explicit in code |
| CloudTrail/Activity Log ingestion delays evidence | Control verdicts become stale/unreliable | Design for asynchronous event arrival; mark delayed evidence; report Unknown when telemetry missing |
| Multi-account isolation leaks evidence | Audit trail becomes ambiguous | ChildRun evidence always tagged with AccountID; composition layer enforces isolation by default |
| Graph inference misleads scenarios | Scenarios execute against stale permissions | Preserve candidate/unknown path states; prerequisite gate conservative (skip if unsure) |
| Provider API rate limits block discovery | Campaign execution hangs | Discovery implements exponential backoff + queue; Phase 2 test account validates limits |
| Hybrid identity matching too aggressive | False positive paths (AD identity matches cloud identity without proof) | Synthetic tests (Phase 1 #3) verify; require explicit federation/sync evidence; mark inferred paths separately |

---

## 10. Open Questions / Future Phases

**Deferred (not blocking implementation):**
- GCP support (Phase 7+)
- Additional SaaS platforms (Okta, Salesforce, etc.)
- Real ransomware and backup scenarios (Phase 5 end)
- Vendor SIEM integration (Phase 4 early)
- Cloud cost/resource impact reporting
- Remediation automation (currently manual re-test)

**In-Scope for Phase 1–5:**
- AWS + Azure/Entra + hybrid AD only
- Evidence-first control efficacy (no score inflation)
- Lab-gated, no real customer data
- Safety: bounded execution, least-privilege discovery, explicit cleanup

---

## Conclusion

Cloud BAS Mastery extends Audspect's proven architecture to cloud environments by reusing shared graph and evidence contracts while keeping provider authorization semantics isolated. The three Phase 1 deliverables validate reuse assumptions before implementation. The 5-phase roadmap delivers AWS/Azure/hybrid AD support with evidence-backed control validation by week 16, contingent on measured progress through each phase's exit criteria.

---

**Next Step:** User review of this specification. After approval, invoke writing-plans skill to create detailed implementation plan.
