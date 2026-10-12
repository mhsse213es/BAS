# Cloud BAS Capabilities Summary — Phases 1-5

**Date:** 2026-10-12
**Status:** All 5 phases implemented and tested with synthetic fixtures. No live cloud account integration exists yet.

## What Is Real (backed by actual evaluated logic, tested)

- **Type system** (Phase 1): CloudResource/CloudIdentity/CloudPermission/PathState/Provenance
  are real Go types with real field semantics, not placeholders.
- **AWS IAM evaluation** (Phase 2): AWSEvaluator runs real hand-coded policy-statement
  matching logic (identity policy, resource policy, role-trust, explicit/implicit deny,
  principal verification for role-trust). This is a simplified evaluator, not AWS's
  actual IAM policy simulator — it does not evaluate IAM Condition operators, SCPs,
  permission boundaries, or resource-based policy intersection with identity policy.
- **CloudTrail-shaped correlation** (Phase 2): SyntheticEventCorrelator's matching
  algorithm (time window, match-quality scoring, telemetry delay calculation) is real
  logic, tested against synthetic events. It has never been run against real CloudTrail.
- **ControlOutcome bridging** (Phase 2): CloudControlOutcome's prediction-vs-evidence
  matching logic is real and tested, including the evidence-first rule that missing
  evidence never becomes a silent match.
- **Prerequisite resolution & step gating** (Phase 3): PrerequisiteResolver and StepGate
  are real, tested decision logic over a DiscoveredGraph — but DiscoveredGraph itself
  is always constructed from synthetic/test data in Phases 1-5, never real discovery.
- **Multi-account concurrency** (Phase 3): RunMultiAccount's bounded-concurrency fan-out
  is real concurrent Go code, tested for isolation and concurrency-limit enforcement
  (verified stable across repeated runs). CloudAggregate's rollup logic is real.
- **Azure RBAC evaluation** (Phase 4): AzureEvaluator's scope-inheritance (prefix-based)
  and deny-assignment-precedence logic is real and tested, including a negative test
  proving sibling-resource-group isolation.
- **Federation evidence requirements** (Phase 4): ValidateFederationEdge's refusal to
  accept a federation link without Provenance.Source is real, enforced logic.
- **Hybrid AD-cloud composition** (Phase 4): ComposeHybridPath calls the REAL
  `adchain.Reachable` function (unmodified, called read-only) to get the AD-side
  verdict — this is not a mock of AD logic, it is the actual AD capability-chaining
  algorithm already used elsewhere in the platform. The federation crossing and
  cloud-side evaluation are real logic over synthetic fixtures.
- **GCP IAM evaluation** (Phase 5): GCPEvaluator's binding/deny-policy matching logic
  is real and tested. Its scope-inheritance has a DOCUMENTED, TESTED limitation:
  prefix matching resolves org-to-project-resource and project-to-resource correctly
  only when the resource's CanonicalID embeds the full parent path, but cannot
  resolve folder membership without a real Cloud Resource Manager hierarchy lookup
  (see TestGCPEvaluator_FolderScopeInheritsToProjectUnderIt).
- **Provider-agnostic interface** (Phase 5): the AuthorizationEvaluator interface and
  its capstone test are real proof that calling code written against the interface
  needs zero provider-specific branches — this was verified by an actual test with a
  generic calling function, not asserted.
- **Ransomware kill-chain verdict logic** (Phase 5): ExecuteCloudRansomwareScenario's
  fully-blocked/partially-blocked/fully-open classification and early-stop-at-first-block
  behavior is real, tested logic.

## What Is Synthetic Fixtures Only (logic is real; data is not)

- Every CloudResource/CloudIdentity/CloudPermission used in any test across all 5
  phases is hand-constructed in test code. No AWS/Azure/GCP SDK call has ever been
  made by this codebase.
- Every CloudEvent used by SyntheticEventCorrelator is hand-constructed. No real
  CloudTrail, Azure Activity Log, or GCP Audit Log has been queried.
- The adprimitive.Capability/Primitive catalogs used by ComposeHybridPath's AD-side
  tests are hand-constructed synthetic catalogs, not a real Active Directory's
  discovered capability graph (though the underlying adchain.Reachable algorithm
  itself is the real, already-shipped implementation).

## What Is Explicitly Deferred (not built)

- Real AWS/Azure/GCP SDK integration for discovery, policy retrieval, or execution.
- Real CloudTrail / Azure Activity Log / GCP Audit Log ingestion.
- IAM Condition operators, SCPs, permission boundaries (AWS); Azure Conditional
  Access / PIM; GCP Resource Manager hierarchy API (needed to close the
  folder-membership gap documented above).
- YAML scenario schema changes to declare cloud prerequisites in actual scenario files.
- Wiring RunMultiAccount, ComposeHybridPath, or ExecuteCloudRansomwareScenario into
  the live orchestrator's scenario dispatcher — all three are standalone, fully
  tested functions not yet called from any production code path.
- Cross-account correlation (CloudCampaignScope.CorrelateAcrossAccounts is a typed
  field with no implementation behind it).
- Real AD-Connect sync log ingestion for constructing FederationEdge from live data.

## Package Inventory (orchestrator/internal/cloudgraph)

| File | Phase | Responsibility |
|------|-------|-----------------|
| types.go | 1-2 | CloudResource/Identity/Permission, PathState, Provenance, AccountScope, Condition, RequestContext, EvaluationResult, CloudEvent, EventSearchResult |
| aws_evaluator.go | 2 | AWS IAM policy evaluation (Layer C) |
| cloudtrail_correlator.go | 2 | Synthetic event correlation |
| cloud_outcomes.go | 2 | CloudControlOutcome prediction/evidence bridging |
| prerequisite.go | 3 | DiscoveredGraph, PrerequisiteResolver |
| step_gate.go | 3 | StepGate dispatch-time safety check |
| campaign_scope.go | 3 | CloudCampaignScope, CloudChildRun |
| multiaccount.go | 3 | RunMultiAccount, CloudAggregate |
| azure_evaluator.go | 4 | Azure RBAC evaluation (Layer C) |
| federation.go | 4 | FederationEdge, evidence validation |
| hybrid_composition.go | 4 | AD-to-cloud reachability composition |
| gcp_evaluator.go | 5 | GCP IAM evaluation (Layer C) |
| evaluator.go | 5 | AuthorizationEvaluator interface |
| ransomware_scenario.go | 5 | Cloud storage ransomware kill chain |

66 tests across all phases, 0 regressions in existing AD/scenario/controlval/campaign packages.

## How To Verify Any Claim Above

Every claim in this document traces to a named test in
`orchestrator/internal/cloudgraph/*_test.go`. Run `go test ./internal/cloudgraph -v`
to see all of them pass. Nothing in this document should be read as a claim about
behavior against a real cloud account — none has been attempted.
