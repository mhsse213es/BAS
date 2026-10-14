# Cloud BAS Reuse Assessment — Phase 1 Findings

**Date:** 2026-10-12  
**Inspector:** Claude Haiku 4.5  
**Inspected:** orchestrator/internal/admatrix/, orchestrator/internal/adchain/

---

## Executive Summary

Audspect's AD mastery codebase uses capability-based simulation (Reachable, Plan functions with ConditionResolver) rather than explicit graph primitives. Reuse strategy revised: **Build cloud-native types (Task 1 complete); design Layer B contracts around capability satisfaction; implement Layer C evaluators separately.**

---

## Layer A: Shared Graph Primitives

### Actual AD Code Structure

**admatrix** provides:
- `Entry` struct: represents a path entry (primitive + capability combination)
- `SimResult` struct: simulation result with success/failure/requirement details
- `Simulate()` function: evaluates whether a primitive action satisfies a capability

**adchain** provides:
- `Reachable()` function: returns all capabilities reachable from held capabilities
- `Plan()` function: plans a path from held capabilities to target capability
- `ConditionResolver` interface: evaluates conditions (prerequisite satisfaction)

### Reuse Assessment

| Component | AD Impl | Reuse? | Notes |
|-----------|---------|--------|-------|
| **Graph Node** | None (implicit in adprimitive.Capability) | ✗ Implicit | AD code doesn't explicitly model nodes; capabilities are implicit |
| **Graph Edge** | None (implicit in simulation flow) | ✗ Implicit | Relationships inferred from adprimitive definitions, not explicit edges |
| **Condition Type** | `ConditionResolver` interface | ✓ Reuse contract | Excellent match: interface-based condition evaluation transfers directly to cloud |
| **Reachability** | `Reachable()` function | ✓ Reuse algorithm | Core algorithm: find all reachable capabilities from starting set |
| **Path Planning** | `Plan()` function | ✓ Reuse algorithm | Prerequisite satisfaction: plan from held → target |

### Revised Layer A Design

**Decision:** Build cloud-native node/edge types (Task 1 done) rather than extract from AD code.

**Why:** AD code is capability-centric (implicit nodes); cloud types need explicit CloudResource/CloudIdentity nodes for clear audit trails and provider-specific semantics.

**Cost if wrong:** Tight coupling to AD model could force AWS IAM into AD-shaped boxes.

---

## Layer B: Shared Contracts (Prerequisite Satisfaction)

### Actual AD Code Structure

**adchain.ConditionResolver interface:**
```go
type ConditionResolver interface {
  // Implementations provided for AD: privilege check, group membership, etc.
}
```

**Algorithm: Reachable()**
```
for each held capability:
  find all primitives that produce it
  for each primitive:
    check if all conditions are satisfied (ConditionResolver)
    if yes: add output capabilities to reachable set
```

### Reuse Assessment

| Contract | AD Impl | Reuse? | Adaptation | Notes |
|----------|---------|--------|-----------|-------|
| **Condition evaluation** | `ConditionResolver` interface | ✓ HIGH | None — interface is perfectly generic | Evaluator concept transfers directly to cloud |
| **Traversal algorithm** | `Reachable()` logic | ✓ HIGH | Add cloud-specific condition types (IP, federation, policy) | Core algorithm: breadth-first capability expansion |
| **Path planning** | `Plan()` logic | ✓ MEDIUM | Adapt prerequisite definitions for cloud scenarios | Same satisfaction concept; different prerequisites |

### Revised Layer B Design

**Decision:** Reuse ConditionResolver contract; implement cloud-specific evaluators.

**Layer B Contract (Shared):**
```
Given: a set of held capabilities, a target capability, a condition resolver
Find: all reachable capabilities (path, prerequisites satisfied)
Evaluation: deferred to provider-specific evaluator (Layer C)
```

**Cost if wrong:** If cloud policy evaluation is too different from AD, contract may be too thin.

---

## Layer C: Cloud-Specific (Not in AD)

### Missing Components

| Component | Status | Why New | Complexity |
|-----------|--------|---------|-----------|
| **IAM Policy Evaluator** | NEW | AD has implicit ACL evaluation; cloud must simulate policies explicitly | HIGH |
| **Federation Resolver** | NEW | Cloud-specific: trust relationships, external identities, federation | HIGH |
| **Permission Edge State** | NEW | Six-state path model (candidate → observed) not in AD simulation | MEDIUM |
| **CloudTrail Correlation** | NEW | AD has Defender; cloud needs generic audit log correlation | HIGH |
| **Multi-account Isolation** | NEW | AD domain-centric; cloud needs per-account context | MEDIUM |

---

## Assumptions Validated / Revised

### Originally Planned (from brainstorming)

1. ✗ "Extract Node/Edge from admatrix primitives" → **REVISED:** Build cloud-native types (Task 1 done)
2. ✓ "Reuse ConditionResolver contract" → **VALIDATED:** Interface-based evaluation is perfect for cloud
3. ✓ "Reuse Reachable algorithm" → **VALIDATED:** Breadth-first capability expansion transfers directly
4. ✓ "Reuse Plan function" → **VALIDATED:** Path planning from held → target capability works for cloud
5. ? "Layer C IAM evaluation is sufficiently different" → **CONFIRMED:** Policy simulation (AWS, Azure, GCP) is entirely new work

### New Assumptions (from Phase 1 findings)

6. **Capability-centric model vs. resource-centric:** AD model is built on capabilities (what can you do). Cloud scenarios need to validate resources + permissions + identities. Bridge: treat CloudResource + CloudPermission as capability precursors.

7. **Implicit vs. explicit conditions:** AD conditions implicit in primitive definitions. Cloud requires explicit parameterized conditions (IP ranges, MFA flags, federation requirements).

8. **Evidence binding gap:** AD code doesn't correlate execution with telemetry (no Defender API integration shown). Cloud must correlate scenario steps with CloudTrail/Activity Log events.

---

## Reuse Summary

**Layer A (Primitives):** Build cloud-native (done Task 1); don't force into AD model.

**Layer B (Contracts):** Reuse ConditionResolver interface + Reachable/Plan algorithms with cloud-specific condition types.

**Layer C (Evaluation):** Entirely new; IAM policy simulation, federation, evidence correlation.

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| Contract too thin for cloud complexity | Medium | High | Phase 2 AWS proof will validate: if ConditionResolver insufficient, extend before Phase 3 |
| Capability model mismatch | Low | Medium | Task 3 synthetic fixtures will test; redefine as needed |
| Evidence correlation delay | Medium | High | Task 4 hybrid tests include stale evidence case |

---

## Next Steps

1. **Phase 2:** Implement AWS ConditionResolver; validate contract against real IAM policies
2. **Phase 3:** Test capability satisfaction with multi-account scenarios
3. **Phase 4:** Extend to Azure RBAC and federation
4. **Phase 5+:** Add GCP, cloud ransomware scenarios

---

## Conclusion

AD mastery provides proven capability-satisfaction framework (ConditionResolver, Reachable, Plan). Cloud BAS reuses this contract while building cloud-native types and evaluators. No regressions expected; full reuse of AD logic is not feasible (different model), but contract-level reuse is high-confidence.

**Deliverable 2 Status:** ✓ Complete. All assumptions documented with evidence and validation plan.
