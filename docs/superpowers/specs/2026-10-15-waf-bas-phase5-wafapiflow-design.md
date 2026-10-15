# WAF BAS Mastery Phase 5: API and Business-Flow Protection — `internal/wafapiflow` Design

**Status:** Approved for implementation under the user's standing authorization to complete all WAF BAS Mastery phases autonomously ("fix any critical or important findings then move to the next phase without approval start spec plan and native" / "keep going until all phases are done"). Condensed self-directed brainstorm — no interactive Q&A round; design decisions below are this session's own reasoned choices, made explicit for review.

## 1. Scope (from `waf.txt`)

> Phase 5 — API and business-flow protection
> Test API schemas, authentication boundaries, sensitive workflows, GraphQL, and resource controls.

## 2. Why this is a new catalog, not a new evaluation rule

Phase 3 and Phase 4 each added a *new comparison rule* (`wafpolicygap.EvaluatePairedScenario`/`EvaluateCoverageGapScenario`, `wafevasion.EvaluateEvasionGap`) because each needed to compare two legs under a specific attribution story. Phase 5's five named items don't need a new comparison rule at all: each one is answerable by the same single-request-vs-benign-counterpart shape `wafcatalog.AttackVector` already uses, evaluated through the exact same `wafval.EvaluateClaim` pipeline Phase 2 built. A schema-violating request, an authorization-boundary-violating request, a single-use-token-replay request, a GraphQL depth-abuse query, and a resource-quantity-abuse request are all, structurally, "one malicious request that a correctly configured control should block, with a benign counterpart that should be allowed" — precisely what `AttackVector`/`Expectations`/`EvaluateClaim` already model.

So Phase 5 is `internal/wafapiflow`: a new catalog package, structurally a sibling of `internal/wafcatalog` (not a consumer of it), covering a **different attack surface** — API-schema, authorization-boundary, business-workflow, GraphQL, and per-request resource-quantity attacks — that Phase 2's generic web-attack catalog does not cover. It reuses `wafcatalog`'s proven pattern (type shape, construction validation, `Expectations`, aggregator) rather than its code, for the same reason Phase 2 itself was a standalone package: keeping an already-reviewed, closed package's boundary intact. `internal/wafapiflow` depends only on `internal/wafval` — not on `wafcatalog`, `wafpolicygap`, or `wafevasion` — making it a second sibling of `wafcatalog` under `wafval`, exactly as independent of the other phases' packages as `wafcatalog` itself is:

```
wafval ← wafcatalog   (Phase 2)
wafval ← wafapiflow   (Phase 5)
```

This phase adds **zero new `wafval` verdict logic** — every vector's claim is evaluated by the unmodified `wafval.EvaluateClaim`, exactly as Phase 2's vectors already are.

## 3. Deliberately distinct from Phase 2's existing API/auth vectors

Phase 2's `wafcatalog` already seeded `FamilyAPIAbuse` (API-001 BOLA/IDOR, API-002 mass assignment, API-003 excessive data exposure) and `FamilyAuthAbuse` (AUTH-001 credential stuffing, AUTH-002 account enumeration, AUTH-003 JWT alg-confusion). Phase 5's five seed vectors are chosen to be genuinely distinct attack shapes, not restatements of those six:

- **Schema conformance** is about a field *violating its declared type/bound* (e.g. a negative quantity where the schema declares a positive integer), not an *undeclared* field (that's API-002's mass-assignment story).
- **Auth boundary** is about a *validly-signed token carrying the wrong scope* for the endpoint, not a forged/alg-confused signature (AUTH-003) or credential-guessing (AUTH-001/002).
- **Sensitive workflow** is about *replaying a single-use token/step* after it has already been consumed — a state/sequencing violation, not an object-ownership violation (API-001).
- **GraphQL abuse** is about *query-depth/complexity resource exhaustion*, a shape none of the existing six vectors cover.
- **Resource control** is about an *unbounded per-request quantity parameter* (e.g. `?limit=999999999` on a bulk-export endpoint), distinct from both API-001 (object-level authorization) and Phase 6's planned request-rate-limiting efficacy (a time-window concern, not a per-request-quantity concern).

## 4. Core types

Mirrors `wafcatalog`'s shape, redefined locally (no import of `wafcatalog`) to keep the dependency one-way and the two catalogs independent:

```go
type APIFlowCategory string

const (
    CategorySchemaConformance  APIFlowCategory = "schema_conformance"
    CategoryAuthBoundary       APIFlowCategory = "auth_boundary"
    CategorySensitiveWorkflow  APIFlowCategory = "sensitive_workflow"
    CategoryGraphQLAbuse       APIFlowCategory = "graphql_abuse"
    CategoryResourceControl    APIFlowCategory = "resource_control"
)

type Severity string // Critical, High, Medium, Low -- same four levels as wafcatalog.Severity

type RequestTemplate struct {
    Method          string
    Path            string
    PayloadLocation string
    Payload         string
    Description     string
}

type StandardsMapping struct {
    CWEIDs           []string
    WSTGCategory     string
    Top10Category    string
    APITop10Category string
    ATTACKTechniques []string
}

// APIFlowVector owns both a malicious RequestTemplate and, structurally,
// its benign counterpart -- exactly one of BenignCounterpart or
// NoBenignCounterpartReason is set, never both, never neither, enforced at
// construction (identical discipline to wafcatalog.AttackVector).
type APIFlowVector struct {
    ID                        string
    Version                   int
    Category                  APIFlowCategory
    Name                      string
    Severity                  Severity
    Preconditions             string
    Malicious                 RequestTemplate
    BenignCounterpart         *RequestTemplate
    NoBenignCounterpartReason string
    Standards                 StandardsMapping
    Provenance                string
}
```

`NewAPIFlowVector(id, version, category, name, severity, preconditions, malicious, benignCounterpart, noBenignCounterpartReason, standards, provenance) (APIFlowVector, error)` validates identically to `wafcatalog.NewAttackVector`: ID non-empty, `Version >= 1`, known `Category`/`Severity`, `Malicious` fields non-empty, every `CWEIDs` entry matches `^CWE-\d+$`, `Standards` has at least one of its four mapping fields set, `Provenance` non-empty, and exactly one of `BenignCounterpart`/`NoBenignCounterpartReason`.

## 5. Catalog-wide validation

`ValidateAPIFlowCatalog(vectors []APIFlowVector) error` rejects a catalog containing two vectors with the same ID — the same single-purpose duplicate-ID guard every catalog package in this project uses (`wafcatalog.ValidateCatalog`, `wafpolicygap.ValidatePolicyGapCatalog`, `wafevasion.ValidateEvasionCatalog`).

## 6. Evidence/evaluation integration

```go
type APIFlowLeg string

const (
    LegMalicious APIFlowLeg = "malicious"
    LegBenign    APIFlowLeg = "benign"
)

type APIFlowLegExpectation struct {
    VectorID    string
    Leg         APIFlowLeg
    Request     RequestTemplate
    Expectation wafval.Expectation
}

// Expectations returns exactly 1 entry (malicious only) or 2 entries
// (malicious + benign) -- never padded -- mirroring
// wafcatalog.AttackVector.Expectations exactly. The malicious leg is always
// first and always present.
func (v APIFlowVector) Expectations(policyBasis string) []APIFlowLegExpectation
```

Each leg's `wafval.Expectation` carries `Claim: wafval.ClaimPrevention` for the malicious leg and `Claim: wafval.ClaimFalsePositive` for the benign leg (when present) — identical to `wafcatalog`'s own mapping. Callers evaluate each leg with the unmodified `wafval.EvaluateClaim(exp, results, key)`; this package adds no evaluation function of its own.

## 7. Seed catalog

`AudspectWAFAPIFlowCatalog() ([]APIFlowVector, error)` returns exactly 5 vectors, one per `APIFlowCategory`, proving the model rather than attempting exhaustive breadth (same discipline as Phase 3's and Phase 4's 1-per-category seed catalogs):

| ID | Category | Malicious / benign sketch | Standards |
|----|----------|------------------------------|-----------|
| APIFLOW-001 | schema_conformance | checkout API's `quantity` field, declared a positive integer in the OpenAPI schema, sent as `-1` to attempt a negative-quantity refund/credit abuse vs. a valid positive quantity | CWE-1284 |
| APIFLOW-002 | auth_boundary | a validly-signed bearer token carrying only `read:profile` scope used against a `write:profile` endpoint vs. the same request with a token actually carrying `write:profile` scope | CWE-285 |
| APIFLOW-003 | sensitive_workflow | a password-reset token already consumed by a completed reset, replayed to set a new password a second time vs. a freshly issued, not-yet-consumed token used for the identical operation | CWE-294 |
| APIFLOW-004 | graphql_abuse | a GraphQL query with deeply nested recursive field selections (~50 levels) intended to exhaust backend resources vs. the same query shape at a shallow, reasonable depth | CWE-400 |
| APIFLOW-005 | resource_control | a bulk-export endpoint's `limit` query parameter sent as `999999999` to exfiltrate an entire dataset in one call vs. the same request with `limit` within the endpoint's intended bound | CWE-770 |

## 8. Acceptance gate

1. `NewAPIFlowVector` rejects: empty ID, `Version < 1`, unknown `Category`, unknown `Severity`, empty `Malicious.*` fields, a `Standards.CWEIDs` entry not matching `^CWE-\d+$`, `Standards` with all four mapping fields empty, empty `Provenance`, both `BenignCounterpart` and `NoBenignCounterpartReason` set, and neither set.
2. `ValidateAPIFlowCatalog` rejects a catalog with two vectors sharing an ID.
3. `Expectations` returns exactly 1 entry when `NoBenignCounterpartReason` is set and exactly 2 when `BenignCounterpart` is set — never 0, never padded.
4. `AudspectWAFAPIFlowCatalog` returns exactly 5 vectors, one per distinct `APIFlowCategory`, and the aggregator's own `ValidateAPIFlowCatalog` call passes on its output.

## 9. Explicitly deferred

- Real execution against a live API gateway/WAF and a real backend to actually send these requests and observe enforcement.
- Expanding the seed catalog beyond one example per category.
- GraphQL-specific protocol parsing (query AST depth measurement, introspection-response inspection) — this phase models the *attack shape* as a `RequestTemplate`, the same documentary level of detail `wafcatalog`'s vectors use; a real GraphQL-aware harness is real-execution work, out of scope here.
- Any new `wafval` verdict logic, any dependency on `wafcatalog`/`wafpolicygap`/`wafevasion`, and any multi-step *sequence* modeling beyond "one terminal request whose validity depends on prior state" — `sensitive_workflow`'s single vector captures the state-dependency claim (a token's single-use invariant) without needing a session/sequence data structure; richer workflow-sequence modeling (e.g. a full ordered step graph) is left for a future phase if the client's actual workflows require it.
