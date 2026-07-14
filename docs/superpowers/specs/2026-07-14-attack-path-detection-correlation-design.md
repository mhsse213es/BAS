# Attack Path ↔ Detection Correlation (SP3) — Design

**Goal:** Connect the native Attack Path Validation engine (`internal/attackpath` — graph of hosts/users/groups, lateral-movement edges, choke points, crown-jewel exposure, shortest path to Domain Admin) with the Detection Validation stack (`internal/scenario` expected detections, `internal/verification` verified results, `internal/rulelib` the SP2 rule library) to answer: *for every dangerous path through this environment, would we actually catch the attacker?*

**Non-goals (this slice):** no UI page (API + report section only, matching the SP1/SP2 pattern), no `internal/findings` records, no change to `AttackPathScore`'s existing formula, no per-deployment mapping overrides (built-in table only — the mapper is an interface so overrides can be added later without a redesign).

---

## Architecture

A new, independent package `internal/pathcorrelation`. It is a **consumer** of three existing subsystems, not a member of any of them — this keeps `attackpath` a pure graph engine and keeps the correlation logic reusable by future consumers (Exposure Explorer, Asset Criticality) without redesign:

```
attackpath (graph/paths)  ──┐
rulelib (expected coverage) ─┼──▶ pathcorrelation ──▶ API handler / report section
verification+scenario       ─┘         (SQL join via
 (verified coverage)                    scenario_runs + agents)
```

No new database tables. `pathcorrelation` reads `scenario_runs`/`agents` directly (SQL), and reuses `scenario.Engine.ResolveStepExpectations` + `verification.Store.CurrentForRun` — the exact same resolution path the existing Detection Validation report section already uses, so there is no second implementation of "which expectations belong to this step" to maintain.

### Small additive export on `attackpath.Graph`

`pathcorrelation` needs to enumerate the edges feeding into a choke-point node, and `Graph` currently exposes no edge-listing accessor at all (only `Nodes()`, `Node()`, counts). Add one minimal, read-only, backward-compatible method:

```go
// EdgesTo returns every edge whose To == id (order unspecified).
func (g *Graph) EdgesTo(id string) []Edge
```

No existing behavior changes; this is purely a new accessor next to the existing `Nodes()`/`Node()` methods in `graph.go`.

---

## Data model

### Edge → technique mapping (with weight/reason, per feedback)

```go
// TechniqueMapping is one edge-kind → ATT&CK-technique association. Weight
// (0.0–1.0) does double duty: it is both "how directly does this edge realize
// this technique" (mapping confidence) and "how critical is this technique to
// catch" (severity) — for a lateral-movement edge the two collapse, since the
// more direct technique is also the one most worth detecting.
type TechniqueMapping struct {
    TechniqueID string  `json:"techniqueId"`
    Weight      float64 `json:"weight"`
    Reason      string  `json:"reason"`
}

type EdgeTechniqueMapper interface {
    Techniques(kind attackpath.EdgeKind) []TechniqueMapping
}

type DefaultEdgeTechniqueMapper struct{}
func (DefaultEdgeTechniqueMapper) Techniques(kind attackpath.EdgeKind) []TechniqueMapping
```

Built-in table (`DefaultEdgeTechniqueMapper`):

| EdgeKind | Techniques (ID · weight · reason) |
|---|---|
| `EdgeSMB` | T1021.002 · 1.0 · "SMB/Windows Admin Shares is the direct mechanism of this edge" |
| `EdgeWinRM` | T1021.006 · 1.0 · "Windows Remote Management is the direct mechanism of this edge" |
| `EdgeRDP` | T1021.001 · 1.0 · "Remote Desktop Protocol is the direct mechanism of this edge" |
| `EdgeAdminTo` | T1078 · 1.0 · "Valid Accounts used to hold local admin on the target" |
| `EdgeHasSession` | T1003 · 0.7 · "OS Credential Dumping is possible from an interactive session"; T1552 · 0.5 · "Unsecured Credentials may be exposed via an active session" |
| `EdgeMemberOf` | T1078 · 0.6 · "Group membership implies valid-account privilege reuse"; T1098 · 0.4 · "Account Manipulation is a less direct but possible origin" |
| `EdgeCredential` | T1550 · 1.0 · "Use Alternate Authentication Material is the direct mechanism"; T1555 · 0.5 · "Credentials from Password Stores is a possible but not certain origin" |

### Status enums

```go
type ExpectedStatus string
const (
    ExpectedCovered ExpectedStatus = "covered"
    ExpectedGap     ExpectedStatus = "gap"
)

type VerifiedStatus string
const (
    VerifiedCovered VerifiedStatus = "covered"
    VerifiedPartial VerifiedStatus = "partial" // some but not all of the edge's mapped techniques are verified
    VerifiedGap     VerifiedStatus = "gap"
    VerifiedUnknown VerifiedStatus = "unknown"  // no verification evidence anywhere for any mapped technique
)

// VerificationConfidence replaces a plain HostSpecific bool: it says WHERE the
// verified evidence came from, not just whether it exists.
type VerificationConfidence string
const (
    ConfidenceHost        VerificationConfidence = "host"        // verified against this exact host
    ConfidenceEnvironment VerificationConfidence = "environment" // verified elsewhere in the environment, not this host
    ConfidenceUnknown     VerificationConfidence = "unknown"     // no evidence at all
)
```

### Evidence

```go
type Evidence struct {
    RuleIDs          []string   `json:"ruleIds,omitempty"`
    AlertIDs         []string   `json:"alertIds,omitempty"`
    RunID            string     `json:"runId,omitempty"`
    VerifiedAt       *time.Time `json:"verifiedAt,omitempty"`
    Provider         string     `json:"provider,omitempty"`         // e.g. "microsoft_sentinel"
    InvestigationURL string     `json:"investigationUrl,omitempty"` // deep link into the vendor console, when the connector supplied one
}
```

`RuleIDs` comes from `rulelib.Engine.RulesByTechnique`. `AlertIDs`/`Provider`/`InvestigationURL` come from the matched `verification.Record`'s evidence (when the record's source is `api`, i.e. produced by a detectverify connector) — `RunID`/`VerifiedAt` always come from the matched `verification.Record` itself.

### Per-edge detection status

```go
type DetectionStatus struct {
    Techniques []TechniqueMapping     `json:"techniques"`
    Expected   ExpectedStatus         `json:"expected"`
    Verified   VerifiedStatus         `json:"verified"`
    Confidence VerificationConfidence `json:"confidence"`
    Evidence   Evidence               `json:"evidence,omitempty"`
}

type AnnotatedEdge struct {
    Edge   attackpath.Edge `json:"edge"`
    Status DetectionStatus `json:"status"`
}
```

`Expected` is `Covered` iff `rulelib.RulesByTechnique` returns ≥1 rule for **any** of the edge's mapped techniques (evaluated once per technique, independently of `Verified` — the two fields are never derived from each other).

`Verified` is computed from `RunLookup.VerifiedDetection`, per mapped technique, then combined across the edge's technique set:
- every technique `found` → `Covered`
- some but not all `found` → `Partial`
- none `found`, and the technique's own `Expected` is `Covered` (a rule exists but was never proven to fire) → `Gap`
- none `found`, and `Expected` is also `Gap` for every technique (no rule exists at all) → `Unknown`

`Confidence` takes the strongest confidence among the edge's `found` techniques (`Host` > `Environment`), or `Unknown` when none were found.

### Generic paths (not hardcoded to Domain Admin)

```go
// AttackPath is a named sequence of edges to annotate — the Domain-Admin path,
// a crown-jewel path, or (later) a path supplied by another subsystem, e.g.
// Exposure Explorer. Correlate takes []AttackPath so today's caller (this
// slice's report/API) and tomorrow's callers share one engine.
type AttackPath struct {
    Label string            `json:"label"`
    Edges []attackpath.Edge `json:"-"`
}

type AnnotatedPath struct {
    Label       string          `json:"label"`
    Edges       []AnnotatedEdge `json:"edges"`
    WeakestLink *AnnotatedEdge  `json:"weakestLink,omitempty"` // the edge on this path an attacker is likeliest to cross undetected
}

// DefaultPaths builds this slice's default path set from an already-computed
// Summary: the Domain-Admin path (Summary.ShortestDAPath, if any) plus one
// representative shortest path to each reachable crown jewel. Exists so the
// report/API caller doesn't need to know how paths are derived; a future
// caller can build its own []AttackPath and skip this entirely.
func DefaultPaths(g *attackpath.Graph, s attackpath.Summary) []AttackPath
```

### Choke points

```go
type AnnotatedChokePoint struct {
    ChokePoint    attackpath.ChokePoint `json:"chokePoint"`
    IncomingEdges []AnnotatedEdge       `json:"incomingEdges"` // g.EdgesTo(chokePoint.Node), annotated
    WeakestLink   *AnnotatedEdge        `json:"weakestLink,omitempty"`
}
```

### Gaps (prioritized remediation)

```go
type GapPriority string
const (
    PriorityCritical GapPriority = "critical"
    PriorityHigh     GapPriority = "high"
    PriorityMedium   GapPriority = "medium"
    PriorityLow      GapPriority = "low"
)

type PrioritizedGap struct {
    Edge       attackpath.Edge    `json:"edge"`
    Techniques []TechniqueMapping `json:"techniques"`
    Priority   GapPriority        `json:"priority"`
    Reason     string             `json:"reason"` // e.g. "crossed by 3 of 4 paths, 1 hop from crown jewel FileServer, no verified detection"
}
```

Only edges with `Verified != Covered` appear in `Gaps`. Priority is derived from an internal (unexported, unserialized) `gapScore` — the raw number is intentionally not part of the API surface, matching the request to expose a tier rather than a weight:

```
gapScore(edge) = normalizedPathFrequency(edge)        // pathCrossCount / max(1, totalPaths)
               × proximityFactor(edge)                 // 1 / (1 + hops from edge.To to the nearest DA/crown-jewel target)
               × techniqueCriticality(edge)             // max(mapping.Weight) over the edge's mapped techniques
               × verifiedGapFactor(edge.Status.Verified) // Gap=1.0, Unknown=0.6, Partial=0.4, Covered=0 (excluded)

Priority:  gapScore ≥ 0.5  → Critical
           gapScore ≥ 0.25 → High
           gapScore ≥ 0.10 → Medium
           gapScore >  0   → Low
```

`Gaps` is sorted by `gapScore` descending (worst first). These thresholds are tunable constants (`internal/pathcorrelation`), not load-bearing — same style as `attackpath/score.go`'s `wDomainCompromise` etc.

### Statistics

```go
type Statistics struct {
    EdgesTotal           int              `json:"edgesTotal"`           // canonical edges referenced by any path or choke point
    ExpectedCovered      int              `json:"expectedCovered"`
    ExpectedGap          int              `json:"expectedGap"`
    VerifiedCovered      int              `json:"verifiedCovered"`
    VerifiedPartial      int              `json:"verifiedPartial"`
    VerifiedGap          int              `json:"verifiedGap"`
    VerifiedUnknown      int              `json:"verifiedUnknown"`
    HighestRiskTechnique string           `json:"highestRiskTechnique,omitempty"` // technique with the largest total gapScore contribution
    HighestRiskEdge      *attackpath.Edge `json:"highestRiskEdge,omitempty"`      // Gaps[0].Edge, nil if Gaps is empty
}
```

Counts are per **canonical edge** (deduplicated by From+To+Kind across every path and choke point it appears in), not per technique — an edge with two mapped techniques contributes once to these counts, matching how its single combined `Verified`/`Expected` status was computed.

### Top-level object

```go
// AttackPathCorrelation is named for extensibility, not for the report title:
// future slices (Exposure Explorer, Asset Criticality) can add fields
// (ExposureScore, AssetCriticality, CompensatingControls) to this same object
// without a redesign. The report section renders it under the title "Attack
// Path Detection Coverage".
type AttackPathCorrelation struct {
    Summary     string                 `json:"summary"` // one-line, e.g. "3 of 5 techniques on the Domain Admin path have no verified detection"
    Score       int                    `json:"detectionCoverageScore"` // 0–100, higher = better; fully separate from attackpath.Summary.AttackPathScore
    Paths       []AnnotatedPath        `json:"paths"`
    ChokePoints []AnnotatedChokePoint  `json:"chokePoints"`
    Gaps        []PrioritizedGap       `json:"gaps"`
    Statistics  Statistics             `json:"statistics"`
}
```

---

## Detection Coverage Score (weighted, per feedback — not a flat ratio)

For each `AnnotatedPath` in the correlated set:

```
pathStrength(path) = max over edges in path of:
                          (1 - verifiedGapFactor(edge.Status.Verified)) × techniqueCriticality(edge)
```

The strongest single hop dominates — one well-detected hop is enough for the SOC to catch an attacker walking that path, matching the "broken attack chain" framing (a path with `pathStrength` near 1 is broken; near 0 is silent end-to-end).

```
pathWeight(path) = 40                                   if path is the Domain-Admin path
                  = 15 + 3 × min(cj.EntryHosts, 5)        if path targets crown jewel cj

totalWeight  = Σ pathWeight(path)   (0 if no DA path and no reachable crown jewels)
deficitSum   = Σ pathWeight(path) × (1 - pathStrength(path))
Score        = 100                                        if totalWeight == 0
             = clamp(100 - round(100 × deficitSum / totalWeight), 0, 100)  otherwise
```

`totalWeight == 0` means there is nothing dangerous to detect against (no DA path, no reachable crown jewel) — score is trivially 100, consistent with `AttackPathScore`'s own treatment of the no-exposure case.

---

## Verified-coverage lookup (`RunLookup`)

```go
// RunLookup answers "has this technique been verified as detected, on this
// host or anywhere in the environment?" The SQL-backed implementation joins
// scenario_runs → agents for host matching, then reuses
// scenario.Engine.ResolveStepExpectations + verification.Store.CurrentForRun
// — the exact mechanism the existing Detection Validation report section
// already uses to go from a run + step to expectation IDs to verified state.
type RunLookup interface {
    VerifiedDetection(ctx context.Context, techniqueID, hostname string) (result VerificationResult, found bool, err error)
}

type VerificationResult struct {
    Confidence VerificationConfidence
    Evidence   Evidence
}
```

Algorithm for the SQL-backed implementation (`SQLRunLookup`, constructed with `*pgxpool.Pool` + `*scenario.Engine` + `*verification.Store`):

1. Query `scenario_runs` joined to `agents` for runs where `agents.hostname` matches (normalized the same way `attackpath.NormalizeHostKey` does) and `results` (JSONB) contains a technique with `ID = techniqueID`, most recent `completed_at` first.
2. For the first matching run, resolve the run's scenario steps via `scenario.Engine.Get` + find the step with that `TechniqueID`, call `ResolveStepExpectations(step)` to get its `[]ExpectedDetection`.
3. Call `verification.Store.CurrentForRun(ctx, runID)`, filter to the expectation IDs from step 2, and check for `Result == Detected && WorkflowState == Approved`.
4. If found → `Confidence: Host`, `Evidence` populated from the matched `verification.Record` (+ `rulelib.RulesByTechnique` for `RuleIDs`).
5. If no host-specific match, repeat steps 1–3 **without** the hostname filter (any host) → `Confidence: Environment` if found.
6. If nothing found anywhere → `found = false` → caller treats as `VerifiedUnknown`.

No caching in this slice — correlation runs at report/API-request time against a small number of techniques (≤ ~10 per request); acceptable at current scale, revisit if profiling says otherwise.

---

## `Correlate` entry point

```go
func Correlate(
    ctx context.Context,
    g *attackpath.Graph,
    paths []AttackPath,
    mapper EdgeTechniqueMapper,
    runs RunLookup,
    rules *rulelib.Engine,
) (AttackPathCorrelation, error)
```

Steps: collect the canonical edge set (every edge across `paths` + `g.EdgesTo(cp.Node)` for every `cp` in `g.ChokePoints()`) → compute `DetectionStatus` once per canonical edge → build `AnnotatedPath`/`AnnotatedChokePoint` by looking up the canonical statuses → compute `Gaps` and `Statistics` from the canonical set → compute `Score` from the annotated paths.

---

## API + report surface

- New file `internal/api/pathcorrelation_handlers.go`: `GET /api/attackpath/correlation` (Viewer+, same RBAC tier as the existing attack-path read endpoints), returns `AttackPathCorrelation` as JSON. Loads the agent's current graph/collections + `Summary` exactly as `GetAttackPathSummary` already does, builds `DefaultPaths`, and calls `Correlate` with `DefaultEdgeTechniqueMapper{}`, a `SQLRunLookup`, and the handler's existing `h.rules` (SP2's engine, already wired). `h.rules == nil` or no attack-path collection yet → returns an empty/zero-value `AttackPathCorrelation` (score 100, no paths), not an error — same nil-safety convention as the rest of the API.
- New report section "Attack Path Detection Coverage" in the report engine, wired the same nil-safe way as SP1/SP2: `reportingEngine.WithPathCorrelation(...)` setter; section renders nothing when there's no attack-path collection for the agent (`HasData=false`), so existing reports are unaffected. Placed directly after the existing Attack Path Validation section.

---

## Testing

- `internal/pathcorrelation`: table-driven unit tests for `DefaultEdgeTechniqueMapper` (all 7 edge kinds → expected `TechniqueMapping` sets); unit tests for `Correlate` against fake `RunLookup`/`rulelib.Engine` implementations covering: no history anywhere (`Unknown`), host-specific detection (`Covered`/`Host`), environment-only detection (`Covered`/`Environment`), rule exists but never verified (`Expected: Covered`, `Verified: Gap`), multi-technique edge with mixed results (`Partial`); scoring tests for `pathStrength`/`Score` (all-Gap path → low score, one well-covered hop → high score, no dangerous paths → 100); `Gaps` ordering/priority-threshold tests.
- `internal/attackpath`: a small test for the new `EdgesTo` accessor.
- `internal/api`: handler tests for `GET /api/attackpath/correlation` (nil `h.rules` → empty result, RBAC-matrix entry, happy path with a fixture graph) — same pattern as SP2's `rulelib_handlers_test.go`, including a Postgres-backed integration test for `SQLRunLookup` (mirrors `detectverify`'s existing integration-test style).
