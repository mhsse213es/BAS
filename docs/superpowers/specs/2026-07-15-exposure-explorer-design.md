# SP4 — Exposure Explorer Design Spec

**Date:** 2026-07-15
**Status:** Approved by user, ready for planning.

## Goal

An asset-centric "how exposed is this box" view. For any host — enrolled agent or attack-path-discovered-only — show which ATT&CK techniques threaten it, whether we'd detect an attacker using them (SP3), which CVEs/KEV/EPSS exposure apply, which threat groups use those techniques, this asset's findings history, and a prioritized remediation list. This is the flagship UI feature the roadmap describes, now buildable because SP1 (Detection Verification), SP2 (Rule Library), and SP3 (Attack Path ↔ Detection Correlation) all exist to feed it.

## Non-goals (v1)

- No free-form node-link graph canvas. Structured drill-down (cards/tables with cross-links), consistent with the rest of the dashboard.
- No per-technique / per-threat-group / per-CVE reverse-lookup pages. The API shape allows adding `/api/exposure/techniques/{id}`, `/api/exposure/groups/{apt}`, `/api/exposure/cves/{cve}` later without redesign, but only the asset-centric endpoints ship in v1.
- No report-section integration. This is a live dashboard feature, not a new report section (unlike SP3). Could be added later.
- No SP6 (Asset Criticality) input into the score — that lands after this, per the roadmap, and can extend `ScoreBreakdown` without a redesign when it does.
- Findings/threat-group data are NOT inputs to the Exposure Score — they're contextual evidence only (see Scoring section for why).

## Architecture

New `internal/exposure` package: a pure aggregator/orchestration layer over four existing subsystems, with **zero new DB tables**. Mirrors the `internal/pathcorrelation` precedent from SP3 exactly — same shape, same nil-safety conventions, same "caller builds the graph/correlation once, this package only aggregates" discipline.

```
attackpath  ─┐
pathcorrelation ─┤
relationships ───┼──► internal/exposure ──► API / UI
attackdata ───────┤
findings (DB) ────┘
```

Nothing points back out of `exposure` — `attackpath` and `pathcorrelation` stay unaware this package exists, exactly as they're unaware of each other's respective consumers today.

### Asset universe

An "asset" is the union of:
1. Attack-path graph host nodes (`attackpath.Graph`, `KindHost` nodes — built from stored `attackpath_collections`, same as SP3).
2. Enrolled agents (`agents` table).

Deduplicated by `attackpath.NormalizeHostKey`. Each resulting asset carries `Managed bool` — true when an `agents` row backs it. Managed assets get full data (findings, run history via existing endpoints). Discovered-only assets (found via SharpHound/reachability but never enrolled) still get Attack Path / Detection / Vulnerability / ThreatIntel sections — those don't require an agent — but their Findings section renders an explicit "not enrolled, no scan history" state. This is never a fabricated empty table; it's an honest state, matching the existing "not yet collected" convention used elsewhere (e.g. the Attack Path Validation report section before any collection has run).

## Data model

```go
// internal/exposure/types.go
package exposure

type AssetIdentity struct {
    HostKey    string `json:"hostKey"`
    Label      string `json:"label"`
    Managed    bool   `json:"managed"`
    AgentID    string `json:"agentId,omitempty"`
    OS         string `json:"os,omitempty"`
    IP         string `json:"ip,omitempty"`
    CrownJewel string `json:"crownJewel,omitempty"`
    Segment    string `json:"segment,omitempty"`
    HighValue  bool   `json:"highValue,omitempty"`
}

// ScoreBreakdown — all fields 0-100, higher = safer. AttackPathScore and
// DetectionCoverageScore here are ASSET-SCOPED derived values computed by
// this package (see Scoring section) — NOT the fleet-wide numbers from
// attackpath.Summary / pathcorrelation.AttackPathCorrelation, which remain
// available separately via their own existing endpoints. Polarity is
// consistent with those fleet scores and with html.go's scoreColor
// template func.
type ScoreBreakdown struct {
    ExposureScore          int `json:"exposureScore"`
    AttackPathScore         int `json:"attackPathScore"`
    DetectionCoverageScore  int `json:"detectionCoverageScore"`
    VulnerabilityScore      int `json:"vulnerabilityScore"`
}

type AttackPathContext struct {
    Reachable               bool `json:"reachable"`
    OnShortestDAPath         bool `json:"onShortestDaPath"`
    DistanceToNearestCrownJewel int `json:"distanceToNearestCrownJewel,omitempty"` // -1 if none reachable
    IsChokePoint             bool `json:"isChokePoint"`
    ChokePointCoverage       float64 `json:"chokePointCoverage,omitempty"`
}

type DetectionContext struct {
    Edges           []pathcorrelation.AnnotatedEdge `json:"edges"`
    Covered         int `json:"covered"`
    Partial         int `json:"partial"`
    Gap             int `json:"gap"`
    Unknown         int `json:"unknown"`
}

type CVEExposure struct {
    CVEID       string  `json:"cveId"`
    CVSS        float64 `json:"cvss,omitempty"`
    KEV         bool    `json:"kev"`
    EPSSScore   float64 `json:"epssScore,omitempty"`
    TechniqueID string  `json:"techniqueId"`
    Severity    float64 `json:"severity"` // computed, see Scoring
}

type FindingsContext struct {
    Collected    bool                  `json:"collected"` // false for discovered-only assets
    OpenCount    int                   `json:"openCount"`
    CriticalCount int                  `json:"criticalCount"`
    Findings     []findings.FindingRef `json:"findings,omitempty"`
}

type ThreatGroupExposure struct {
    GroupName   string   `json:"groupName"`
    TechniqueIDs []string `json:"techniqueIds"`
}

type AssetExposureProfile struct {
    Asset           AssetIdentity            `json:"asset"`
    Scores          ScoreBreakdown           `json:"scores"`
    AttackPath      AttackPathContext        `json:"attackPath"`
    Detection       DetectionContext         `json:"detection"`
    Vulnerabilities []CVEExposure            `json:"vulnerabilities"`
    Findings        FindingsContext          `json:"findings"`
    ThreatIntel     []ThreatGroupExposure    `json:"threatIntel"`
    Recommendations []pathcorrelation.PrioritizedGap `json:"recommendations"`
}

// AssetSummary is the lightweight index row for GET /api/exposure/assets.
type AssetSummary struct {
    Asset               AssetIdentity `json:"asset"`
    ExposureScore       int     `json:"exposureScore"`
    AttackPathScore      int     `json:"attackPathScore"`
    DetectionCoverageScore int   `json:"detectionCoverageScore"`
    WorstCVESeverity     float64 `json:"worstCveSeverity,omitempty"`
    KEVExposed           bool    `json:"kevExposed"`
    OpenFindingsCount    int     `json:"openFindingsCount"`
}
```

## Scoring

### Per-CVE severity (0–100)

```
severity = (CVSS/10)*60 + (KEV ? 25 : 0) + EPSSScore*15
```

CVSS defaults to 0 when unknown (some KEV entries carry no CVSS); a KEV-listed CVE with unknown CVSS still contributes its 25-point KEV term, so it's never scored as zero-risk.

### Vulnerability Risk (asset-level)

```
VulnerabilityRisk = MAX(severity) across every CVE reached via relationships.Store.ForTechnique()
                     for every technique threatening this asset
VulnerabilityScore = 100 - VulnerabilityRisk
```

Worst-CVE-dominates (not an average), deliberately mirroring SP3's `pathStrength` weakest-link philosophy already established in this codebase: one critical, actively-exploited CVE should drive an asset's vulnerability risk regardless of how many mild CVEs also apply. An asset with zero mapped CVEs gets `VulnerabilityScore = 100`.

### Exposure Score (composite)

```
ExposureRisk = 0.40*(100-AttackPathScore) + 0.35*(100-DetectionCoverageScore) + 0.25*VulnerabilityRisk
ExposureScore = 100 - ExposureRisk
```

Weights reflect: Attack Path (how reachable/valuable to an attacker) is the largest factor, Detection (would we catch it) close behind, Vulnerability (how easy to compromise) smallest — all three are independently measurable 0–100 scores already in the system, so no new arbitrary-scale inputs are blended in.

**Findings and ThreatIntel are deliberately excluded from the score.** Findings are a consequence of how much simulation testing has happened on a host, not of its actual exposure — scoring them would make an untested host look artificially safer than a heavily-tested one. Threat-group attribution indicates *who* uses a technique, not *how exposed* this specific asset is. Both remain visible as contextual evidence in the profile.

### Per-asset AttackPathScore / DetectionCoverageScore (asset-scoped, NOT the fleet-wide numbers)

**Self-review catch:** an earlier draft of this spec reused `attackpath.Summary.AttackPathScore` and the fleet-wide SP3 `DetectionCoverageScore` verbatim for every asset. Since those two terms carry 75% of the composite weight (0.40+0.35), every asset would have shown near-identical `ExposureScore`s, differing only by the 0.25 vulnerability term — defeating the purpose of an asset-centric view. Fixed: both components are derived **per-asset** inside `internal/exposure`, from data already computed by `attackpath`/`pathcorrelation` (no new scoring logic added to either of those packages — this stays purely an aggregation-layer computation, per the established dependency boundary).

```
AttackPathRisk (per asset, 0-100, higher = more exposed):
  100                                    if the asset's host key appears on s.ShortestDAPath
  90                                     if the asset is itself a reachable crown jewel (via s.ReachableCrownJewels())
  max(20, 100 - 15*d)                    if reachable from s.MaxBlastEntry at graph distance d (via g.ShortestPath)
  0                                      if not reachable / not present in the attack-path graph at all
                                          (v1 cannot distinguish "definitely safe" from "no data yet" —
                                          same honesty caveat as elsewhere in this codebase; the UI must
                                          show "not in attack-path graph" rather than implying safety)
AttackPathScore (per asset) = 100 - AttackPathRisk
```

```
DetectionRisk (per asset, 0-100, higher = more exposed) =
  100 * (Gap*1.0 + Unknown*0.6 + Partial*0.4 + Covered*0.0) / edgesTotal
  where the four counts are DetectionContext's own per-asset counts (edges touching this host only)
  and edgesTotal = Covered+Partial+Gap+Unknown for this asset; DetectionRisk = 0 when edgesTotal = 0
  (no technique-mapped edge threatens this asset via any known path → safe by default, same
  "no dangerous paths → 100" convention SP3 already uses)
DetectionCoverageScore (per asset) = 100 - DetectionRisk
```

The weight constants (1.0/0.6/0.4/0.0) mirror SP3's `gapFactor` scale conceptually but are intentionally **averaged** across this asset's edges rather than dominated by the single worst hop — SP3's per-*path* scoring wants "one broken link breaks the whole chain," but a per-*asset* rollup of multiple distinct incoming edges is better read as "how many of the ways in are covered," where each additional covered edge incrementally improves the asset's posture. This is a deliberate, different aggregation from SP3's, not an unexplained inconsistency with it.

The fleet-wide `attackpath.Summary.AttackPathScore` and SP3's fleet `DetectionCoverageScore` remain available via their existing endpoints for global/fleet context — they are not removed, just not reused verbatim per-asset here.

## API

- `GET /api/exposure/assets` (Viewer+) — returns `[]AssetSummary`, one per asset in the union. Built from ONE graph build + ONE `Correlate()` call (not per-asset), plus one batched findings-count query (`SELECT agent_id, COUNT(*) FILTER (WHERE status='open') FROM findings GROUP BY agent_id`) — never N+1 per asset.
- `GET /api/exposure/assets/{hostKey}` (Viewer+) — returns one `AssetExposureProfile`. `hostKey` matched via `attackpath.NormalizeHostKey`, case-insensitive. 404 if no such asset exists in either the graph or `agents`.

Both nil-safe: an empty attack-path graph and no rules wired still returns a 200 with `ExposureScore: 100` assets list (assets from `agents` alone, e.g.), matching this API's established convention from SP3/SP2.

## Package structure

```go
// internal/exposure/profile.go
func BuildProfile(ctx context.Context, hostKey string, g *attackpath.Graph, s attackpath.Summary,
    corr pathcorrelation.AttackPathCorrelation, rels RelationshipLookup, findings FindingsLookup) (AssetExposureProfile, error)

func BuildSummaries(ctx context.Context, g *attackpath.Graph, s attackpath.Summary,
    corr pathcorrelation.AttackPathCorrelation, rels RelationshipLookup, findings FindingsLookup, agents []AgentRow) ([]AssetSummary, error)

// AgentRow is the minimal projection of the `agents` table BuildSummaries needs
// to extend the asset union beyond the attack-path graph's own host nodes.
type AgentRow struct {
    AgentID  string
    Hostname string
    IP       string
    OS       string
}

// internal/exposure/relationships.go
type RelationshipLookup interface {
    ForTechnique(ctx context.Context, techniqueID string) ([]relationships.Relationship, error)
}

// internal/exposure/findings.go
type FindingsLookup interface {
    OpenFindingsForAgent(ctx context.Context, agentID string) ([]findings.FindingRef, error)
    OpenFindingsCounts(ctx context.Context) (map[string]int, error) // agentID -> open count, batched
}
type SQLFindingsLookup struct{ db *pgxpool.Pool } // production impl, queries `findings` directly like SQLRunLookup queries verification_history
```

`*relationships.Store` satisfies `RelationshipLookup` directly (its existing `ForTechnique` signature matches). `SQLFindingsLookup` is a new small direct-SQL reader, same pattern as SP3's `SQLRunLookup`.

CVE/KEV/EPSS enrichment for each `relationships.Relationship.CVEID` is a small additional join against the existing `cves` and `cve_epss` tables inside `profile.go` (batched: one `WHERE cve_id = ANY($1)` query per profile build, not per-CVE).

## API handler

`internal/api/exposure_handlers.go` follows the exact SP3 `pathcorrelation_handlers.go` pattern: builds the graph via `attackpath.BuildGraphAndAnalyze`, builds the correlation via `pathcorrelation.Correlate` (same nil-guard for `h.rules`), then calls `exposure.BuildProfile`/`BuildSummaries`. New routes registered in the `tierAny` block alongside the SP3 route.

## UI

New "Exposure Explorer" nav item in the Visibility group (after "Attack Paths"), per `project_ui_design_reference` conventions (dual-rail styling, side-drawer detail views, heavy cross-linking):

- **Asset index tab**: a sortable table — Host, Managed badge, Exposure Score (colored via the same `scoreColor` convention as reports), Attack Path Score, Detection Coverage, Crown Jewel badge, Open Findings count, KEV flag.
- **Detail side drawer** (opened by clicking a row, matching the existing run-result/report drawer convention): score cards row (Exposure/AttackPath/Detection/Vulnerability, each colored), Attack Path context block, Detection gaps table (reuses the SP3 report's gap-table markup/CSS), Vulnerabilities table (CVE / CVSS / KEV / EPSS / source technique, worst-first), Findings list or "not enrolled" state, Threat Group chip list, Recommendations list (SP3 `PrioritizedGap`s, same priority-color styling as the report table).

## Testing

- `internal/exposure`: table-driven unit tests for `BuildProfile`/`BuildSummaries` against fake `RelationshipLookup`/`FindingsLookup` fixtures (mirrors SP3's `fakeRunLookup`/`fakeRuleLibrary` pattern exactly) — score-formula edge cases (no CVEs → VulnerabilityScore 100, no attack-path data → ExposureScore 100), worst-CVE-dominates behavior, managed-vs-discovered `Findings.Collected` state, asset-union dedup by hostKey.
- `internal/api`: handler tests via the package's existing `sharedDB` pattern (same as SP3 Task 6), covering nil-`h.rules` nil-safety and the 404 case for an unknown hostKey.
- No new DB tables — no migration risk, no new testcontainer setup needed beyond what already exists in `internal/api`.

## Global constraints (carried over from SP3, still apply)

- Garble/json-tag-map rule: the report template resolves fields via `json.Marshal`→`map[string]any`, never raw struct reflection — not directly relevant here since v1 has no report-section integration, but every new exported type still needs complete json tags for the *API* JSON responses regardless.
- `gofmt -w` the exact files touched, then `-l` to confirm — never a whole-directory sweep (pre-existing CRLF noise on untouched files is expected, not a regression).
- Docker Desktop must be running for any test touching `internal/api`'s shared testcontainer.
