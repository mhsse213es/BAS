# Endpoint Risk & Remediation View — Design

**Status:** Approved for planning
**Sub-project:** 1 of 6 in the Endpoint Health & Remediation initiative (2: Security Configuration & Identity Posture Collection, 3: Patch Management Data, 4: One-Click Remediation Execution, 5: BAS-Verified Remediation, 6: Enterprise ops tail — fleet comparison, exceptions, ownership/SLA, maintenance windows, bulk remediation, MTTR)
**Source:** User's Endpoint Health & Remediation proposal (this conversation, 2026-08-01), grounded via a code-research fork that found most of the data layer already exists

## Problem

The Agents section today has one "Operational" view — an inventory table with no notion of "how healthy is this endpoint and what should I fix." Meanwhile `internal/exposure` already computes rich per-asset risk data (CVE exposure, attack-path position, detection coverage gaps, prioritized remediation text) that has no UI surface of its own in the Agents section — it's only exposed via the separate Exposure Explorer. This sub-project turns that already-computed data (plus two small new per-agent aggregations) into the "Risk & Remediation" tab the user described: a fleet-wide list ranked by health, and a per-agent drill-down with categorized, evidence-backed findings.

## Goals

1. A new "Risk & Remediation" tab in the Agents section: every enrolled agent, its Health Score, and enough context to know which ones need attention first.
2. A per-agent drill-down (new "risk" tab in the existing agent detail drawer) showing categorized findings, an attack-path chain narrative, and a deficit-ranked action plan — built from real evidence only.
3. Two small new per-agent aggregations (Compliance, BAS Readiness) to round out the categories `internal/exposure` doesn't already cover.

## Non-goals

- No new agent-side data collection. Security Configuration, Identity, Patch Management, and Application Risk categories render as visible "Not yet collected" placeholders — Sub-projects 2 and 3 fill them in later.
- No remediation *execution* of any kind (no one-click fixes, no vendor API calls beyond what already exists for EPP isolate/kill/quarantine). That's Sub-project 4.
- No BAS-verified remediation (rerunning a technique after a fix). That's Sub-project 5.
- No fleet comparison, exception management, ownership/SLA, maintenance windows, bulk remediation, or MTTR metrics. That's Sub-project 6.
- No new 30-day snapshot infrastructure — trend is a now-vs-7-days-ago comparison, reusing Control Health Foundation's `asOf` recompute pattern.
- "Estimated Time," "Requires Reboot," and "Can Audspect Fix" are not shown on findings in this sub-project — they describe a fixable action, and no fix mechanism exists until Sub-project 4.

## 1. Architecture

No new scoring engine from scratch. `internal/exposure`'s existing `AssetExposureProfile` (per-asset, already includes `Scores{ExposureScore, AttackPathScore, DetectionCoverageScore, VulnerabilityScore, CriticalityRisk}`, `Vulnerabilities []CVEExposure`, `AttackPathContext`, `DetectionContext`, `Recommendations []pathcorrelation.PrioritizedGap`) is the backbone, reused via the existing `buildAssetGraph` helper (`internal/api/exposure_handlers.go:19`) — the same graph-build-once-per-request pattern the Exposure Explorer already uses.

A new package, `internal/endpointrisk`, is a pure consumer (like `internal/controlhealth`) that combines an `AssetExposureProfile` with two new per-agent inputs — a Compliance rollup and a BAS Readiness aggregation — into one `EndpointHealth` result. It owns no DB tables; the two new inputs are small, targeted queries added to `internal/api` (mirroring `h.complianceRows`'s existing per-agent pattern), not a new subsystem.

```
GET /api/agents/risk-summary          (fleet list)
GET /api/agents/{agentId}/risk         (per-agent detail)
        │
        ▼
internal/api/endpointrisk_handlers.go
        │  buildAssetGraph() → ag.Profile(hostKey)   [existing, exposure.Build]
        │  complianceRollup(agentId)                  [new, thin wrapper over compliance.Mapper.GenerateReport]
        │  basReadiness(agentId)                       [new, small SQL aggregation]
        ▼
internal/endpointrisk.ComputeHealth(profile, compliance, basReadiness, asOf)
        │
        ▼
EndpointHealth{Score, Categories, ActionPlan, AttackPathChain, Trend}
```

## 2. Health Score

Simple average of 5 category inputs, all already 0-100, higher = safer. "Exposure / Attack Path" is one category (matching §3's table) whose input is itself the average of `exposure`'s two related sub-scores, so `AttackPathScore` isn't silently dropped:

```
ExposureAttackPathInput = mean(ExposureScore, AttackPathScore)  // exposure.Scores

HealthScore = round(mean(
    ExposureAttackPathInput,
    DetectionCoverageScore,  // exposure.Scores.DetectionCoverageScore
    VulnerabilityScore,      // exposure.Scores.VulnerabilityScore
    CompliancePercent,       // new: per-agent compliance rollup
    BASReadinessScore,       // new: per-agent BAS readiness aggregation
))
```

Equal 20% weighting across the 5 categories is a proposed V1 default (named constants, same "flag before tuning against real data" caveat as Control Health Foundation's coverage thresholds).

`CriticalityRisk` (already computed by `exposure`) is **not** folded into the score — it's "how much this asset matters," not "how healthy it is." It becomes a separate sort/priority signal on the fleet list: `GET /api/agents/risk-summary` returns both `healthScore` and `criticalityRisk` so the UI can sort or highlight by either, or by a derived priority (e.g. low score × high criticality ranks worst).

## 3. Categories

| Category | Source | Real today? |
|---|---|---|
| Vulnerabilities | `exposure.Vulnerabilities` (CVE/CVSS/KEV/EPSS) | Yes — evidence real; remediation text is generic ("update to a patched version"), since CVE-specific patch instructions need Sub-project 3 |
| Exposure / Attack Path | `exposure.AttackPathContext` + `exposure.Recommendations` (`pathcorrelation.PrioritizedGap`, real per-edge Reason/Remediation) | Yes |
| Detection Health | `exposure.DetectionContext` (Covered/Partial/Gap/Unknown edge counts) | Yes — evidence real; per-gap remediation is generic tuning guidance |
| Compliance | New per-agent rollup via `compliance.Mapper.GenerateReport(results, frameworkID, agentID, ...)` (already agent-scoped) | Yes — failed controls carry real remediation via `TechniqueEvidence.Remediation` (sourced from `SimulationResult.Remediation`) |
| BAS Readiness | New aggregation: last-run date, coverage %, pass rate, never-tested techniques, reusing the reporting engine's existing per-agent result fetch | Yes |
| Security Configuration | — | **Not yet collected** placeholder (Sub-project 2) |
| Identity | — | **Not yet collected** placeholder (Sub-project 2) |
| Patch Management | — | **Not yet collected** placeholder (Sub-project 3) |
| Application Risk | — | **Not yet collected** placeholder (Sub-project 3) |

A "Not yet collected" card shows the category name and a one-line explanation, never a fabricated score or finding.

## 4. Attack-path chain narrative

Rendered directly from `exposure.Recommendations` — each `pathcorrelation.PrioritizedGap` already carries `Edge{From, To, Kind}`, `Reason`, and `Remediation`, and `AttackPathContext` already tells us whether this asset is reachable, its distance to the nearest crown jewel, and whether it's a choke point. The narrative is a rendering of the existing edge sequence (reusing `apNodePill`/`apArrow`-style presentation already established for Attack Path Validation), not new correlation logic.

## 5. Recommended Action Plan

Ranked by **category-level deficit** (`100 - categoryScore`, biggest gap first), not a fabricated per-finding "18% risk reduction" figure — computing a real per-finding what-if score would require re-running scoring with that finding hypothetically fixed, which none of the current data supports honestly. Each ranked category shows its single worst finding as the representative action, e.g.:

```
1. Vulnerabilities  (−22 pts)
   Worst: CVE-2026-XXXX — Critical, KEV-listed, EPSS 0.94
2. Detection Health  (−15 pts)
   Worst: 3 techniques with no detection coverage (Gap)
```

## 6. Trend

Partial, not full-score, trend in V1 — discovered during implementation planning that this is a real constraint, not just an option. `ExposureScore`/`AttackPathScore`/`DetectionCoverageScore` come from rebuilding the whole attack-path graph (`exposure.Build`), which isn't cheaply re-computable "as of 7 days ago" without new plumbing to time-filter the underlying `attackpath` collections — unlike Control Health Foundation's flat evidence rows, which filter by timestamp directly. Compliance and BAS Readiness, by contrast, are both derived from `models.SimulationResult` lists (via the existing `h.aggregateAgentResults`) and filter by `ExecutedAt <= asOf` exactly like Control Health does.

So `internal/endpointrisk.ComputeHealth` takes an `asOf time.Time` parameter that only affects the Compliance and BAS Readiness inputs; Exposure/Attack-Path/Detection Health stay at their current value in both the "now" and "7-days-ago" computation. The Trend badge reflects only the two evidence-row-based categories — it will catch a compliance or testing-cadence regression, but not an attack-path or detection-coverage regression. That fuller trend is deferred (either to a later refinement of this sub-project or absorbed into Sub-project 3's Compliance Drift Detection work, which already needs a time-aware graph story). No new snapshot table either way.

## 7. UI surfaces

- **Fleet tab** ("Risk & Remediation", sibling to "Operational" in the Agents section): a sortable/filterable table — agent, Health Score, criticality, trend, top-deficit category, open findings count. Backed by `GET /api/agents/risk-summary`.
- **Per-agent drill-down** (new "risk" tab in the existing `#agent-detail-overlay` drawer, alongside `overview | scenarios | logs | health | attackpath` — deliberately *not* named "health" to avoid colliding with the existing heartbeat/connectivity tab of that name): category cards (findings + "Not yet collected" placeholders), attack-path chain, action plan, trend. Backed by `GET /api/agents/{agentId}/risk`.

## 8. Testing

- `internal/endpointrisk`: table-driven unit tests for `ComputeHealth`'s score averaging, category deficit ranking, and trend banding — pure functions, no DB, same style as `controlhealth`'s `health_test.go`.
- `internal/api`: container-backed handler tests for both new endpoints, including the nil-dependency-safe path (matching the existing `TestComplianceHandlers_NilMapper503` / this session's `TestGetControlHealthSummary_NilMapper503` convention) and a "Not yet collected" placeholder assertion for the four uncollected categories.
- Frontend: no automated test suite exists for `wwwroot/index.html` (established convention this session) — verification is `node --check` on the extracted inline script plus manual review; full browser QA deferred to the existing pending-QA backlog.
