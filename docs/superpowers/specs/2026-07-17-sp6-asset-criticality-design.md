# SP6 — Asset Criticality (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Asset Criticality (SP6) — next in the main roadmap sequence after SP5, per `project_platform_roadmap_2026h2`. Extends SP4 Exposure Explorer (`internal/exposure`) and the attack-path asset-tagging system (`internal/attackpath`).

## Problem
SP4's Exposure Explorer scores every asset purely on attack-path/detection/vulnerability risk. Two assets with identical technical posture score identically today, whether one is an idle test VM and the other a domain controller running payroll. The roadmap named seven criticality factors (business criticality, internet exposure, identity exposure, domain-controller status, production workload, compliance scope, threat exposure) with an open question of where the data comes from.

Investigation found the codebase is not starting from zero:
- `attackpath_asset_tags` already stores operator-set `crown_jewel`/`segment`/`high_value` per host, applied onto the attack-path graph (`Graph.applyAssetTags`) and read by `exposure.Build`.
- `Node.Role == RoleDC` is already auto-derived from parsed SharpHound/AD collection data (`sharphound.go`) — domain-controller status needs zero new collection work.
- SP4 already computes per-asset threat-group and CVE/KEV exposure (`AssetExposureProfile.ThreatIntel`/`.Vulnerabilities`).
- Nothing exists yet for internet exposure, identity exposure (beyond the binary `HighValue` DA-equivalent flag), production-workload, or compliance-scope — no collection signal, no field.

## Decisions
1. **Extend the existing asset-tag model in place** rather than building a parallel criticality subsystem or replacing `crown_jewel`/`high_value`. One table, one source of truth for "this asset matters."
2. **New factors are manual tags this slice** (`criticality_tier`, `internet_facing`, `identity_exposed`, `production`, `compliance_scope`) — same operator-set pattern as the existing fields. No new agent-side collection. Auto-derived inputs stay limited to what's already free: DC role and SP4's existing threat-group exposure count.
3. **Criticality becomes a 4th weighted term in `ExposureScore`**, reweighted from `100 - (0.40×AttackPathRisk + 0.35×DetectionRisk + 0.25×VulnerabilityRisk)` to `100 - (0.30×AttackPathRisk + 0.30×DetectionRisk + 0.20×VulnerabilityRisk + 0.20×CriticalityRisk)`. Explicitly accepted trade-off: a critical, internet-facing DC with zero vulnerabilities and full detection coverage will still score below 100 — criticality costs up to 20 points even at perfect technical hygiene, by design ("keep eyes on the crown jewels even when green"). This also means every existing `riskscore_test.go` fixture's expected score changes, not just new ones — a real re-validation of SP4's shipped formula, accepted as the cost of this integration choice over a separate-axis alternative.
4. **`internal/attackpath/score.go`'s fleet-wide `wCrownJewel` mechanism is explicitly untouched.** Crown-jewel *reachability* at the graph level is a different metric (can an attacker reach a crown jewel at all) from per-asset criticality tiering. Re-touching it would drag in re-validating attackpath's already-shipped fleet score too — out of scope for this slice.

## Architecture

### Data model
`attackpath_asset_tags` gains 5 columns (additive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`):
```sql
criticality_tier   text    NOT NULL DEFAULT ''   -- '' | critical | high | medium | low
internet_facing    boolean NOT NULL DEFAULT false
identity_exposed   boolean NOT NULL DEFAULT false
production         boolean NOT NULL DEFAULT false
compliance_scope   text[]  NOT NULL DEFAULT '{}'
```
`attackpath.AssetTag` and `attackpath.Node` (`graph.go`) both gain matching fields. `Graph.applyAssetTags` (`assets.go`) overlays all 8 fields now (was 3) — new fields follow the same "non-empty overrides" rule as `CrownJewel`/`Segment`; booleans follow `HighValue`'s "only ever promotes" rule (never silently clear a flag another source set).

### Criticality scoring — `internal/exposure/criticality.go` (new file)
```go
// CriticalityRisk scores 0-100 (higher = matters more) from an asset's tag,
// its auto-derived domain-controller role, and its SP4 threat-group exposure
// count. Pure function, no I/O.
func CriticalityRisk(tag AssetCriticalityInputs) int
```
Composition (exact bump sizes tunable during implementation, this is the starting point):
- Tier base: critical=100, high=70, medium=40, low=15, unrated(`""`)=0
- Flat bumps (capped at 100 total): +15 domain controller, +10 internet-facing, +10 identity-exposed, +10 production, +10 non-empty compliance-scope, +5 if any threat-group attributed (existing SP4 data)

### ExposureScore integration
`riskscore.go`'s composite formula gains the 4th term and reweights the existing three, per Decision 3. `ScoreBreakdown` gains `CriticalityRisk int`. `AssetIdentity` gains the 5 new tag fields (mirroring `CrownJewel`/`HighValue`'s existing presence there) plus a computed `CriticalityTier string` convenience field. `AssetSummary` (the sortable index row) gains `CriticalityTier string` and `CriticalityRisk int` so the Exposure Explorer table can sort/filter without new plumbing.

### Propagation path (no new mechanism — mirrors `CrownJewel`/`HighValue` exactly)
`attackpath_asset_tags` (DB) → `AssetTag` struct → `Graph.applyAssetTags` → `Node.<fields>` → `exposure.Build` reads `n.<fields>` off the graph node (same place it already reads `n.CrownJewel`/`n.HighValue`) → `CriticalityRisk()`.

### API
`GET /api/attackpath/assets` / `POST /api/attackpath/assets` (`attackpath_handlers.go`) round-trip the 5 new `AssetTag` JSON fields alongside the existing ones — no new endpoints. `SetAttackPathAsset`'s "empty tag clears the row" check widens from 3 fields to all 8, so clearing only the legacy fields doesn't orphan a criticality tag.

### UI
The existing attack-path asset-tagging panel (`wwwroot/index.html`, hardlinked to `cmd/server/wwwroot/index.html` — both files need editing, both need committing, per the SP4 repo-quirk note) gains a criticality-tier dropdown, three checkboxes, and a compliance-scope tag input. Exposure Explorer asset cards gain a criticality-tier badge. No new tabs or drawers — extends what's already there.

## Testing (TDD)
- `criticality_test.go` (new) — table-driven: unrated/untagged → 0; each tier alone; each boolean bump; DC auto-bump; threat-group-count bump; capped at 100.
- `riskscore_test.go` — **recalculate existing fixtures' expected scores** for the new weights (not just add new cases — every existing expected value shifts even at criticality=0, since the three original weights themselves change).
- `build_test.go` (exposure) — tag → `Node` → `AssetIdentity`/`ScoreBreakdown` propagation, including the "only promotes" boolean rule.
- `attackpath_assets_test.go` (API) — round-trip the 5 new fields through Set/Get; verify "clear" now requires all 8 fields empty, not 3.
- Manual: browser spot-check the widened tagging panel and the criticality badge (no browser tool available mid-session historically for this repo — flag as a known gap same as SP4/OpenAEV, recommend a manual pass).

## Out of scope
New agent-side collection for internet-exposure auto-detection (Decision 2 — manual tag this slice, revisit if a client engagement needs the automation). `internal/attackpath/score.go`'s fleet `wCrownJewel` mechanism (Decision 4). Any change to the `findings` table schema — criticality reaches findings entirely through the existing per-asset aggregation in `AssetExposureProfile`, no new join or column.

## Capture
Vault: new `Asset Criticality` feature note (status: in-progress); Roadmap SP6 moves to in-progress; new ADR for the ExposureScore reweighting decision (a real architectural trade-off, not a routine implementation choice); daily note.
