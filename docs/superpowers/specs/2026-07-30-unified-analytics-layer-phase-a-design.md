# Unified Analytics Layer, Sub-project A: Foundation — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-30.
**Depends on:** nothing new — this sub-project touches only already-shipped packages (`internal/dashboard`, `internal/campaign`, `internal/compliance`/`internal/db`, `internal/exposure`, `internal/predict`, `internal/attackpath`, `internal/pathcorrelation`).

## Problem

The platform has two dashboards (Operational tab, Executive Dashboard tab) computing overlapping metrics through two independent code paths with zero shared logic. Investigated live this session before any design work: `internal/dashboard.Compute()` (Executive's engine) already assembles Risk, Exposure, and Detection Coverage into one `Snapshot`, but via inline SQL and a flat, collapsed shape; Operational computes nothing fleet-wide for Risk at all, and reads Compliance/Campaigns through entirely separate handler-local code that `dashboard.Compute()` never touches. There is no single place that defines "what is this fleet's Risk Score" — only two dashboards each computing their own answer, with real risk of silent disagreement.

**User's target architecture** (stated explicitly): dashboards become a pure presentation layer; every metric — Risk, Compliance, Exposure, Campaigns, Detection, Threat Intel, Endpoint Posture — has exactly one canonical definition in an Analytics Layer that all current and future dashboard views consume.

This sub-project covers 4 of the 7 categories, confirmed by investigation to be clean or near-clean: **Risk, Compliance, Exposure, Campaigns**. Detection (3 genuinely distinct "coverage" concepts needing a real design decision), Threat Intel (no summary function exists), and Endpoint Posture (no backend concept exists at all) are separate, later sub-projects — deliberately excluded here so this sub-project stays provably correct and shippable on its own.

## Non-Goals

- **No frontend changes.** Nothing in `cmd/server/wwwroot/index.html` changes in this sub-project. Both dashboard tabs keep working exactly as they do today, on their existing endpoints, until Sub-project B rewires them.
- **No changes to the campaign detail endpoint** (`GET /api/campaigns/{id}/summary`, `CampaignSummary` handler) or its richer per-agent `childRunOut` response shape (`internal/api/campaign_handlers.go:145-151`). Only the fleet-*list* endpoint (`GET /api/campaigns`, `ListCampaigns`) gets refactored to call the new canonical function — the detail view's existing `loadCampaign`/`loadChildren`/`summaryFor` machinery is untouched, since it serves a different, richer purpose this sub-project doesn't need to touch.
- **No new database tables, columns, or migrations.** Every category here reads data that's already persisted (`scenario_runs`, `compliance_snapshots`, `campaigns`, `findings`, `attackpath_collections`, `attackpath_asset_tags`, `agents`) through queries that already exist in some form.
- **No behavior change to `dashboard.Compute()`'s output.** Refactoring it to call the new `internal/analytics` functions instead of owning the logic inline must produce byte-identical `Snapshot` values for the same DB state — this is a pure extraction, not a recalculation. Verified by keeping `dashboard`'s existing tests green (or adding one if none exist) before and after the refactor.
- **No merging of Exposure's distinct concepts into one number.** `AssetExposureSummary` and `FindingExposureWindows` stay separately named, separately callable results — this sub-project's whole point for Exposure is disambiguating what "exposure" means, not re-collapsing it. (Investigated further while grounding the plan: `exposure.CriticalityRisk` turned out to already be fully wired into `exposure.Build()` itself — every `AssetSummary.CriticalityRisk` field is already that computation's output, already served live by Operational's `GetExposureAssets` today. So there is no separate "asset criticality" accessor to build here; it was never actually a 3rd un-unified concept, just a field inside the already-unified asset summary. Corrected below.)

## Architecture

### 1. New package `internal/analytics` — thin orchestration facade, one file per category

Each domain's actual computation logic stays in its own existing domain package (`internal/campaign`, `internal/db`, `internal/exposure`, `internal/predict`) — `internal/analytics` does not reimplement anything; it's the single place dashboards call, which delegates. This matches the one category that's already exactly the target pattern (Compliance) rather than inventing a new shape.

```go
// internal/analytics/risk.go
package analytics

// FleetRisk returns the fleet-wide average risk score across completed runs
// in the last 30 days -- the exact query moved verbatim from
// internal/dashboard's former avgRiskScore, now the only definition.
func FleetRisk(ctx context.Context, pool *pgxpool.Pool) (RiskResult, error)

type RiskResult struct {
	FleetAvgScore int `json:"fleetAvgScore"` // 0-100, 0 when no completed runs in the window
}
```

```go
// internal/analytics/compliance.go
package analytics

// Compliance returns the latest persisted compliance_snapshots rows -- fleet-
// wide (one row per framework, the lowest-compliance agent's snapshot,
// matching db.GetFleetComplianceScores' existing ORDER BY compliance_pct ASC)
// when agentID is "", or that agent's own per-framework rows otherwise.
// Thin pass-through -- no new query logic, both underlying functions
// (db.GetFleetComplianceScores, db.GetComplianceScores) already exist and are
// already what Operational's dashboard calls today via GetComplianceDashboardScores.
func Compliance(ctx context.Context, pool *pgxpool.Pool, agentID string) ([]db.ComplianceSnapshot, error)
```

```go
// internal/analytics/campaigns.go
package analytics

// Campaigns returns every campaign with its live rollup -- a thin pass-
// through to the new campaign.ListWithRollups (see §2).
func Campaigns(ctx context.Context, pool *pgxpool.Pool) ([]campaign.Rollup, error)
```

```go
// internal/analytics/exposure.go
package analytics

// FleetExposure holds the one expensive build (attack-path graph + asset
// exposure computation) so its two accessors below stay cheap -- mirrors
// exposure.AssetGraph's own existing "Build() is the only expensive call"
// convention (internal/exposure/build.go:12-19).
type FleetExposure struct {
	graph *attackpath.Graph
	sum   attackpath.Summary
	corr  pathcorrelation.AttackPathCorrelation
	ag    *exposure.AssetGraph
	tags  []attackpath.AssetTag
}

// BuildFleetExposure performs the one expensive pass -- the same
// attackpath.BuildGraphAndAnalyze + pathcorrelation.Correlate + exposure.Build
// sequence dashboard.Compute already performs today, moved here as the
// single definition. dashboard.Compute is refactored to call this (§3)
// instead of repeating the sequence inline. pathcorrelation.Correlate is
// computed internally because exposure.Build's existing signature already
// requires its output as an input -- this was true before this sub-project
// too (dashboard.Compute already calls Correlate before Build today).
// Storing it on FleetExposure just avoids computing it a second time; it
// does NOT make this sub-project the owner of Detection's canonical
// analytics category -- Sub-project C still decides what "Detection" means
// across pathcorrelation.Correlate/coverage.Compute/GetCoverageAnalytics'
// 3 distinct concepts. Correlation() below only re-exposes a value this
// struct already had to compute for Exposure's own sake.
func BuildFleetExposure(ctx context.Context, pool *pgxpool.Pool) (*FleetExposure, error)

// Correlation returns the pathcorrelation.AttackPathCorrelation value this
// FleetExposure already computed as a prerequisite for exposure.Build --
// exposed so dashboard.Compute (§3) doesn't need to call Correlate a second
// time just to read corr.Score for its (still Sub-project-A-untouched)
// DetectionCoverage field.
func (fe *FleetExposure) Correlation() pathcorrelation.AttackPathCorrelation

// AssetExposureSummary is the cheap accessor: fleet average (same
// total/len(summaries) arithmetic dashboard.Compute already does) plus the
// full per-asset list -- exposure.AssetGraph.Summaries()'s own
// []AssetSummary, unchanged, which Operational's GetExposureAssets already
// serves live today via the same exposure.Build call. Each AssetSummary
// already carries both ExposureScore and CriticalityRisk
// (internal/exposure/types.go:124,131) -- CriticalityRisk is computed
// inside exposure.Build itself (build.go:175-183) and stored in
// profile.Scores.CriticalityRisk, surfaced via Summaries(). There is no
// separate "asset criticality" accessor to add here: it was never actually
// a distinct un-unified concept, just a field on the already-unified asset
// summary.
func (fe *FleetExposure) AssetExposureSummary() ExposureSummary

type ExposureSummary struct {
	FleetAvgScore int                    `json:"fleetAvgScore"`
	Assets        []exposure.AssetSummary `json:"assets"`
}

// FindingExposureWindows is unrelated to the graph/asset-based exposure
// above -- the 3rd distinct "exposure" concept (open-finding staleness).
// Thin pass-through to predict.Build, using only its Exposure half; no
// change needed inside internal/predict, Build is already exported.
func FindingExposureWindows(ctx context.Context, pool *pgxpool.Pool) (predict.ExposureWindows, error)
```

### 2. New `campaign.ListWithRollups` — the one real extraction

`internal/campaign` (package comment: "Pure + server-side; compute-on-read, no stored counters") already owns `Aggregate`/`DeriveStatus` — the actual rollup math. What it's missing is the *listing* query, which today lives trapped inside `internal/api/campaign_handlers.go`'s `Handler.loadCampaign`/`loadChildren`/the `ListCampaigns` loop (`campaign_handlers.go:224-286`), unreachable from anywhere outside `internal/api`.

```go
// internal/campaign/store.go (new file)
package campaign

// Rollup is one campaign with its live-computed Summary -- the shape
// GET /api/campaigns already returns today (campaign_handlers.go:281-284),
// now with a name: the analytics-layer's canonical Campaigns result.
type Rollup struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ScenarioID   string  `json:"scenarioId"`
	ScenarioName string  `json:"scenarioName"`
	Mode         string  `json:"mode"`
	CreatedBy    string  `json:"createdBy"`
	StartedAt    time.Time `json:"startedAt"`
	Summary      Summary `json:"summary"`
}

// ListWithRollups queries every campaign and its child runs, computing each
// one's live Summary via the existing Aggregate/DeriveStatus. A fresh,
// focused implementation for the fleet-list need -- deliberately not a
// refactor of loadCampaign/loadChildren (internal/api/campaign_handlers.go),
// which also builds the richer per-agent childRunOut breakdown the single-
// campaign detail endpoint needs and this list endpoint does not. See
// design spec Non-Goals.
func ListWithRollups(ctx context.Context, pool *pgxpool.Pool) ([]Rollup, error)
```

`internal/api/campaign_handlers.go`'s `ListCampaigns` (`campaign_handlers.go:260-287`) is refactored to call `campaign.ListWithRollups` and shape the JSON response from its result, removing its own per-ID loop. `CampaignSummary` (the detail endpoint) is untouched.

### 3. `dashboard.Compute()` refactored to consume the new layer

`internal/dashboard/snapshot.go`'s `Compute()` currently: calls its own private `avgRiskScore` (inline SQL), builds the attack-path graph and calls `exposure.Build` itself, and computes the fleet exposure average inline (`snapshot.go:65-72`). After this sub-project:

```go
func Compute(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error) {
	risk, err := analytics.FleetRisk(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	fe, err := analytics.BuildFleetExposure(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	expSummary := fe.AssetExposureSummary()
	corr := fe.Correlation() // see §1 -- reuses the value FleetExposure already computed, doesn't redefine Detection's API

	return Snapshot{
		AvgRiskScore:      risk.FleetAvgScore,
		ExposureScore:     expSummary.FleetAvgScore,
		DetectionCoverage: corr.Score,
		AssetCount:        len(expSummary.Assets),
	}, nil
}
```

This is a net *reduction* in `internal/dashboard/snapshot.go` — `avgRiskScore`, `loadCollections`, `loadAssetTags`, `loadAgents`, and the inline exposure-averaging arithmetic all move into `internal/analytics`, leaving `dashboard.Compute` as a thin caller. Confirms real deduplication happened, not just new code added alongside old.

## Testing

- `internal/analytics/risk_test.go`: `FleetRisk` against a real Postgres testcontainer — seeds `scenario_runs` with completed runs inside/outside the 30-day window and with/without a `score` JSONB value, asserts the average matches hand-computed expectation and that rows outside the window or with null `score` are excluded (mirrors the existing SQL's `WHERE` clause exactly).
- `internal/analytics/compliance_test.go`: `Compliance("")` returns fleet-wide rows (delegates to `db.GetFleetComplianceScores`), `Compliance(agentID)` returns that agent's rows only (delegates to `db.GetComplianceScores`) — both already have their own tests in `internal/db`; this test only proves the delegation, not re-testing the SQL.
- `internal/campaign/store_test.go`: `ListWithRollups` against real Postgres — seeds 2+ campaigns with differing child-run outcomes (some completed/passed, some failed-and-detected, some failed-and-missed), asserts each `Rollup.Summary` matches what `Aggregate`/`DeriveStatus` alone would compute for the same inputs (proving no logic drift from the existing, already-tested primitives).
- `internal/analytics/exposure_test.go`: `BuildFleetExposure(...).AssetExposureSummary()` against seeded attack-path/asset-tag/agent data, asserting `FleetAvgScore` and `Assets` (including each asset's `CriticalityRisk` field) match what a direct `exposure.Build(...).Summaries()` call would produce for the same inputs. `FindingExposureWindows` asserts its output equals `predict.Build(...).Exposure` for the same seeded `findings` rows.
- `internal/dashboard/snapshot_test.go` (existing or new): asserts `Compute()`'s output is unchanged for a fixed seeded DB state before and after the refactor — the regression guard for the Non-Goals' "byte-identical output" requirement.
