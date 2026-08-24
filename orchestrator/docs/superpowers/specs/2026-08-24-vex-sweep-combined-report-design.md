# Variant Sweep Combined Report — Design

**Status:** Approved (sections reviewed and confirmed with user, 2026-08-24)
**Spec type:** Architectural

## Problem

Reported as: "no report generated for variant runs, there should be report
for even one technique, multiple or full sweep or any."

Investigation split this into two parts:

1. **A bounded UI gap** (not covered by this spec — implemented separately
   as a normal bounded fix): the ad-hoc Variant Test panel (single
   technique, `RunVariants`) and the Full Variant Sweep drilldown row have
   no report buttons at all, even though the underlying per-run report
   endpoints (`GetRunReport`/`GetRunPDF`, keyed by `scenario_runs.id`)
   already work correctly for these runs — the fix is adding buttons that
   call an endpoint that already works.
2. **This spec**: a Full Variant Sweep, by construction, dispatches many
   *different* techniques (one to potentially hundreds) as separate
   `scenario_runs` rows. There is no single report showing the sweep as a
   whole — an operator can only ever see one technique's results at a
   time. Given a sweep can group anywhere from 1 to hundreds of
   techniques, "multiple techniques" and "full sweep" are the same
   mechanism at different scales; this spec covers a **combined report for
   an entire sweep**, at any size.

## Constraints confirmed with the user

- **Row grain**: the technique-level table shows one row per MITRE
  technique, not one row per variant/result. At full-sweep scale
  (potentially hundreds of variants across many techniques), a
  one-row-per-result table would bury the signal in noise and turn the
  report into a raw execution log rather than an assessment. Raw
  per-variant detail stays available one click away, via the existing
  per-technique report (already built, already reportable, just needs a
  button per the bounded fix above).
- **Row columns**: `Technique | Variants | Blocked | Detected | Missed |
  Error/Skipped | Prevention% | Detection%`. Missed is the row's critical
  drill-down signal — the blind spots a variant sweep exists to surface.
- **Never discard variant-level data**: the aggregation is purely
  computed on top of `scenario_runs.results`; nothing about how
  individual variant results are stored or reported changes.
- **Include an encoding/evasion-effectiveness breakdown**: which
  encodings and evasions actually get past controls is arguably the core
  insight a variant sweep exists to produce, not a "later" feature — it
  ships in the same report as the technique table.
- **Hierarchy**: Sweep (executive/coverage view) → Technique (analyst
  view, via the per-technique report) → Variant (forensic view, via that
  report's own result rows). This design only adds the top layer; the
  other two already exist.

## Root cause / why nothing shows today

Nothing prevents this at the data layer — every technique dispatched in a
sweep already lands as a real `scenario_runs` row (tagged `sweep_id`),
with its `results` fully populated exactly like any other run. The gap
is purely that no code today unions those rows into one document, the
way `BuildFromCampaign` already does for campaigns. The building blocks
needed already exist elsewhere in the codebase (see Design), just never
assembled for this grouping.

## Design

### 1. Architecture & data flow

New `Engine.BuildFromSweep(ctx, sweepID, filter) (*FullReport, error)` in
`internal/reporting/engine.go`, mirroring `BuildFromCampaign`'s exact
shape (same `*FullReport` return type, same `ReportScope` pattern with
`Kind: "sweep"`):

1. Loads sweep metadata (`vexsweep.Store.Get` — the same call
   `GetVexSweepRuns` already makes).
2. Loads every `scenario_runs` row for the sweep, reusing
   `GetVexSweepRuns`'s existing query (`WHERE sweep_id = $1`) — one row
   per technique, `results` already containing every variant's outcome.
3. Unions all `results` across those rows exactly like the campaign
   roll-up's `allResults`, and reuses the **existing, unmodified** report
   sections computed from that union for free: `TacticHeatmap`,
   `TopFindings`, `ExecutiveSummary`, `DetectionSummary`, `AttackPath`,
   `EnvRestoration`, etc. — no new code needed for any of these; the rest
   of the report "just works" the same way it does for campaigns.
4. Adds two new sections specific to this report (see Data model below):
   `SweepTechniqueBreakdown` and `SweepEncodingBreakdown`.

New routes, mirroring the campaign report routes exactly: `GET
/api/vex/sweeps/{id}/report` and `GET /api/vex/sweeps/{id}/pdf` — thin
handlers calling `BuildFromSweep` then the existing
`GenerateHTML`/PDF renderer. Same template, no new HTML/PDF generation
code: `ReportScope` and per-section nil-safety already make the template
scope-agnostic (a sweep report simply never populates `CampaignAgents`,
which the template already skips gracefully when empty).

**Frontend wiring is part of this spec** (distinct from the separately
implemented bounded fix, which adds a button on an *individual*
technique's row linking to its own per-technique report): the sweep
drilldown (`openSweepDrilldown`, `wwwroot/index.html:15621`) gets its own
"HTML Report"/"Download"/PDF buttons at the sweep level, calling the two
new endpoints above — mirroring `openCampaignReport`/
`downloadCampaignReport`'s existing pattern exactly. Without this, the
new report would exist server-side with no way to reach it, repeating
the same class of gap this whole investigation started from.

### 2. Data model & interface changes

New types in `internal/reporting/engine.go`:

```go
// SweepTechniqueRow is one technique's rolled-up outcome across every
// variant dispatched for it within a sweep.
type SweepTechniqueRow struct {
	TechniqueID   string  `json:"techniqueId"`
	TechniqueName string  `json:"techniqueName"`
	Tactic        string  `json:"tactic"`
	Variants      int     `json:"variants"`      // total results for this technique
	Blocked       int     `json:"blocked"`       // prevented
	Detected      int     `json:"detected"`      // ran, but alerted
	Missed        int     `json:"missed"`        // ran, no alert — the blind spot
	ErrorSkipped  int     `json:"errorSkipped"`  // execution problems, not security outcomes
	Measurable    bool    `json:"measurable"`    // false when Blocked+Detected+Missed == 0
	PreventionPct float64 `json:"preventionPct"` // Blocked / (Blocked+Detected+Missed) * 100; 0 when !Measurable
	DetectionPct  float64 `json:"detectionPct"`  // Detected / (Blocked+Detected+Missed) * 100; 0 when !Measurable
	ScenarioRunID string  `json:"scenarioRunId"` // drill-down target for the existing per-technique report
}

// SweepEncodingRow is one encoding/evasion dimension's effectiveness
// across every technique in a sweep.
type SweepEncodingRow struct {
	Encoding   string  `json:"encoding"`  // variant.Enc* constant
	Total      int     `json:"total"`
	Caught     int     `json:"caught"`    // PREVENTED
	Bypassed   int     `json:"bypassed"`  // ALLOWED
	Measurable bool    `json:"measurable"` // false when Caught+Bypassed == 0 (all ERROR)
	CaughtPct  float64 `json:"caughtPct"` // Caught / (Caught+Bypassed) * 100; 0 when !Measurable
}
```

`FullReport` gains two new `omitempty` fields —
`SweepTechniqueBreakdown []SweepTechniqueRow` and
`SweepEncodingBreakdown []SweepEncodingRow` — both nil for every
non-sweep report, so campaign and single-run report shapes are
unchanged.

**Not-measurable guard**: a technique (or encoding) whose variants all
errored or got skipped has zero measurable security outcomes, so its row
must show `Measurable: false` — the frontend renders "—", never a
misleading "0% prevention" that would read as "100% failure." This
mirrors the rule already established elsewhere in this reporting engine
for pure-deficit scores (`EnvRestoration`, exercise scoring): a
zero-denominator result is withheld as not-measurable, not silently
shown as a real number.

**Shared classifier**: extract `classifyOutcome(r models.SimulationResult,
dets []DetectionTechnique) string` (returns
`"blocked"|"detected"|"missed"|"excluded"`) from `buildKillChain`'s
existing inline prevented/detected/missed logic. Both `buildKillChain`
and the new technique-rollup call this one function, so there is a
single source of truth for what counts as blocked vs. detected vs.
missed, not two copies that can drift apart.

**Data source for the encoding breakdown**: join `variant_runs` (scoped
to the sweep's `scenario_run_id`s) → `variant_run_steps`, matched against
each run's `results` by `TaskID` — the exact join `GetVariantRun`
already performs for a single technique's detail view, run here across
every technique in the sweep instead of one. Classified with the
existing `simResultToVerdict` (PREVENTED/ALLOWED/ERROR), which is the
coarser 3-way split already used for encoding-level "caught vs. bypassed"
framing.

**New routes**: `internal/api/vexsweep_handlers.go` gets
`GetSweepReport`/`GetSweepPDF`, registered in `routes.go` as `GET
/api/vex/sweeps/{id}/report` and `GET /api/vex/sweeps/{id}/pdf` — same
pattern as `GetCampaignReport`/`GetCampaignPDF`.

### 3. Error handling & fallback behavior

- **Sweep not found**: `404`, same as `GetVexSweepRuns`/`GetCampaignReport`
  today.
- **Sweep still running (not completed)**: the report renders anyway,
  reflecting whatever results have landed so far — same precedent as
  campaigns, which never check `status` before aggregating. The report
  carries a clear "Sweep in progress — N/M techniques completed" banner
  (reusing the sweep's own `CompletedVariants`/`TotalVariants` progress
  fields) so a partial report is never mistaken for a final assessment.
- **Sweep with zero completed results yet**: `HasData: false` on the new
  sections (same convention as `EnvRestoration.HasData`/
  `DetectionValidationSection.HasData` elsewhere in this engine) — an
  empty state, not an error.
- **A technique dispatched but its run has no results yet**: excluded
  from `SweepTechniqueBreakdown` entirely (nothing to aggregate) rather
  than shown as a fake zero-row; it reappears once its first result
  lands.
- **Encoding-breakdown join gap** (a `variant_run_steps` row missing, or
  the join returning nothing for one technique): fails soft — that
  technique contributes nothing to `SweepEncodingBreakdown`, the rest of
  the report renders normally. Never blocks the whole report over one
  join gap, matching how the campaign roll-up already treats its own
  optional aggregate queries.
- **PDF rendering**: no new behavior — reuses the exact same
  `GenerateHTML` → Chromium-sidecar → fpdf-fallback pipeline every other
  report already goes through.

### 4. Testing

- **`classifyOutcome`** (extracted from `buildKillChain`): table-driven
  unit test covering blocked/detected/missed/excluded, plus confirming
  `buildKillChain`'s existing tests still pass unchanged after the
  extraction.
- **`buildSweepTechniqueBreakdown(results []models.SimulationResult, dets
  []DetectionTechnique) []SweepTechniqueRow`**: pure function,
  synthetic-fixture table tests — mixed blocked/detected/missed/error
  results for one technique → correct counts and percentages; an
  all-error technique → `Measurable: false`; empty input → empty slice.
- **`buildSweepEncodingBreakdown(results []variant.Result)
  []SweepEncodingRow`**: same pure-function approach — the DB join is a
  thin, separately-tested data-gathering step feeding this function, so
  the aggregation logic itself needs no live DB to test.
- **`BuildFromSweep` integration test**: extend the existing
  `seedReportableRun`-style fixture pattern with a seeded sweep (multiple
  techniques, mixed outcomes, one technique's variants spanning several
  encodings) — assert both new sections aggregate correctly *and* that
  the reused sections (TacticHeatmap, TopFindings, ExecutiveSummary)
  reflect the union of all sweep results, matching how the campaign
  roll-up test already verifies for campaigns.
- **In-progress sweep case**: seed a sweep with some techniques completed
  and one still running with zero results — assert the report renders
  without error, shows the progress banner, and excludes the
  zero-result technique.
- **API-level tests** for `GetSweepReport`/`GetSweepPDF`: 404 for unknown
  sweep, 200 + correct JSON for a real seeded sweep — mirroring
  `TestGetCampaignReport_HTML`/`TestGetCampaignPDF_Success` exactly.
- **Frontend**: `node --check` syntax verification on the report-button
  wiring added to the sweep drilldown row, mirroring
  `openCampaignReport`/`downloadCampaignReport`.
- **Real end-to-end verification**: a live sweep run through the actual
  UI is best-effort depending on whether a dev environment is available
  at implementation time — flagged honestly rather than assumed.

## Out of scope

- The bounded per-technique report-button wiring fix (ad-hoc Variant Test
  panel, sweep drilldown row's single-technique link) — implemented
  separately as a normal bounded fix, not spec'd here.
- Any change to how individual variant results are stored, dispatched,
  or classified at the agent level — this is purely a new report
  assembled from data that already exists.
- A combined report spanning multiple *sweeps* (e.g. comparing two
  sweeps run weeks apart) — out of scope; this is one report per one
  sweep.
- Grouping ad-hoc (non-sweep) multi-technique test runs into a combined
  report — `RunVariants` only ever accepts one technique per call today
  and has no shared grouping key across separate calls; if an operator
  wants a combined view across specific techniques without a full ART
  sweep, the existing sweep feature (which already supports a technique
  subset via `dispatch_subset`) is the mechanism, not a new one.
