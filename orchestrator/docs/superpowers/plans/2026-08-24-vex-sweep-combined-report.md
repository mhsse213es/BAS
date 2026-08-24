# Variant Sweep Combined Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Full Variant Sweep (1 to hundreds of techniques) gets one combined report — technique-level Blocked/Detected/Missed rollup plus an encoding/evasion-effectiveness breakdown — reachable from the sweep drilldown.

**Architecture:** New `Engine.BuildFromSweep` in `internal/reporting/engine.go`, mirroring `BuildFromCampaign`'s existing shape exactly: union every dispatched technique's `results`, reuse every existing report section computed from that union for free, and add two new sweep-specific sections built from a shared classifier extracted from `buildKillChain`.

**Tech Stack:** Go (orchestrator only — no agent changes), vanilla JS (`wwwroot/index.html`), Postgres (`vex_sweeps`, `scenario_runs`, `variant_runs`, `variant_run_steps` — no schema changes, all tables already exist).

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-24-vex-sweep-combined-report-design.md`

## Global Constraints

- One row per technique in the technique breakdown, not one row per variant/result — a full sweep can have hundreds of variants and the table must stay readable.
- Columns exactly: `Technique | Variants | Blocked | Detected | Missed | Error/Skipped | Prevention% | Detection%`.
- Never discard or reinterpret `scenario_runs.results` — the new sections are purely computed on top; raw per-variant data stays reachable through the existing per-technique report.
- A technique (or encoding) row with zero measurable outcomes (all Error/Skipped) must show `Measurable: false`, never a misleading `0%`.
- Reuses the existing HTML/PDF rendering pipeline (`GenerateHTML`, `PDFFromReport`) unchanged — no new template.
- Report available at any sweep status, including still-running, with a progress banner — never blocked or 404'd just because the sweep isn't finished.

---

## Task 1: Extract `classifyOutcome` from `buildKillChain`

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`
- Test: `orchestrator/internal/reporting/killchain_test.go`

**Interfaces:**
- Produces: `detTechIndex(dets []DetectionTechnique) map[string]DetectionTechnique` and `classifyOutcome(r models.SimulationResult, detByTech map[string]DetectionTechnique) string` (returns `"blocked"|"detected"|"missed"|"excluded"`), both in `internal/reporting/engine.go`. Consumed by Task 3 (technique rollup) and Task 4 (encoding rollup).

This is a pure refactor — `buildKillChain`'s external behavior must not change. The current function (verified this session, lines 848-900):

```go
func buildKillChain(results []models.SimulationResult, dets []DetectionTechnique) []KillChainStep {
	detByTech := make(map[string]DetectionTechnique, len(dets))
	for _, d := range dets {
		if d.TechniqueID != "" {
			detByTech[d.TechniqueID] = d
		}
	}
	byTactic := make(map[string][]models.SimulationResult)
	for _, r := range results {
		if r.Result == models.ResultError || r.Result == models.ResultSkipped {
			continue
		}
		if r.Technique.Tactic == "" {
			continue
		}
		byTactic[r.Technique.Tactic] = append(byTactic[r.Technique.Tactic], r)
	}
	var out []KillChainStep
	for _, tactic := range tacticOrder {
		rs := byTactic[tactic]
		if len(rs) == 0 {
			continue
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].ExecutedAt.Before(rs[j].ExecutedAt) })
		for _, r := range rs {
			step := KillChainStep{
				Phase: tactic, TechniqueID: r.Technique.ID,
				Technique: r.Technique.Name, Action: killChainAction(r),
			}
			if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
				step.Outcome = "prevented"
				if ctrl := attributeControl(r); ctrl != "" {
					step.Detail = "Blocked by " + ctrl
				} else {
					step.Detail = "Prevented by a control"
				}
			} else if d, ok := detByTech[r.Technique.ID]; ok && d.Verdict == "detected" {
				step.Outcome = "detected"
				step.Confidence = d.Confidence
				step.LatencyMs = d.TimeToDetectMs
				step.Detail = "Detection alert raised"
			} else if cd := classifyDetection(r.Events); cd.Status == "Detected" {
				step.Outcome = "detected"
				step.Detail = cd.Detail
			} else {
				step.Outcome = "missed"
				step.Detail = "No detection — executed unseen"
			}
			out = append(out, step)
		}
	}
	return out
}
```

- [ ] **Step 1: Run the existing kill-chain test to record the current-passing baseline**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildKillChain -v`
Expected: PASS (this is the regression baseline the refactor must not break).

- [ ] **Step 2: Add `detTechIndex` and `classifyOutcome` above `buildKillChain`**

In `internal/reporting/engine.go`, immediately before `func buildKillChain(...)`:

```go
// detTechIndex builds a TechniqueID -> DetectionTechnique lookup, built once
// and shared across every result classification in a report (avoids
// rebuilding this map per-result).
func detTechIndex(dets []DetectionTechnique) map[string]DetectionTechnique {
	idx := make(map[string]DetectionTechnique, len(dets))
	for _, d := range dets {
		if d.TechniqueID != "" {
			idx[d.TechniqueID] = d
		}
	}
	return idx
}

// classifyOutcome classifies one result's security outcome: "blocked" (a
// control prevented it), "detected" (ran, but an alert fired), "missed"
// (ran, no detection — the blind spot), or "excluded" (ERROR/SKIPPED — an
// execution problem, not a security outcome). Shared by buildKillChain and
// the sweep technique/encoding rollups (buildSweepTechniqueBreakdown,
// buildSweepEncodingBreakdown) so there is one source of truth for this
// classification instead of copies that can drift apart.
func classifyOutcome(r models.SimulationResult, detByTech map[string]DetectionTechnique) string {
	if r.Result == models.ResultError || r.Result == models.ResultSkipped {
		return "excluded"
	}
	if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
		return "blocked"
	}
	if d, ok := detByTech[r.Technique.ID]; ok && d.Verdict == "detected" {
		return "detected"
	}
	if cd := classifyDetection(r.Events); cd.Status == "Detected" {
		return "detected"
	}
	return "missed"
}
```

- [ ] **Step 3: Rewrite `buildKillChain` to use the extracted functions**

Replace the whole function body with:

```go
func buildKillChain(results []models.SimulationResult, dets []DetectionTechnique) []KillChainStep {
	detByTech := detTechIndex(dets)
	byTactic := make(map[string][]models.SimulationResult)
	for _, r := range results {
		if classifyOutcome(r, detByTech) == "excluded" {
			continue
		}
		if r.Technique.Tactic == "" {
			continue
		}
		byTactic[r.Technique.Tactic] = append(byTactic[r.Technique.Tactic], r)
	}
	var out []KillChainStep
	for _, tactic := range tacticOrder {
		rs := byTactic[tactic]
		if len(rs) == 0 {
			continue
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].ExecutedAt.Before(rs[j].ExecutedAt) })
		for _, r := range rs {
			step := KillChainStep{
				Phase: tactic, TechniqueID: r.Technique.ID,
				Technique: r.Technique.Name, Action: killChainAction(r),
			}
			switch classifyOutcome(r, detByTech) {
			case "blocked":
				step.Outcome = "prevented"
				if ctrl := attributeControl(r); ctrl != "" {
					step.Detail = "Blocked by " + ctrl
				} else {
					step.Detail = "Prevented by a control"
				}
			case "detected":
				step.Outcome = "detected"
				if d, ok := detByTech[r.Technique.ID]; ok && d.Verdict == "detected" {
					step.Confidence = d.Confidence
					step.LatencyMs = d.TimeToDetectMs
					step.Detail = "Detection alert raised"
				} else {
					step.Detail = classifyDetection(r.Events).Detail
				}
			default: // "missed"
				step.Outcome = "missed"
				step.Detail = "No detection — executed unseen"
			}
			out = append(out, step)
		}
	}
	return out
}
```

- [ ] **Step 4: Run the existing kill-chain test to confirm no behavior change**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildKillChain -v`
Expected: PASS, identical to Step 1's baseline.

- [ ] **Step 5: Write a focused unit test for `classifyOutcome` itself**

Add to `internal/reporting/killchain_test.go`:

```go
func TestClassifyOutcome(t *testing.T) {
	dets := []DetectionTechnique{{TechniqueID: "T1003", Verdict: "detected", Confidence: "high"}}
	detByTech := detTechIndex(dets)

	cases := []struct {
		name string
		r    models.SimulationResult
		want string
	}{
		{"blocked pass", models.SimulationResult{Result: models.ResultPass, Technique: models.AttackTechnique{ID: "T1059"}}, "blocked"},
		{"blocked result", models.SimulationResult{Result: models.ResultBlocked, Technique: models.AttackTechnique{ID: "T1059"}}, "blocked"},
		{"error excluded", models.SimulationResult{Result: models.ResultError, Technique: models.AttackTechnique{ID: "T1059"}}, "excluded"},
		{"skipped excluded", models.SimulationResult{Result: models.ResultSkipped, Technique: models.AttackTechnique{ID: "T1059"}}, "excluded"},
		{"fail with detection alert", models.SimulationResult{Result: models.ResultFail, Technique: models.AttackTechnique{ID: "T1003"}}, "detected"},
		{"fail no detection", models.SimulationResult{Result: models.ResultFail, Technique: models.AttackTechnique{ID: "T1059"}}, "missed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyOutcome(c.r, detByTech); got != c.want {
				t.Errorf("classifyOutcome() = %q, want %q", got, c.want)
			}
		})
	}
}
```

- [ ] **Step 6: Run the new test**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestClassifyOutcome -v`
Expected: PASS (all 6 subtests).

- [ ] **Step 7: Commit**

```bash
git add internal/reporting/engine.go internal/reporting/killchain_test.go
git commit -m "refactor(reporting): extract classifyOutcome from buildKillChain"
git push
```

---

## Task 2: `SweepTechniqueRow` / `SweepEncodingRow` types + `FullReport` fields

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`

**Interfaces:**
- Produces: `SweepTechniqueRow`, `SweepEncodingRow` structs; `FullReport.SweepTechniqueBreakdown []SweepTechniqueRow` and `FullReport.SweepEncodingBreakdown []SweepEncodingRow` fields, consumed by Tasks 3-5.

- [ ] **Step 1: Add the two new types**

In `internal/reporting/engine.go`, immediately above `func buildKillChain(...)` (near the other report-section types), add:

```go
// SweepTechniqueRow is one technique's rolled-up outcome across every
// variant dispatched for it within a Full Variant Sweep.
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

// SweepEncodingRow is one encoding/evasion dimension's effectiveness across
// every technique in a sweep — which obfuscation actually gets past
// controls, folded from classifyOutcome's "blocked" vs "detected"/"missed".
type SweepEncodingRow struct {
	Encoding   string  `json:"encoding"`
	Total      int     `json:"total"`
	Caught     int     `json:"caught"`     // classifyOutcome == "blocked"
	Bypassed   int     `json:"bypassed"`   // classifyOutcome == "detected" or "missed"
	Measurable bool    `json:"measurable"` // false when Caught+Bypassed == 0 (all excluded)
	CaughtPct  float64 `json:"caughtPct"`  // Caught / (Caught+Bypassed) * 100; 0 when !Measurable
}
```

- [ ] **Step 2: Add the two new `FullReport` fields**

In `internal/reporting/engine.go`, the `FullReport` struct currently has (verified this session, lines 192-193):

```go
	Scope          *ReportScope       `json:"scope,omitempty"`
	CampaignAgents []CampaignAgentRow `json:"campaignAgents,omitempty"`
```

Change to:

```go
	Scope          *ReportScope       `json:"scope,omitempty"`
	CampaignAgents []CampaignAgentRow `json:"campaignAgents,omitempty"`
	// SweepTechniqueBreakdown and SweepEncodingBreakdown are set only for a
	// Full Variant Sweep's combined report (Scope.Kind == "sweep"); nil for
	// every other report kind.
	SweepTechniqueBreakdown []SweepTechniqueRow `json:"sweepTechniqueBreakdown,omitempty"`
	SweepEncodingBreakdown  []SweepEncodingRow  `json:"sweepEncodingBreakdown,omitempty"`
```

- [ ] **Step 3: Build to confirm it compiles**

Run: `cd orchestrator && go build ./...`
Expected: succeeds (no test yet — these are just new types/fields, exercised by Task 3 onward).

- [ ] **Step 4: Commit**

```bash
git add internal/reporting/engine.go
git commit -m "feat(reporting): add SweepTechniqueRow/SweepEncodingRow types"
git push
```

---

## Task 3: `buildSweepTechniqueBreakdown`

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`
- Test: `orchestrator/internal/reporting/engine_test.go`

**Interfaces:**
- Consumes: `classifyOutcome`, `detTechIndex` (Task 1); `SweepTechniqueRow` (Task 2).
- Produces: `buildSweepTechniqueBreakdown(results []models.SimulationResult, dets []DetectionTechnique) []SweepTechniqueRow`, consumed by Task 5.

- [ ] **Step 1: Write the failing tests**

Add to `internal/reporting/engine_test.go`:

```go
func TestBuildSweepTechniqueBreakdown_MixedOutcomes(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultBlocked},
		{ID: "r2", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultFail},
		{ID: "r3", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultFail},
		{ID: "r4", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultError},
	}
	dets := []DetectionTechnique{{TechniqueID: "T1055", Verdict: "detected", Confidence: "high"}}

	rows := buildSweepTechniqueBreakdown(results, dets)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.TechniqueID != "T1055" || r.TechniqueName != "Process Injection" || r.Tactic != "defense-evasion" {
		t.Errorf("row identity = %+v", r)
	}
	if r.Variants != 4 {
		t.Errorf("Variants = %d, want 4", r.Variants)
	}
	if r.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", r.Blocked)
	}
	// Both fails share technique T1055, which has a "detected" DetectionTechnique
	// entry -- classifyOutcome applies that verdict to every fail for the
	// technique (matches buildKillChain's own existing behavior), so both
	// land in Detected, none in Missed.
	if r.Detected != 2 {
		t.Errorf("Detected = %d, want 2", r.Detected)
	}
	if r.Missed != 0 {
		t.Errorf("Missed = %d, want 0", r.Missed)
	}
	if r.ErrorSkipped != 1 {
		t.Errorf("ErrorSkipped = %d, want 1", r.ErrorSkipped)
	}
	if !r.Measurable {
		t.Error("Measurable = false, want true")
	}
	wantPrevention := 1.0 / 3.0 * 100
	if math.Abs(r.PreventionPct-wantPrevention) > 0.01 {
		t.Errorf("PreventionPct = %v, want %v", r.PreventionPct, wantPrevention)
	}
	wantDetection := 2.0 / 3.0 * 100
	if math.Abs(r.DetectionPct-wantDetection) > 0.01 {
		t.Errorf("DetectionPct = %v, want %v", r.DetectionPct, wantDetection)
	}
}

func TestBuildSweepTechniqueBreakdown_AllErrorNotMeasurable(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "r1", Technique: models.AttackTechnique{ID: "T1059", Name: "PowerShell"}, Result: models.ResultError},
		{ID: "r2", Technique: models.AttackTechnique{ID: "T1059", Name: "PowerShell"}, Result: models.ResultSkipped},
	}
	rows := buildSweepTechniqueBreakdown(results, nil)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Measurable {
		t.Error("Measurable = true, want false (all results are error/skipped)")
	}
	if r.PreventionPct != 0 || r.DetectionPct != 0 {
		t.Errorf("PreventionPct/DetectionPct = %v/%v, want 0/0 when not measurable", r.PreventionPct, r.DetectionPct)
	}
	if r.ErrorSkipped != 2 {
		t.Errorf("ErrorSkipped = %d, want 2", r.ErrorSkipped)
	}
}

func TestBuildSweepTechniqueBreakdown_MultipleTechniquesAndEmptyInput(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection"}, Result: models.ResultBlocked},
		{ID: "r2", Technique: models.AttackTechnique{ID: "T1059", Name: "PowerShell"}, Result: models.ResultFail},
	}
	rows := buildSweepTechniqueBreakdown(results, nil)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2 (one per technique)", len(rows))
	}

	if rows := buildSweepTechniqueBreakdown(nil, nil); len(rows) != 0 {
		t.Errorf("empty input: len(rows) = %d, want 0", len(rows))
	}
}
```

Add `"math"` to `engine_test.go`'s import block if not already present (check with `grep -n '"math"' internal/reporting/engine_test.go` first).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildSweepTechniqueBreakdown -v`
Expected: FAIL — `buildSweepTechniqueBreakdown` undefined.

- [ ] **Step 3: Implement `buildSweepTechniqueBreakdown`**

Add to `internal/reporting/engine.go`, after `buildKillChain`:

```go
// buildSweepTechniqueBreakdown rolls a sweep's unioned results up into one
// row per technique — Blocked/Detected/Missed/ErrorSkipped counts plus
// Prevention/Detection percentages, using the same classifyOutcome rule
// buildKillChain uses. Row order follows first-appearance order in results.
func buildSweepTechniqueBreakdown(results []models.SimulationResult, dets []DetectionTechnique) []SweepTechniqueRow {
	detByTech := detTechIndex(dets)
	order := []string{}
	byTech := make(map[string]*SweepTechniqueRow)

	for _, r := range results {
		row, ok := byTech[r.Technique.ID]
		if !ok {
			row = &SweepTechniqueRow{
				TechniqueID:   r.Technique.ID,
				TechniqueName: r.Technique.Name,
				Tactic:        r.Technique.Tactic,
				ScenarioRunID: r.ID, // overwritten below if a later result carries the real run id; see note
			}
			byTech[r.Technique.ID] = row
			order = append(order, r.Technique.ID)
		}
		row.Variants++
		switch classifyOutcome(r, detByTech) {
		case "blocked":
			row.Blocked++
		case "detected":
			row.Detected++
		case "missed":
			row.Missed++
		case "excluded":
			row.ErrorSkipped++
		}
	}

	out := make([]SweepTechniqueRow, 0, len(order))
	for _, id := range order {
		row := byTech[id]
		measurable := row.Blocked+row.Detected+row.Missed > 0
		row.Measurable = measurable
		if measurable {
			denom := float64(row.Blocked + row.Detected + row.Missed)
			row.PreventionPct = float64(row.Blocked) / denom * 100
			row.DetectionPct = float64(row.Detected) / denom * 100
		}
		out = append(out, *row)
	}
	return out
}
```

**Note on `ScenarioRunID`**: this placeholder assignment (`r.ID`, a per-result ID, not a run ID) is corrected in Task 5, where `BuildFromSweep` overwrites `ScenarioRunID` on each row using the actual `scenario_runs.id` it already tracks per technique — `buildSweepTechniqueBreakdown` itself has no access to run-level identity, only to the flat `results` slice, so it cannot set this field correctly on its own. Leave the field's zero-ish value here; Task 5 Step 3 fixes it. Do not skip that step.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildSweepTechniqueBreakdown -v`
Expected: PASS (all 3 test functions).

- [ ] **Step 5: Commit**

```bash
git add internal/reporting/engine.go internal/reporting/engine_test.go
git commit -m "feat(reporting): add buildSweepTechniqueBreakdown"
git push
```

---

## Task 4: `buildSweepEncodingBreakdown`

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`
- Test: `orchestrator/internal/reporting/engine_test.go`

**Interfaces:**
- Consumes: `classifyOutcome`, `detTechIndex` (Task 1).
- Produces: `sweepEncodingSample` struct (a minimal per-step join result) and `buildSweepEncodingBreakdown(samples []sweepEncodingSample, dets []DetectionTechnique) []SweepEncodingRow` (pure aggregation, no DB access — the DB-side join lives in Task 5's `BuildFromSweep`, which gathers `[]sweepEncodingSample` and passes it in). Consumed by Task 5.

**Data source note** (from the design's grounding): `variant_run_steps.encoding` joins to a result via `variant_run_steps.task_id == models.SimulationResult.ID` (confirmed against `GetVariantRun`'s existing working join in `internal/api/variant_handlers.go`) — a variant-dispatched result's own `.ID` field equals its step's `TaskID`. `sweepEncodingSample` captures exactly this pre-joined pair so the aggregation function stays pure and DB-free.

- [ ] **Step 1: Write the failing tests**

Add to `internal/reporting/engine_test.go`:

```go
func TestBuildSweepEncodingBreakdown_CaughtVsBypassed(t *testing.T) {
	samples := []sweepEncodingSample{
		{Encoding: "base64", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultBlocked}},
		{Encoding: "base64", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail}},
		{Encoding: "plain", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail}},
		{Encoding: "plain", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail}},
	}
	rows := buildSweepEncodingBreakdown(samples, nil)
	byEnc := map[string]SweepEncodingRow{}
	for _, r := range rows {
		byEnc[r.Encoding] = r
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if b := byEnc["base64"]; b.Total != 2 || b.Caught != 1 || b.Bypassed != 1 {
		t.Errorf("base64 = %+v, want Total=2 Caught=1 Bypassed=1", b)
	}
	if p := byEnc["plain"]; p.Total != 2 || p.Caught != 0 || p.Bypassed != 2 {
		t.Errorf("plain = %+v, want Total=2 Caught=0 Bypassed=2", p)
	}
	if !byEnc["base64"].Measurable || byEnc["base64"].CaughtPct != 50 {
		t.Errorf("base64 CaughtPct/Measurable = %v/%v, want 50/true", byEnc["base64"].CaughtPct, byEnc["base64"].Measurable)
	}
}

func TestBuildSweepEncodingBreakdown_AllErrorNotMeasurable(t *testing.T) {
	samples := []sweepEncodingSample{
		{Encoding: "gzip_b64", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultError}},
	}
	rows := buildSweepEncodingBreakdown(samples, nil)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].Measurable {
		t.Error("Measurable = true, want false")
	}
	if rows[0].CaughtPct != 0 {
		t.Errorf("CaughtPct = %v, want 0", rows[0].CaughtPct)
	}
}

func TestBuildSweepEncodingBreakdown_EmptyInput(t *testing.T) {
	if rows := buildSweepEncodingBreakdown(nil, nil); len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0", len(rows))
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildSweepEncodingBreakdown -v`
Expected: FAIL — `sweepEncodingSample`/`buildSweepEncodingBreakdown` undefined.

- [ ] **Step 3: Implement `sweepEncodingSample` and `buildSweepEncodingBreakdown`**

Add to `internal/reporting/engine.go`, after `buildSweepTechniqueBreakdown`:

```go
// sweepEncodingSample is one variant's already-joined encoding + outcome,
// gathered by BuildFromSweep's DB query (scenario_runs -> variant_runs ->
// variant_run_steps, matched to a result by TaskID == result.ID) and fed
// into buildSweepEncodingBreakdown as a plain in-memory slice, keeping the
// aggregation itself DB-free and directly testable.
type sweepEncodingSample struct {
	Encoding string
	Result   models.SimulationResult
}

// buildSweepEncodingBreakdown rolls sweep-wide variant samples up by
// encoding: how often each encoding got caught (classifyOutcome ==
// "blocked") vs bypassed (classifyOutcome == "detected" or "missed").
// Samples classified "excluded" (error/skipped) count toward Total but not
// Caught/Bypassed. Row order follows first-appearance order in samples.
func buildSweepEncodingBreakdown(samples []sweepEncodingSample, dets []DetectionTechnique) []SweepEncodingRow {
	detByTech := detTechIndex(dets)
	order := []string{}
	byEnc := make(map[string]*SweepEncodingRow)

	for _, s := range samples {
		row, ok := byEnc[s.Encoding]
		if !ok {
			row = &SweepEncodingRow{Encoding: s.Encoding}
			byEnc[s.Encoding] = row
			order = append(order, s.Encoding)
		}
		row.Total++
		switch classifyOutcome(s.Result, detByTech) {
		case "blocked":
			row.Caught++
		case "detected", "missed":
			row.Bypassed++
		}
	}

	out := make([]SweepEncodingRow, 0, len(order))
	for _, enc := range order {
		row := byEnc[enc]
		measurable := row.Caught+row.Bypassed > 0
		row.Measurable = measurable
		if measurable {
			row.CaughtPct = float64(row.Caught) / float64(row.Caught+row.Bypassed) * 100
		}
		out = append(out, *row)
	}
	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildSweepEncodingBreakdown -v`
Expected: PASS (all 3 test functions).

- [ ] **Step 5: Commit**

```bash
git add internal/reporting/engine.go internal/reporting/engine_test.go
git commit -m "feat(reporting): add buildSweepEncodingBreakdown"
git push
```

---

## Task 5: `Engine.BuildFromSweep`

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`
- Test: `orchestrator/internal/reporting/engine_test.go`

**Interfaces:**
- Consumes: `buildSweepTechniqueBreakdown` (Task 3), `sweepEncodingSample`/`buildSweepEncodingBreakdown` (Task 4), and every existing report-section builder `BuildFromCampaign` already calls (`buildTacticHeatmap`, `buildTopFindings`, `buildDetectionSummary`, `buildAttackPath`, `buildTechniqueMatrix`, `models.ComputeScore`, `deriveExecutive`, etc.).
- Produces: `func (e *Engine) BuildFromSweep(ctx context.Context, sweepID string, filter string) (*FullReport, error)`, consumed by Task 6's handlers.

`vex_sweeps`' schema (verified this session, `internal/db/postgres.go:655-674`) has these columns relevant here: `agent_id text`, `techniques text[]`, `status text`, `error text`, `completed_variants int`, `total_variants int`, `started_at timestamptz`, `completed_at timestamptz`. Following `BuildFromCampaign`'s own established pattern (verified this session, `internal/reporting/engine.go:1833-1962` — it queries the `campaigns` table directly with a minimal column list rather than importing `internal/campaign`'s Store type), this task queries `vex_sweeps` directly too, not via `vexsweep.Store` — keeps `internal/reporting` free of a new cross-package dependency.

- [ ] **Step 1: Write the failing integration test**

Add to `internal/reporting/engine_test.go` (this is a container-backed test — check the file's existing `TestMain`/`sharedDB` setup at the top of the package, e.g. `internal/reporting/testmain_test.go`, and mirror whatever pool-acquisition pattern `campaign_report_test.go` already uses in this same package for its own `BuildFromCampaign` tests):

```go
func TestBuildFromSweep_AggregatesAcrossTechniquesAndEncodings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)

		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-report')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO vex_sweeps (id, agent_id, techniques, technique_variant_counts, status, completed_variants, total_variants, started_at)
			 VALUES ('sw-report-1', 'agent-sweep-report', ARRAY['T1055','T1059.001'], ARRAY[2,2], 'completed', 4, 4, NOW())`); err != nil {
			t.Fatalf("seed sweep: %v", err)
		}

		t1055Results := []models.SimulationResult{
			{ID: "t1055-r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultBlocked, Severity: "High"},
			{ID: "t1055-r2", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultFail, Severity: "High"},
		}
		t1055JSON, _ := json.Marshal(t1055Results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, sweep_id)
			 VALUES ('sr-t1055', '__variant__T1055', 'agent-sweep-report', 'T1055 variants', 'completed', $1, 'sw-report-1')`,
			t1055JSON); err != nil {
			t.Fatalf("seed sr-t1055: %v", err)
		}

		t1059Results := []models.SimulationResult{
			{ID: "t1059-r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
			{ID: "t1059-r2", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
		}
		t1059JSON, _ := json.Marshal(t1059Results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, sweep_id)
			 VALUES ('sr-t1059', '__variant__T1059.001', 'agent-sweep-report', 'T1059.001 variants', 'completed', $1, 'sw-report-1')`,
			t1059JSON); err != nil {
			t.Fatalf("seed sr-t1059: %v", err)
		}

		// variant_runs + variant_run_steps wiring for the encoding breakdown.
		if _, err := pool.Exec(ctx,
			`INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, total_variants, status)
			 VALUES ('vr-t1055', 'agent-sweep-report', 'T1055', 'sr-t1055', 2, 'completed')`); err != nil {
			t.Fatalf("seed vr-t1055: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO variant_run_steps (variant_run_id, task_id, encoding, exec_context, evasion, executor, risk_level, variant_hash)
			 VALUES ('vr-t1055', 't1055-r1', 'base64', 'powershell_direct', 'none', 'powershell', 'SAFE', 'hash1'),
			        ('vr-t1055', 't1055-r2', 'plain', 'powershell_direct', 'none', 'powershell', 'SAFE', 'hash2')`); err != nil {
			t.Fatalf("seed variant_run_steps: %v", err)
		}

		rep, err := e.BuildFromSweep(ctx, "sw-report-1", "")
		if err != nil {
			t.Fatalf("BuildFromSweep: %v", err)
		}

		if rep.Scope == nil || rep.Scope.Kind != "sweep" {
			t.Fatalf("Scope = %+v, want Kind=sweep", rep.Scope)
		}
		if len(rep.SweepTechniqueBreakdown) != 2 {
			t.Fatalf("len(SweepTechniqueBreakdown) = %d, want 2", len(rep.SweepTechniqueBreakdown))
		}
		byTech := map[string]SweepTechniqueRow{}
		for _, r := range rep.SweepTechniqueBreakdown {
			byTech[r.TechniqueID] = r
		}
		if t1055 := byTech["T1055"]; t1055.Blocked != 1 || t1055.ScenarioRunID != "sr-t1055" {
			t.Errorf("T1055 row = %+v, want Blocked=1 ScenarioRunID=sr-t1055", t1055)
		}
		if len(rep.SweepEncodingBreakdown) != 2 {
			t.Fatalf("len(SweepEncodingBreakdown) = %d, want 2 (base64, plain)", len(rep.SweepEncodingBreakdown))
		}
		// The rest of the report reuses the union of all sweep results --
		// spot-check one already-existing section actually populated.
		if len(rep.TacticHeatmap) == 0 {
			t.Error("TacticHeatmap is empty — union of sweep results did not reach the reused report sections")
		}
	})
}

func TestBuildFromSweep_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := NewEngine(pool)
		if _, err := e.BuildFromSweep(context.Background(), "nope", ""); err == nil {
			t.Fatal("expected an error for an unknown sweep id")
		}
	})
}
```

Before writing this, run `grep -n "func TestMain\|sharedDB\|func NewEngine" internal/reporting/*.go` to confirm the exact `NewEngine` constructor signature and the package's shared-pool test helper name — adjust the fixture above to match exactly what's actually there (this plan's fixture is grounded in the same patterns used by `vexsweep_handlers_test.go` and `report_fixtures_test.go` elsewhere in this session, but the `internal/reporting` package's own test scaffolding must be confirmed directly since it wasn't re-read line-by-line for this specific file).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildFromSweep -v`
Expected: FAIL — `BuildFromSweep` undefined.

- [ ] **Step 3: Implement `BuildFromSweep`**

Add to `internal/reporting/engine.go`, after `BuildFromCampaign`:

```go
func (e *Engine) BuildFromSweep(ctx context.Context, sweepID string, filter string) (*FullReport, error) {
	report := &FullReport{GeneratedAt: time.Now().UTC()}

	var agentID string
	var techniques []string
	var status, sweepErr string
	var completedVariants, totalVariants int
	var startedAt time.Time
	var completedAt *time.Time
	if err := e.db.QueryRow(ctx,
		`SELECT agent_id, techniques, status, error, completed_variants, total_variants, started_at, completed_at
		   FROM vex_sweeps WHERE id = $1`, sweepID,
	).Scan(&agentID, &techniques, &status, &sweepErr, &completedVariants, &totalVariants, &startedAt, &completedAt); err != nil {
		return nil, fmt.Errorf("sweep %s not found: %w", sweepID, err)
	}

	rows, err := e.db.Query(ctx,
		`SELECT id, results FROM scenario_runs WHERE sweep_id = $1 ORDER BY started_at`, sweepID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allResults []models.SimulationResult
	resultsByID := make(map[string]models.SimulationResult)
	runIDByTechnique := make(map[string]string)
	var scenarioRunIDs []string
	runCount := 0
	for rows.Next() {
		var runID string
		var resultsRaw []byte
		if rows.Scan(&runID, &resultsRaw) != nil {
			continue
		}
		runCount++
		scenarioRunIDs = append(scenarioRunIDs, runID)
		var results []models.SimulationResult
		if len(resultsRaw) > 0 {
			if json.Unmarshal(resultsRaw, &results) == nil {
				results = FilterResults(results, filter)
				for _, r := range results {
					resultsByID[r.ID] = r
					if _, ok := runIDByTechnique[r.Technique.ID]; !ok {
						runIDByTechnique[r.Technique.ID] = runID
					}
				}
				allResults = append(allResults, results...)
			}
		}
	}

	report.TacticHeatmap = buildTacticHeatmap(allResults)
	report.TopFindings = buildTopFindings(allResults, "Full Variant Sweep")
	report.ObjectiveRisks = buildObjectiveRisks(allResults)
	report.Detection = buildDetectionSummary(allResults)
	report.AttackPath = buildAttackPath(allResults)
	report.TechniqueMatrix = buildTechniqueMatrix(allResults, nil)
	report.CoverageBreakdown = buildCoverageBreakdown(report.TechniqueMatrix)
	report.PrivilegeSummary = buildPrivilegeSummary(report.TechniqueMatrix)
	report.KillChain = buildKillChain(allResults, nil)

	report.SweepTechniqueBreakdown = buildSweepTechniqueBreakdown(allResults, nil)
	for i := range report.SweepTechniqueBreakdown {
		report.SweepTechniqueBreakdown[i].ScenarioRunID = runIDByTechnique[report.SweepTechniqueBreakdown[i].TechniqueID]
	}

	var encSamples []sweepEncodingSample
	if len(scenarioRunIDs) > 0 {
		stepRows, err := e.db.Query(ctx,
			`SELECT vrs.task_id, vrs.encoding
			   FROM variant_run_steps vrs
			   JOIN variant_runs vr ON vr.id = vrs.variant_run_id
			  WHERE vr.scenario_run_id = ANY($1)`, scenarioRunIDs)
		if err == nil {
			for stepRows.Next() {
				var taskID, encoding string
				if stepRows.Scan(&taskID, &encoding) != nil {
					continue
				}
				if res, ok := resultsByID[taskID]; ok {
					encSamples = append(encSamples, sweepEncodingSample{Encoding: encoding, Result: res})
				}
			}
			stepRows.Close()
		}
	}
	report.SweepEncodingBreakdown = buildSweepEncodingBreakdown(encSamples, nil)

	score := models.ComputeScore(allResults, nil)
	report.Summary = ExecutiveSummary{
		RiskScore: score.RiskScore, Classification: score.Classification,
		PreventionScore: score.PreventionScore, ExposureScore: score.ExposureScore,
		CoverageScore: score.CoverageScore, KillChainCoverage: score.KillChainCoverage,
		KillChainAmplifier: score.KillChainAmplifier, Trend: score.Trend,
		TotalRuns: runCount, TotalTechniques: score.TotalTechniques,
		PassedTechniques: score.PassedTechniques, FailedTechniques: score.FailedTechniques,
		ErroredTechniques: score.ErroredTechniques, SkippedTechniques: score.SkippedTechniques,
		LastRunAt: startedAt, LastScenarioName: "Full Variant Sweep",
		CriticalFailures: score.CriticalFailures,
		Recommendations:  buildRecommendations(score, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}

	title := fmt.Sprintf("Full Variant Sweep — %s", agentID)
	subtitle := fmt.Sprintf("%d/%d techniques completed", completedVariants, totalVariants)
	if status == "running" || status == "agent_disconnected" {
		subtitle = "Sweep in progress — " + subtitle
	}
	report.Agent.Hostname = agentID
	report.ScenarioName = "Full Variant Sweep"
	report.Scope = &ReportScope{
		Kind: "sweep", Title: title, Subtitle: subtitle,
		Scenario: "Full Variant Sweep", AgentCount: 1, RunCount: runCount,
	}

	deriveExecutive(report, allResults, nil)

	return report, nil
}
```

**Note**: `report.SweepTechniqueBreakdown[i].ScenarioRunID` is set in a second pass after `buildSweepTechniqueBreakdown` returns, using `runIDByTechnique` (built while unioning results) — this is the fix flagged in Task 3 Step 3's note; `buildSweepTechniqueBreakdown` itself has no run-level identity to draw on, so the caller (`BuildFromSweep`, the only place with both technique and run identity in scope) closes that gap.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/... -run TestBuildFromSweep -v`
Expected: PASS (both `TestBuildFromSweep_AggregatesAcrossTechniquesAndEncodings` and `TestBuildFromSweep_NotFound`).

- [ ] **Step 5: Run the full reporting package suite**

Run: `cd orchestrator && go test ./internal/reporting/... -v`
Expected: PASS, zero `--- FAIL` lines (confirms Tasks 1-5 together haven't broken anything else in the package, including the `TestBuildKillChain` regression baseline from Task 1).

- [ ] **Step 6: Commit**

```bash
git add internal/reporting/engine.go internal/reporting/engine_test.go
git commit -m "feat(reporting): add Engine.BuildFromSweep"
git push
```

---

## Task 6: `GetSweepReport`/`GetSweepPDF` handlers + routes

**Files:**
- Modify: `orchestrator/internal/api/vexsweep_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Test: `orchestrator/internal/api/vexsweep_handlers_test.go`

**Interfaces:**
- Consumes: `Engine.BuildFromSweep` (Task 5), `reporting.GenerateHTML`, `Engine.PDFFromReport` (both already exist and are used identically by `GetCampaignReport`/`GetCampaignPDF`, verified this session at `internal/api/campaign_handlers.go:369-413`).
- Produces: `GET /api/vex/sweeps/{id}/report`, `GET /api/vex/sweeps/{id}/pdf`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/api/vexsweep_handlers_test.go`, mirroring `TestGetVexSweepRuns_ReturnsOnlyTaggedRunsPlusSweepSummary`'s exact fixture pattern (verified this session, same file, lines 321-381):

```go
func TestGetSweepReport_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-report-api')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-sweep-report-api", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}
		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
		}
		resultsJSON, _ := json.Marshal(results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, sweep_id)
			 VALUES ('sr-report-api', '__variant__T1059.001', 'agent-sweep-report-api', 'T1059.001 variants', 'completed', $1, $2)`,
			resultsJSON, sw.ID); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).
			WithVexSweep(store, testVexSweepDispatcher(store)).
			WithReporting(reporting.NewEngine(pool))
		userID := seedUser(t, pool, "sweep-report-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/"+sw.ID+"/report", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.GetSweepReport, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("content-type = %q", ct)
		}
		if !strings.Contains(rec.Body.String(), "T1059.001") {
			t.Fatal("HTML report missing seeded technique T1059.001")
		}
	})
}

func TestGetSweepReport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := vexsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret).
			WithVexSweep(store, testVexSweepDispatcher(store)).
			WithReporting(reporting.NewEngine(pool))
		userID := seedUser(t, pool, "sweep-report-404-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/nope/report", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", "nope")
		rec := callAuthed(h.GetSweepReport, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
```

Add `"github.com/audspect/bas/internal/models"` and `"github.com/audspect/bas/internal/reporting"` and `"strings"` to `vexsweep_handlers_test.go`'s import block if not already present — check first with `grep -n '"strings"\|internal/models\|internal/reporting"' internal/api/vexsweep_handlers_test.go`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetSweepReport -v`
Expected: FAIL — `h.GetSweepReport` undefined (compile error).

- [ ] **Step 3: Implement `GetSweepReport` and `GetSweepPDF`**

Add to `internal/api/vexsweep_handlers.go`, after `GetVexSweepRuns` (which ends at line 191, verified this session):

```go
// GET /api/vex/sweeps/{id}/report
// Combined HTML report for a Full Variant Sweep: one row per dispatched
// technique (Blocked/Detected/Missed/Error rollup) plus an
// encoding-effectiveness breakdown, aggregated from every scenario_runs row
// the sweep dispatched.
func (h *Handler) GetSweepReport(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	rep, err := h.reportingEngine.BuildFromSweep(r.Context(), id, r.URL.Query().Get("filter"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	h.auditLog(r, "report.export", id, map[string]any{"format": "html", "type": "sweep"}, "ok")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporting.GenerateHTML(w, rep, nil); err != nil {
		log.Printf("[api] sweep report html: %v", err)
	}
}

// GET /api/vex/sweeps/{id}/pdf
func (h *Handler) GetSweepPDF(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	rep, err := h.reportingEngine.BuildFromSweep(r.Context(), id, r.URL.Query().Get("filter"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	fname := fmt.Sprintf("bas-sweep-%s-%s.pdf", sanitizeFilename(rep.Agent.Hostname), time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	h.auditLog(r, "report.export", id, map[string]any{"format": "pdf", "type": "sweep"}, "ok")
	if err := h.reportingEngine.PDFFromReport(r.Context(), w, rep, nil, nil); err != nil {
		log.Printf("[api] sweep report pdf: %v", err)
	}
}
```

Check `internal/api/vexsweep_handlers.go`'s existing import block for `"fmt"`, `"time"`, and `"github.com/audspect/bas/internal/reporting"` — add whichever are missing (`campaign_handlers.go` already imports all three for the identical pattern; match its import block).

- [ ] **Step 4: Register the two new routes**

In `internal/api/routes.go`, immediately after the existing sweep routes (verified this session, lines 353-358):

```go
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}/runs", h.GetVexSweepRuns)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}/report", h.GetSweepReport)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}/pdf", h.GetSweepPDF)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps", h.ListVexSweeps)
```

(Insert the two new lines between the existing `/runs` line and the existing `ListVexSweeps` line — same `CanViewVariantRun` permission as every other read-only sweep endpoint.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestGetSweepReport -v`
Expected: PASS (both tests).

- [ ] **Step 6: Run the full API package suite**

Run: `cd orchestrator && go test ./internal/api/... -v -timeout 20m`
Expected: PASS, zero `--- FAIL` lines. This is the largest package in the repo — expect it to take several minutes.

- [ ] **Step 7: Commit**

```bash
git add internal/api/vexsweep_handlers.go internal/api/routes.go internal/api/vexsweep_handlers_test.go
git commit -m "feat(api): add GetSweepReport/GetSweepPDF endpoints"
git push
```

---

## Task 7: Frontend — sweep drilldown report buttons

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET /api/vex/sweeps/{id}/report`, `GET /api/vex/sweeps/{id}/pdf` (Task 6).

- [ ] **Step 1: Add a report-actions container to the sweep drilldown's static markup**

In `wwwroot/index.html`, the sweep drilldown overlay currently reads (verified this session, lines 4719-4730):

```html
<div id="sweep-drilldown-overlay" class="drawer-overlay" onclick="if(event.target===this)closeSweepDrilldown()">
  <div class="drawer" style="width:540px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="sweep-drilldown-title">Full Variant Sweep</h3>
      <button class="drawer-close" onclick="closeSweepDrilldown()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="sweep-drilldown-summary" class="sub2" style="margin-bottom:0.75rem"></div>
      <ul id="sweep-drilldown-list" style="list-style:none;margin:0;padding:0"></ul>
    </div>
  </div>
</div>
```

Change to add a new `sweep-drilldown-actions` container between the summary and the list:

```html
<div id="sweep-drilldown-overlay" class="drawer-overlay" onclick="if(event.target===this)closeSweepDrilldown()">
  <div class="drawer" style="width:540px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="sweep-drilldown-title">Full Variant Sweep</h3>
      <button class="drawer-close" onclick="closeSweepDrilldown()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="sweep-drilldown-summary" class="sub2" style="margin-bottom:0.75rem"></div>
      <div id="sweep-drilldown-actions" style="margin-bottom:0.75rem"></div>
      <ul id="sweep-drilldown-list" style="list-style:none;margin:0;padding:0"></ul>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Populate the actions container in `openSweepDrilldown`**

`openSweepDrilldown` currently reads (verified this session, lines 15621-15658):

```javascript
function openSweepDrilldown(sweepId) {
  document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep';
  document.getElementById('sweep-drilldown-summary').textContent = 'Loading…';
  document.getElementById('sweep-drilldown-list').innerHTML = '';
  document.getElementById('sweep-drilldown-overlay').classList.add('open');
  apicall('/api/vex/sweeps/' + sweepId + '/runs').then(function(payload) {
    var sw = payload.sweep, childRuns = payload.runs || [];
    document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep — ' + (sw.agentId || '');
    document.getElementById('sweep-drilldown-summary').textContent =
      sw.status + ' · ' + childRuns.length + ' technique(s) dispatched';
    document.getElementById('sweep-drilldown-list').innerHTML = childRuns.map(function(r) {
```

Change the loading-state reset and the `.then()` body's opening lines to:

```javascript
function openSweepDrilldown(sweepId) {
  document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep';
  document.getElementById('sweep-drilldown-summary').textContent = 'Loading…';
  document.getElementById('sweep-drilldown-actions').innerHTML = '';
  document.getElementById('sweep-drilldown-list').innerHTML = '';
  document.getElementById('sweep-drilldown-overlay').classList.add('open');
  apicall('/api/vex/sweeps/' + sweepId + '/runs').then(function(payload) {
    var sw = payload.sweep, childRuns = payload.runs || [];
    document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep — ' + (sw.agentId || '');
    document.getElementById('sweep-drilldown-summary').textContent =
      sw.status + ' · ' + childRuns.length + ' technique(s) dispatched';
    document.getElementById('sweep-drilldown-actions').innerHTML =
      '<button class="btn btn-outline btn-sm" onclick="window.open(\'/api/vex/sweeps/' + encodeURIComponent(sweepId) + '/report\',\'_blank\')" title="Open the combined sweep report">&#8599; HTML Report</button> ' +
      '<button class="btn btn-outline btn-sm" onclick="downloadSweepReport(\'' + x(sweepId) + '\')" title="Download the combined sweep report as a file">&#8595; HTML Report</button> ' +
      '<button class="btn btn-outline btn-sm" onclick="window.open(\'/api/vex/sweeps/' + encodeURIComponent(sweepId) + '/pdf\',\'_blank\')" title="Download the combined sweep report as PDF">&#8595; PDF</button>';
    document.getElementById('sweep-drilldown-list').innerHTML = childRuns.map(function(r) {
```

- [ ] **Step 3: Add `downloadSweepReport`, mirroring `downloadCampaignReport` exactly**

`downloadCampaignReport` currently reads (verified this session, lines 16092-16100):

```javascript
// downloadCampaignReport mirrors downloadRunReport for the campaign report.
function downloadCampaignReport(id) {
  showDownloadOptions('Campaign HTML Report', function(filter) {
    var query = filter ? '?filter=' + encodeURIComponent(filter) : '';
    var a = document.createElement('a');
    a.href = '/api/campaigns/' + encodeURIComponent(id) + '/report' + query;
    a.download = 'bas-campaign-report-' + id.substring(0, 8) + '.html';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  });
}
```

Add immediately after it:

```javascript
// downloadSweepReport mirrors downloadCampaignReport for the sweep report.
function downloadSweepReport(id) {
  var a = document.createElement('a');
  a.href = '/api/vex/sweeps/' + encodeURIComponent(id) + '/report';
  a.download = 'bas-sweep-report-' + id.substring(0, 8) + '.html';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}
```

(No filter picker here — unlike campaign reports, a sweep report has no equivalent `filter` query-param use case documented in this spec, so this stays a direct single-click download rather than reusing `showDownloadOptions`.)

- [ ] **Step 4: Verify JS syntax**

Following this session's established method:

```bash
python3 -c "
import re
html = open('wwwroot/index.html', encoding='utf-8').read()
scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', html, re.S)
open(r'<scratchpad-dir>/index_scripts.js', 'w', encoding='utf-8').write('\n'.join(scripts))
"
node --check "<scratchpad-dir>/index_scripts.js"
```

Expected: no output from `node --check` (success). Use the actual scratchpad directory path from this session's environment.

- [ ] **Step 5: Commit**

```bash
git add wwwroot/index.html
git commit -m "feat(ui): add combined report buttons to the sweep drilldown"
git push
```

---

## Task 8: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Build the whole module**

Run: `cd orchestrator && go build ./...`
Expected: succeeds.

- [ ] **Step 2: Run the full orchestrator test suite**

Run: `cd orchestrator && go test ./... -v -timeout 30m`
Expected: PASS, zero `--- FAIL` lines. If Docker resource contention causes spurious container failures (seen earlier this session with many packages' testcontainers running concurrently), rerun with `-p 1` to serialize package execution before concluding anything is actually broken.

- [ ] **Step 3: Confirm the agent module is untouched**

Run: `cd agent && go build ./...`
Expected: succeeds trivially — this plan makes no agent changes; this step only confirms nothing was accidentally touched there.

- [ ] **Step 4: Use the finishing-a-development-branch skill**

Announce: "I'm using the finishing-a-development-branch skill to complete this work." This session has worked directly on `main` throughout (no feature branch), so there is nothing to merge or open a PR for — report the verified-green state and stop.

---

## Self-Review

- **Spec coverage**: Design §1 (architecture) → Tasks 5-6. Design §2 (data model) → Tasks 2-4. Design §3 (error handling) → Task 5 (in-progress banner, zero-result exclusion, encoding-join fail-soft) and Task 6 (404). Design §4 (testing) → every task's own test steps. Frontend wiring (explicitly called out as in-scope in the spec's Section 1 addendum) → Task 7. Out-of-scope items (bounded per-technique buttons, cross-sweep reports, ad-hoc multi-technique grouping) → none of the eight tasks touch any of these.
- **Placeholder scan**: no TBD/TODO. The one explicitly-flagged uncertainty (Task 5 Step 1's test-scaffolding note about confirming `NewEngine`'s exact constructor and the package's shared-pool helper name before writing the test) is a concrete grep-first instruction, not an unresolved placeholder — it exists because this specific package's `TestMain` file wasn't re-read line-by-line during planning, and the instruction says exactly what to check and why.
- **Type consistency**: `SweepTechniqueRow`/`SweepEncodingRow` field names and types are identical everywhere they appear (Task 2's definition, Task 3/4's builders, Task 5's `BuildFromSweep`, Task 6's test assertions). `classifyOutcome`'s four return strings (`"blocked"|"detected"|"missed"|"excluded"`) are used consistently in Tasks 1, 3, and 4 — no task invents a fifth state or a different spelling.

## Execution Handoff

Plan complete and saved to `orchestrator/docs/superpowers/plans/2026-08-24-vex-sweep-combined-report.md`. Per your instruction, proceeding directly to inline execution now.
