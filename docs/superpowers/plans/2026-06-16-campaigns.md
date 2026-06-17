# Campaigns (v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group one scenario fanned out across many agents into a single trackable "campaign" with live, compute-on-read aggregation (progress, result mix, status) and a per-agent breakdown.

**Architecture:** A `campaigns` row + N child `scenario_runs` (linked by a new nullable `campaign_id`). Launch fans out by calling a shared `dispatchRun(...)` per target — the per-agent core extracted from the existing `RunScenario` handler. Rollup is derived on read by pure functions in a new `internal/campaign` package; the run engine is otherwise untouched.

**Tech Stack:** Go (chi router, pgx/pgxpool, PostgreSQL jsonb), vanilla JS dashboard (`wwwroot/index.html`).

**Spec:** `docs/superpowers/specs/2026-06-16-campaigns-design.md`

---

## Key facts (verified against the codebase)

- Run dispatch lives in `RunScenario` (`orchestrator/internal/api/handlers.go:591`): validates → agent-state gate → OS-compat → busy guard → `INSERT INTO scenario_runs (...status='running'...)` → WS dispatch (`h.hub.SendToAgent`). Run terminal statuses: `completed | partial | failed`; non-terminal: `running`. Cancel route exists: `POST /api/scenarios/runs/{runId}/cancel` → `h.CancelRun`.
- `newID()` (`handlers.go:1603`) generates run/campaign IDs. User id: `if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil { ...c.UserID }`.
- `models.Score` (`internal/models/schema.go:97+`) has `PreventionScore float64` etc. `models.SimulationResult` has `Technique.ID`, `Result` (`CheckResult`: pass|fail|blocked|skipped|error), `Events []string`.
- Detection per technique already available: a run's persisted `detection_summary.techniques` (jsonb) + `reporting.classifyDetection(events)`; the kill-chain reuses both. For campaign result-mix we classify a `fail` step as Detected when a same-technique detection exists, else Missed (mirror `reporting.buildKillChain`).
- Routes (`internal/api/routes.go`): outer authed read group registers `GET /api/scenarios/runs` (~line 13 region inside the `r.Group` at line ~71); analyst+ write group at lines 103-115 (`auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst)`) holds `RunScenario`/`CancelRun`.
- DB migrations: append `CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` to the `stmts` slice in `internal/db/postgres.go`.
- Frontend: `showTab(name)` (`wwwroot/index.html`) toggles `tab-<name>` divs + nav `[data-tab]`; helpers `apicall`, `x` (escape), `showToast`, `ago`, `fmtDate`; run results drawer `viewRunResults(run)`; donut helper `donutSVG`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `orchestrator/internal/db/postgres.go` | `campaigns` table + `scenario_runs.campaign_id` | Modify |
| `orchestrator/internal/campaign/campaign.go` | pure `Summary`, `ChildRun`, `Skip`, `DeriveStatus`, `Aggregate` | Create |
| `orchestrator/internal/campaign/campaign_test.go` | unit tests | Create |
| `orchestrator/internal/api/handlers.go` | extract `dispatchRun` + `dispatchOpts`; refactor `RunScenario` | Modify |
| `orchestrator/internal/api/campaign_handlers.go` | create/list/detail/summary/stop handlers | Create |
| `orchestrator/internal/api/routes.go` | register 5 campaign routes | Modify |
| `orchestrator/wwwroot/index.html` | nav + list + detail + launch modal + dashboard widget | Modify |

---

## Part A — Schema

### Task A1: campaigns table + campaign_id column

**Files:** Modify `orchestrator/internal/db/postgres.go`

- [ ] **Step 1: Add the table + column** to the `stmts` slice (after the `scenario_runs` detection columns block):

```go
		`CREATE TABLE IF NOT EXISTS campaigns (
			id            text PRIMARY KEY,
			name          text NOT NULL,
			scenario_id   text NOT NULL,
			scenario_name text NOT NULL DEFAULT '',
			mode          text NOT NULL DEFAULT 'posture',
			subset        jsonb NOT NULL DEFAULT '{}',
			reason        text NOT NULL DEFAULT '',
			targets       jsonb NOT NULL DEFAULT '[]',
			skips         jsonb NOT NULL DEFAULT '[]',
			notes         text NOT NULL DEFAULT '',
			tags          jsonb NOT NULL DEFAULT '[]',
			created_by    text,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			started_at    timestamptz NOT NULL DEFAULT NOW(),
			completed_at  timestamptz,
			stopped_at    timestamptz
		)`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS campaign_id text`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_campaign ON scenario_runs (campaign_id)`,
```

- [ ] **Step 2: Build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(db): campaigns table + scenario_runs.campaign_id

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part B — Pure aggregation (TDD)

### Task B1: campaign types + DeriveStatus

**Files:** Create `orchestrator/internal/campaign/campaign.go`, `orchestrator/internal/campaign/campaign_test.go`

- [ ] **Step 1: Failing test** (`campaign_test.go`):

```go
package campaign

import "testing"

func mk(status string) ChildRun { return ChildRun{Status: status} }

func TestDeriveStatus(t *testing.T) {
	cases := []struct {
		name    string
		runs    []ChildRun
		skips   int
		stopped bool
		want    string
	}{
		{"stopped wins", []ChildRun{mk("running")}, 0, true, "stopped"},
		{"no children all skipped", nil, 3, false, "empty"},
		{"any running", []ChildRun{mk("completed"), mk("running")}, 1, false, "running"},
		{"all completed", []ChildRun{mk("completed"), mk("completed")}, 0, false, "completed"},
		{"all failed", []ChildRun{mk("failed"), mk("failed")}, 0, false, "failed"},
		{"mixed terminal", []ChildRun{mk("completed"), mk("partial")}, 0, false, "partial"},
		{"completed+failed is partial", []ChildRun{mk("completed"), mk("failed")}, 0, false, "partial"},
	}
	for _, c := range cases {
		if got := DeriveStatus(c.runs, c.skips, c.stopped); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run, confirm FAIL:** `cd orchestrator && go test ./internal/campaign/` → undefined `ChildRun`/`DeriveStatus`.

- [ ] **Step 3: Implement** `campaign.go`:

```go
// Package campaign derives a campaign's rollup (status, progress, result mix)
// from its child runs. Pure + server-side; compute-on-read, no stored counters.
package campaign

import "github.com/audspect/bas/internal/models"

// ChildRun is the minimal projection of a child scenario_run needed for rollup.
type ChildRun struct {
	Status  string // running | completed | partial | failed
	Results []models.SimulationResult
	Score   *models.Score
}

// Skip records a target agent that could not be dispatched at launch.
type Skip struct {
	AgentID string `json:"agentId"`
	Reason  string `json:"reason"`
}

func isTerminal(s string) bool { return s == "completed" || s == "partial" || s == "failed" }

// DeriveStatus computes the campaign status. Only `stopped` is sticky (operator
// action); everything else is derived. Empty = zero dispatched children (all
// targets skipped) — "no executable targets", distinct from failed.
func DeriveStatus(runs []ChildRun, skips int, stopped bool) string {
	if stopped {
		return "stopped"
	}
	if len(runs) == 0 {
		return "empty"
	}
	allCompleted, allFailed, anyRunning := true, true, false
	for _, r := range runs {
		if !isTerminal(r.Status) {
			anyRunning = true
		}
		if r.Status != "completed" {
			allCompleted = false
		}
		if r.Status != "failed" {
			allFailed = false
		}
	}
	if anyRunning {
		return "running"
	}
	if allCompleted {
		return "completed"
	}
	if allFailed {
		return "failed"
	}
	return "partial"
}
```

- [ ] **Step 4: Run, confirm PASS:** `cd orchestrator && go test ./internal/campaign/`

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/campaign/campaign.go orchestrator/internal/campaign/campaign_test.go
git commit -m "feat(campaign): ChildRun/Skip types + DeriveStatus

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task B2: Aggregate (progress + result mix)

**Files:** Modify `orchestrator/internal/campaign/campaign.go`, `orchestrator/internal/campaign/campaign_test.go`

- [ ] **Step 1: Failing test** (append to `campaign_test.go`):

```go
import "time" // add to the existing import block if not present

func res(verdict, techID string) models.SimulationResult {
	return models.SimulationResult{
		Technique: models.AttackTechnique{ID: techID},
		Result:    models.CheckResult(verdict),
	}
}

func TestAggregate(t *testing.T) {
	runs := []ChildRun{
		{Status: "completed", Results: []models.SimulationResult{res("pass", "T1"), res("fail", "T2")}},
		{Status: "running", Results: []models.SimulationResult{res("blocked", "T3")}},
	}
	// T2 (fail) is "detected" — caller passes the set of detected technique ids per
	// child via DetectedTechs; here mark T2 detected.
	runs[0].DetectedTechs = map[string]bool{"T2": true}
	skips := []Skip{{AgentID: "a", Reason: "offline"}, {AgentID: "b", Reason: "agent busy"}}
	s := Aggregate(runs, skips)
	if s.Targets != 4 || s.Dispatched != 2 || s.Skipped != 2 {
		t.Fatalf("agent counts wrong: %+v", s)
	}
	if s.Prevented != 2 || s.Detected != 1 || s.Missed != 0 {
		t.Fatalf("mix wrong: %+v", s)
	}
	if s.Progress != 50 { // 1 of 2 children terminal
		t.Fatalf("progress = %d want 50", s.Progress)
	}
	_ = time.Now
}
```

- [ ] **Step 2: Run, confirm FAIL:** `cd orchestrator && go test ./internal/campaign/` → undefined `Aggregate`/`Summary`/`DetectedTechs`.

- [ ] **Step 3: Implement** — add to `campaign.go` (and add the `DetectedTechs` field to `ChildRun`):

Add the field to `ChildRun`:
```go
	DetectedTechs map[string]bool // technique ids whose FAIL was detected (set by the DB loader)
```

Then append:
```go
// Summary is the campaign rollup returned by the API. Agent-level counts
// (Targets = Dispatched + Skipped) reconcile to the target list; step-level
// counts (Prevented/Detected/Missed) are within executed child runs.
type Summary struct {
	Status     string `json:"status"`
	Progress   int    `json:"progress"`
	Targets    int    `json:"targets"`
	Dispatched int    `json:"dispatched"`
	Skipped    int    `json:"skipped"`
	Prevented  int    `json:"prevented"`
	Detected   int    `json:"detected"`
	Missed     int    `json:"missed"`
	Errored    int    `json:"errored"`
}

// Aggregate computes the campaign Summary. Step verdicts: pass|blocked ->
// Prevented; fail -> Detected if the technique is in that child's DetectedTechs,
// else Missed; error|skipped -> Errored (kept out of the mix bar). Status is
// derived via DeriveStatus (stopped handled by the caller passing it in via the
// returned struct — here stopped is always false; callers override).
func Aggregate(runs []ChildRun, skips []Skip) Summary {
	var s Summary
	s.Dispatched = len(runs)
	s.Skipped = len(skips)
	s.Targets = s.Dispatched + s.Skipped
	terminal := 0
	for _, r := range runs {
		if isTerminal(r.Status) {
			terminal++
		}
		for _, res := range r.Results {
			switch res.Result {
			case models.ResultPass, models.ResultBlocked:
				s.Prevented++
			case models.ResultFail:
				if r.DetectedTechs[res.Technique.ID] {
					s.Detected++
				} else {
					s.Missed++
				}
			default: // error | skipped
				s.Errored++
			}
		}
	}
	if s.Dispatched > 0 {
		s.Progress = terminal * 100 / s.Dispatched
	}
	s.Status = DeriveStatus(runs, s.Skipped, false)
	return s
}
```

- [ ] **Step 4: Run, confirm PASS:** `cd orchestrator && go test ./internal/campaign/`
Expected: PASS (Targets 4, Prevented 2, Detected 1, Progress 50).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/campaign/campaign.go orchestrator/internal/campaign/campaign_test.go
git commit -m "feat(campaign): Aggregate (progress + reconciling result mix)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part C — Dispatch refactor

### Task C1: extract `dispatchRun`, refactor `RunScenario`

**Files:** Modify `orchestrator/internal/api/handlers.go`

This is an in-place extraction — move the per-agent core of `RunScenario` into a reusable method WITHOUT behavior change, so both the single-run endpoint and the campaign launcher share it.

- [ ] **Step 1: Add the opts struct + method signature.** Above `RunScenario`, add:

```go
// dispatchOpts carries everything dispatchRun needs for one agent.
type dispatchOpts struct {
	Mode        string
	ConfirmLive bool
	ConfirmLab  bool
	Reason      string
	Techniques  []string
	Abilities   []string
	Steps       []int
	Checks      []string
	CampaignID  string  // "" for ad-hoc single runs
	InitiatedBy *string // user id (nil if unauthenticated)
}

// dispatchRun creates and dispatches ONE run of sc on agentID, applying the
// agent-state gate, OS-compat check, busy guard, run-row insert, and WS dispatch.
// On success returns the new run id. When the agent cannot accept the run it
// returns ("", skipReason, nil); err is non-nil only for genuine failures.
// skipReason is one of: "offline", "agent busy", "agent <state>", "os mismatch".
func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID string, skipReason string, err error) {
	// (body moved from RunScenario — see Step 2)
	return "", "", nil
}
```

- [ ] **Step 2: Move the per-agent core into `dispatchRun`.** Cut everything in `RunScenario` from the **agent-state gate** (`// ── Agent state gate ──`, ~line 642) through the **final dispatch + run-id response** into `dispatchRun`, applying exactly these substitutions:
  - `req.AgentID` → `agentID`; `req.Mode`/`req.Reason`/`req.Techniques`/`req.Abilities`/`req.Steps`/`req.Checks` → `o.Mode`/`o.Reason`/`o.Techniques`/`o.Abilities`/`o.Steps`/`o.Checks`; `r.Context()` → `ctx`.
  - Replace each **agent-unavailable early return** with a skip return (no HTTP):
    - blocked agent state → `return "", "agent " + agentState, nil`
    - busy (non-stale running run) → `return "", "agent busy", nil`
    - live mode on OS mismatch (where it currently hard-blocks) → `return "", "os mismatch", nil`
    - WS `SendToAgent` returned false (not connected) → after marking the run failed as today, `return "", "offline", nil`
  - The run-row INSERT uses `o.InitiatedBy` for `initiated_by` and adds `campaign_id`:
    ```go
    _, err = h.db.Exec(ctx,
      `INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, campaign_id)
       VALUES ($1,$2,$3,$4,'running',$5,NOW(),$6)`,
      runID, sc.ID, agentID, sc.Name, o.InitiatedBy, nullIfEmpty(o.CampaignID))
    ```
  - On success return `runID, "", nil`. On genuine DB/build errors return `"", "", err`.
  - The `osWarning` (posture on mismatched OS) is NOT a skip — keep the run; dispatchRun discards the warning string (single-run path recomputes it in Step 3).
  - Add helper near `newID`:
    ```go
    func nullIfEmpty(s string) any { if s == "" { return nil }; return s }
    ```

- [ ] **Step 3: Make `RunScenario` a thin wrapper.** After its existing request parse + validation (scenario lookup, subset validation — keep these), replace the moved body with:

```go
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}
	runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		InitiatedBy: initiatedBy,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if skip != "" {
		// Preserve prior HTTP semantics for the single-run path.
		code := http.StatusServiceUnavailable
		if skip == "agent busy" {
			code = http.StatusConflict
		} else if strings.HasPrefix(skip, "agent ") {
			code = http.StatusForbidden
		} else if skip == "os mismatch" {
			code = http.StatusForbidden
		}
		jsonError(w, skip, code)
		return
	}
	res := map[string]string{"runId": runID, "status": "dispatched", "mode": mode}
	if osWarning != "" {
		res["osWarning"] = osWarning
	}
	respond(w, res)
```

  Keep the `mode` normalization and `osWarning` computation that already precede the dispatch in `RunScenario` (they belong to the single-run response). Ensure `live` is computed inside `dispatchRun` from `o.Mode`.

- [ ] **Step 4: Build + existing tests**

Run: `cd orchestrator && go build ./... && go test ./internal/api/`
Expected: clean / ok (behavior preserved).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "refactor(api): extract dispatchRun; RunScenario uses it

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part D — Campaign handlers + routes

### Task D1: create campaign (launch fan-out)

**Files:** Create `orchestrator/internal/api/campaign_handlers.go`; modify `orchestrator/internal/api/routes.go`

- [ ] **Step 1: Handler** `campaign_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/auth"
	"github.com/go-chi/chi/v5"
)

// CreateCampaign launches one scenario across many agents. Each reachable agent
// gets a child run (campaign_id set) via dispatchRun; unavailable agents are
// recorded as skips. POST /api/campaigns
func (h *Handler) CreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		ScenarioID string   `json:"scenarioId"`
		AgentIDs   []string `json:"agentIds"`
		Mode       string   `json:"mode"`
		ConfirmLive bool    `json:"confirmLive"`
		ConfirmLab  bool    `json:"confirmLab"`
		Reason     string   `json:"reason"`
		Techniques []string `json:"techniques"`
		Abilities  []string `json:"abilities"`
		Steps      []int    `json:"steps"`
		Checks     []string `json:"checks"`
		Notes      string   `json:"notes"`
		Tags       []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.ScenarioID == "" || len(req.AgentIDs) == 0 {
		jsonError(w, "name, scenarioId and at least one agentId are required", http.StatusBadRequest)
		return
	}
	sc, ok := h.engine.Get(req.ScenarioID)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "posture"
	}
	if mode != "posture" && mode != "telemetry" && mode != "lab" {
		jsonError(w, "invalid mode — use posture | telemetry | lab", http.StatusBadRequest)
		return
	}

	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}

	id := newID()
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
	})
	targets, _ := json.Marshal(req.AgentIDs)
	tags, _ := json.Marshal(req.Tags)
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, subset, reason, targets, notes, tags, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, req.Name, sc.ID, sc.Name, mode, subset, req.Reason, targets, req.Notes, tags, initiatedBy); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy,
	}
	skips := []map[string]string{}
	dispatched := 0
	for _, agentID := range req.AgentIDs {
		_, skip, err := h.dispatchRun(r.Context(), sc, agentID, opts)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if skip != "" {
			skips = append(skips, map[string]string{"agentId": agentID, "reason": skip})
		} else {
			dispatched++
		}
	}
	skipsJSON, _ := json.Marshal(skips)
	_, _ = h.db.Exec(r.Context(), `UPDATE campaigns SET skips=$1 WHERE id=$2`, skipsJSON, id)

	respond(w, map[string]any{"campaignId": id, "dispatched": dispatched, "skipped": len(skips)})
}
```

- [ ] **Step 2: Register route** in `routes.go` inside the analyst+ group (after `/api/scenarios/runs/{runId}/cancel`, line ~107):

```go
			r.Post("/api/campaigns", h.CreateCampaign)
			r.Post("/api/campaigns/{id}/stop", h.StopCampaign)
```

- [ ] **Step 3: Build** (StopCampaign added in D3; to keep the build green, implement D1–D3 before building, or temporarily comment the stop route). Run after D3.

- [ ] **Step 4: Commit** (after D3 builds clean — commit D1+D2+D3 together at end of D3).

### Task D2: list / detail / summary (read + rollup)

**Files:** Modify `orchestrator/internal/api/campaign_handlers.go`

- [ ] **Step 1: Shared loader + handlers.** Append:

```go
import (
	"context"
	"time"

	"github.com/audspect/bas/internal/campaign"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
)

// campaignRow mirrors the stored campaign for JSON output.
type campaignRow struct {
	ID, Name, ScenarioID, ScenarioName, Mode, Reason, Notes, CreatedBy string
	Targets   []string
	Skips     []campaign.Skip
	Tags      []string
	CreatedAt time.Time
	StartedAt time.Time
	Stopped   bool
}

// loadChildren loads child runs of a campaign as campaign.ChildRun, classifying
// each FAIL step as detected/missed using the run's persisted detection_summary.
func (h *Handler) loadChildren(ctx context.Context, campaignID string) ([]campaign.ChildRun, []childRunOut, error) {
	rows, err := h.db.Query(ctx,
		`SELECT id, agent_id, status, results, score, detection_summary
		   FROM scenario_runs WHERE campaign_id = $1 ORDER BY started_at`, campaignID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var cr []campaign.ChildRun
	var out []childRunOut
	for rows.Next() {
		var rid, agentID, status string
		var resultsRaw, scoreRaw, detRaw []byte
		if err := rows.Scan(&rid, &agentID, &status, &resultsRaw, &scoreRaw, &detRaw); err != nil {
			return nil, nil, err
		}
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsRaw, &results)
		var score *models.Score
		if len(scoreRaw) > 0 {
			var s models.Score
			if json.Unmarshal(scoreRaw, &s) == nil {
				score = &s
			}
		}
		det := detectedTechs(detRaw, results)
		cr = append(cr, campaign.ChildRun{Status: status, Results: results, Score: score, DetectedTechs: det})
		prev := 0
		for _, res := range results {
			if res.Result == models.ResultPass || res.Result == models.ResultBlocked {
				prev++
			}
		}
		var prevPct float64
		if score != nil {
			prevPct = score.PreventionScore
		}
		out = append(out, childRunOut{RunID: rid, AgentID: agentID, Status: status, PreventionScore: prevPct, Steps: len(results)})
	}
	return cr, out, nil
}

type childRunOut struct {
	RunID           string  `json:"runId"`
	AgentID         string  `json:"agentId"`
	Status          string  `json:"status"`
	PreventionScore float64 `json:"preventionScore"`
	Steps           int     `json:"steps"`
}

// detectedTechs returns the set of technique ids whose FAIL was detected, from
// the run's persisted detection_summary.techniques, falling back to the coarse
// per-step classifier when no sweep was submitted.
func detectedTechs(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if reporting.ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
}

func (h *Handler) loadCampaign(ctx context.Context, id string) (*campaignRow, error) {
	var c campaignRow
	var targetsRaw, skipsRaw, tagsRaw []byte
	var stoppedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT id, name, scenario_id, scenario_name, mode, reason, notes,
		        COALESCE(created_by,''), targets, skips, tags, created_at, started_at, stopped_at
		   FROM campaigns WHERE id=$1`, id,
	).Scan(&c.ID, &c.Name, &c.ScenarioID, &c.ScenarioName, &c.Mode, &c.Reason, &c.Notes,
		&c.CreatedBy, &targetsRaw, &skipsRaw, &tagsRaw, &c.CreatedAt, &c.StartedAt, &stoppedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsRaw, &c.Targets)
	_ = json.Unmarshal(skipsRaw, &c.Skips)
	_ = json.Unmarshal(tagsRaw, &c.Tags)
	c.Stopped = stoppedAt != nil
	return &c, nil
}

// summaryFor builds the rollup for a campaign and lazily stamps completed_at.
func (h *Handler) summaryFor(ctx context.Context, c *campaignRow) (campaign.Summary, []childRunOut, error) {
	children, out, err := h.loadChildren(ctx, c.ID)
	if err != nil {
		return campaign.Summary{}, nil, err
	}
	s := campaign.Aggregate(children, c.Skips)
	s.Status = campaign.DeriveStatus(children, len(c.Skips), c.Stopped)
	if (s.Status == "completed" || s.Status == "partial" || s.Status == "failed") && !c.Stopped {
		_, _ = h.db.Exec(ctx, `UPDATE campaigns SET completed_at=NOW() WHERE id=$1 AND completed_at IS NULL`, c.ID)
	}
	return s, out, nil
}

// GET /api/campaigns
func (h *Handler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT id FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []map[string]any{}
	for _, id := range ids {
		c, err := h.loadCampaign(r.Context(), id)
		if err != nil {
			continue
		}
		s, _, _ := h.summaryFor(r.Context(), c)
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioName": c.ScenarioName, "mode": c.Mode,
			"startedAt": c.StartedAt, "summary": s,
		})
	}
	respond(w, out)
}

// GET /api/campaigns/{id}/summary
func (h *Handler) CampaignSummary(w http.ResponseWriter, r *http.Request) {
	c, err := h.loadCampaign(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}
	s, _, err := h.summaryFor(r.Context(), c)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, s)
}

// GET /api/campaigns/{id}
func (h *Handler) GetCampaign(w http.ResponseWriter, r *http.Request) {
	c, err := h.loadCampaign(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}
	s, children, err := h.summaryFor(r.Context(), c)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
		"mode": c.Mode, "reason": c.Reason, "notes": c.Notes, "tags": c.Tags,
		"targets": c.Targets, "skips": c.Skips, "createdBy": c.CreatedBy,
		"startedAt": c.StartedAt, "summary": s, "runs": children,
	})
}
```

- [ ] **Step 2: Export the classifier.** In `orchestrator/internal/reporting/engine.go`, add (so the campaign loader can reuse it without duplicating the event-token logic):

```go
// ClassifyDetectionStatus returns the coarse detection status ("Detected" |
// "Logged" | "None") for a step's events. Exported for the campaign rollup.
func ClassifyDetectionStatus(events []string) string { return classifyDetection(events).Status }
```

- [ ] **Step 3: Register read routes** in `routes.go` in the outer authed group (after `GET /api/scenarios/runs`, ~line 13):

```go
		r.Get("/api/campaigns", h.ListCampaigns)
		r.Get("/api/campaigns/{id}", h.GetCampaign)
		r.Get("/api/campaigns/{id}/summary", h.CampaignSummary)
```

### Task D3: stop campaign + build/commit

**Files:** Modify `orchestrator/internal/api/campaign_handlers.go`

- [ ] **Step 1: Stop handler.** Append:

```go
// POST /api/campaigns/{id}/stop — marks stopped and cancels running children.
func (h *Handler) StopCampaign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `UPDATE campaigns SET stopped_at=NOW() WHERE id=$1 AND stopped_at IS NULL`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		// already stopped or not found — verify existence
		if _, e := h.loadCampaign(r.Context(), id); e != nil {
			jsonError(w, "campaign not found", http.StatusNotFound)
			return
		}
	}
	// Cancel still-running children (best-effort, mirrors CancelRun's effect).
	rows, _ := h.db.Query(r.Context(),
		`SELECT id FROM scenario_runs WHERE campaign_id=$1 AND status='running'`, id)
	var runIDs []string
	for rows != nil && rows.Next() {
		var rid string
		if rows.Scan(&rid) == nil {
			runIDs = append(runIDs, rid)
		}
	}
	if rows != nil {
		rows.Close()
	}
	for _, rid := range runIDs {
		_, _ = h.db.Exec(r.Context(),
			`UPDATE scenario_runs SET status='partial', completed_at=NOW() WHERE id=$1 AND status='running'`, rid)
	}
	respond(w, map[string]any{"stopped": true, "cancelled": len(runIDs)})
}
```

  Note: if `CancelRun` also signals the agent over WS, prefer calling that shared logic instead of the inline UPDATE — check `h.CancelRun`'s body and reuse its agent-signal helper if one exists; the inline UPDATE is the minimum (marks the run partial like the staleness monitor does).

- [ ] **Step 2: Build + tests**

Run: `cd orchestrator && go build ./... && go test ./internal/campaign/ ./internal/api/ ./internal/reporting/`
Expected: clean / ok.

- [ ] **Step 3: Commit** (D1+D2+D3 together)

```bash
git add orchestrator/internal/api/campaign_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/reporting/engine.go
git commit -m "feat(api): campaign create/list/detail/summary/stop

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part E — Frontend (`orchestrator/wwwroot/index.html`)

### Task E1: Campaigns nav + list view

**Files:** Modify `orchestrator/wwwroot/index.html`

- [ ] **Step 1: Add nav item** in the Operations group (after the Live Runs `nav-item`, ~line 707):

```html
        <div class="nav-item" data-tab="campaigns" onclick="showTab('campaigns')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 13V3M2 13h12M5 11V7M8.5 11V5M12 11V8"/>
          </svg>
          Campaigns
        </div>
```

- [ ] **Step 2: Register the tab** in `showTab` (`['dashboard','agents','scenarios','runs','users','compliance','settings']` array) — add `'campaigns'`, and add a loader call:

```js
  if (name === 'campaigns') loadCampaigns();
```

  Also add a `TAB_TITLES` entry `campaigns: 'Campaigns'` (find the `TAB_TITLES` map).

- [ ] **Step 3: Add the tab markup** after the `tab-runs` view div (search `id="tab-runs"`, add a sibling):

```html
      <div id="tab-campaigns" style="display:none">
        <div class="sec-hdr">
          <h2>Campaigns <span id="campaign-cnt" class="cnt">0</span></h2>
          <div>
            <button class="btn btn-outline btn-sm" onclick="loadCampaigns()">Refresh</button>
            <button class="btn btn-primary btn-sm" id="campaign-new-btn" onclick="openCampaignLaunch()">&#9654; New campaign</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Campaign</th><th>Scenario</th><th>Targets</th><th>Status</th><th>Result mix</th><th>Started</th></tr></thead>
            <tbody id="campaigns-body"><tr><td colspan="6" class="empty">No campaigns yet.</td></tr></tbody>
          </table>
        </div>
      </div>
```

- [ ] **Step 4: Add list JS** (near `loadRuns`):

```js
function campaignMixBar(s) {
  var seg = function(v, c) { return v > 0 ? '<i style="flex:' + v + ';background:' + c + '"></i>' : ''; };
  var total = s.prevented + s.detected + s.missed;
  if (!total) return '<span class="tiny muted">—</span>';
  return '<div class="seg-bar" title="Prevented ' + s.prevented + ' · Detected ' + s.detected + ' · Missed ' + s.missed +
    (s.skipped ? ' · Skipped ' + s.skipped + ' agents' : '') + '" style="display:flex;height:8px;border-radius:5px;overflow:hidden;background:var(--elevated);min-width:120px">' +
    seg(s.prevented, 'var(--success)') + seg(s.detected, 'var(--warning)') + seg(s.missed, 'var(--danger)') + '</div>';
}
function loadCampaigns() {
  apicall('/api/campaigns').then(function(list) {
    document.getElementById('campaign-cnt').textContent = list.length;
    var tb = document.getElementById('campaigns-body');
    if (!list.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">No campaigns yet.</td></tr>'; return; }
    tb.innerHTML = list.map(function(c) {
      var s = c.summary || {};
      var prog = (s.status === 'running') ? ' <span class="tiny muted">' + s.progress + '%</span>' : '';
      return '<tr style="cursor:pointer" onclick="openCampaignDetail(\'' + x(c.id) + '\')">' +
        '<td class="cell-main">' + x(c.name) + '</td>' +
        '<td class="tiny muted">' + x(c.scenarioName) + '</td>' +
        '<td class="tiny">' + (s.dispatched || 0) + '/' + (s.targets || 0) + (s.skipped ? ' <span class="tiny muted">(' + s.skipped + ' skipped)</span>' : '') + '</td>' +
        '<td><span class="sbadge s-' + x(s.status || 'running') + '">' + x(s.status || '—') + '</span>' + prog + '</td>' +
        '<td>' + campaignMixBar(s) + '</td>' +
        '<td class="tiny muted">' + fmtDate(c.startedAt) + '</td></tr>';
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 5: Add status-badge CSS** for the new campaign statuses (near the `.s-*` rules) so `empty`/`stopped` render:

```css
.s-empty   { background: rgba(154,169,188,0.08); color: var(--muted); border: 1px solid rgba(154,169,188,0.14); }
.s-empty::before { background: var(--muted); }
.s-stopped { background: rgba(210,153,34,0.1); color: #e8b84b; border: 1px solid rgba(210,153,34,0.2); }
.s-stopped::before { background: #e8b84b; }
```
  (`running`/`completed`/`partial`/`failed` badges already exist.)

- [ ] **Step 6: Validate + commit**

Run: `node -e "const fs=require('fs');const h=fs.readFileSync('orchestrator/wwwroot/index.html','utf8');const m=h.match(/<script>([\s\S]*)<\/script>/);new Function(m[1]);console.log('OK');"`
Expected: `OK`.

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): Campaigns nav + list view

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task E2: Campaign detail (drawer reusing run results)

**Files:** Modify `orchestrator/wwwroot/index.html`

- [ ] **Step 1: Detail JS** — opens the existing results drawer overlay (`results-overlay`) reused for campaigns:

```js
function openCampaignDetail(id) {
  apicall('/api/campaigns/' + encodeURIComponent(id)).then(function(c) {
    var s = c.summary || {};
    document.getElementById('results-title').textContent = c.name + ' — Campaign';
    var tiles = function(lbl, val, col) {
      return '<div style="background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius-lg);padding:0.6rem 0.75rem">' +
        '<div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)">' + lbl + '</div>' +
        '<div style="font-size:1.3rem;font-weight:700;font-family:var(--font-display);color:' + (col || 'var(--text)') + '">' + val + '</div></div>';
    };
    var head = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.5rem;margin-bottom:0.9rem">' +
      tiles('Status', x(s.status || '—')) +
      tiles('Progress', (s.progress || 0) + '%', 'var(--accent)') +
      tiles('Dispatched', (s.dispatched || 0) + '/' + (s.targets || 0)) +
      tiles('Skipped', s.skipped || 0, s.skipped ? 'var(--warning)' : 'var(--muted)') + '</div>';
    var mix = '<div style="margin-bottom:0.9rem">' + campaignMixBar(s) + '</div>';
    var runs = (c.runs || []).map(function(rn) {
      var col = rn.status === 'completed' ? 'var(--success)' : rn.status === 'failed' ? 'var(--danger)' : 'var(--muted)';
      return '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.4rem 0;border-bottom:1px solid var(--border)">' +
        '<span class="sbadge s-' + x(rn.status) + '">' + x(rn.status) + '</span>' +
        '<code style="font-size:0.72rem">' + x(rn.agentId) + '</code>' +
        '<span style="margin-left:auto;font-weight:600;color:' + col + '">' + (rn.preventionScore ? Math.round(rn.preventionScore) + '%' : '—') + '</span>' +
        '<button class="btn btn-outline btn-sm" onclick="openRunFromCampaign(\'' + x(rn.runId) + '\')">Results</button></div>';
    }).join('') || '<div class="empty">No child runs dispatched.</div>';
    var skips = (c.skips || []).length
      ? '<div style="margin-top:0.9rem"><div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:0.4rem">Skipped targets</div>' +
        c.skips.map(function(k) { return '<div style="display:flex;gap:0.6rem;padding:0.3rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><code>' + x(k.agentId) + '</code><span class="tiny muted" style="margin-left:auto">' + x(k.reason) + '</span></div>'; }).join('') + '</div>'
      : '';
    var actions = (s.status === 'running')
      ? '<button class="btn btn-outline-red btn-sm" onclick="stopCampaign(\'' + x(c.id) + '\')">&#9632; Stop campaign</button>' : '';
    document.getElementById('results-export').innerHTML = actions;
    document.getElementById('results-body').innerHTML = head + mix +
      '<div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin:0.5rem 0">Per-agent runs</div>' +
      runs + skips;
    document.getElementById('results-overlay').classList.add('open');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function openRunFromCampaign(runId) {
  apicall('/api/scenarios/runs').then(function(runs) {
    var r = (runs || []).find(function(x) { return x.id === runId; });
    if (r) viewRunResults(r); else showToast('Run not found', 'err');
  });
}
function stopCampaign(id) {
  if (!confirm('Stop this campaign? Running child runs will be marked partial.')) return;
  apicall('/api/campaigns/' + encodeURIComponent(id) + '/stop', { method: 'POST' })
    .then(function() { showToast('Campaign stopped', 'ok'); openCampaignDetail(id); loadCampaigns(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 2: Validate + commit**

Run: `node -e "...new Function(...)..."` (same as E1 Step 6). Expected `OK`.

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): campaign detail drawer + stop

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task E3: Launch Campaign modal

**Files:** Modify `orchestrator/wwwroot/index.html`

- [ ] **Step 1: Modal markup** after the run-overlay modal (search `id="run-overlay"`, add a sibling overlay):

```html
<div id="campaign-overlay" class="overlay">
  <div class="modal" style="min-width:480px">
    <h3>New Campaign</h3>
    <label class="modal-lbl">Name</label>
    <input id="cmp-name" type="text" placeholder="e.g. Q2 Ransomware Readiness" style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-family:inherit">
    <label class="modal-lbl">Scenario</label>
    <select id="cmp-scenario" onchange="renderCampaignTargets()"></select>
    <label class="modal-lbl">Execution mode</label>
    <select id="cmp-mode">
      <option value="posture">Posture — read-only, safe on any host</option>
      <option value="telemetry">Telemetry — identity-safe (approved windows)</option>
      <option value="lab">Lab — full-fidelity (isolated range only)</option>
    </select>
    <label class="modal-lbl">Targets <span class="tiny muted" id="cmp-target-cnt">(0 selected)</span></label>
    <div style="display:flex;gap:0.5rem;margin-bottom:0.4rem">
      <select id="cmp-filter-os" onchange="renderCampaignTargets()" style="flex:1"><option value="">All OS</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="darwin">macOS</option></select>
      <select id="cmp-filter-env" onchange="renderCampaignTargets()" style="flex:1"><option value="">All environments</option></select>
      <button class="btn btn-outline btn-sm" onclick="cmpSelectAllFiltered()">Select all</button>
    </div>
    <div id="cmp-targets" style="max-height:200px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);padding:0.4rem"></div>
    <label class="modal-lbl">Notes (optional)</label>
    <input id="cmp-notes" type="text" placeholder="optional" style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-family:inherit">
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeCampaignLaunch()">Cancel</button>
      <button class="btn btn-primary btn-sm" onclick="submitCampaign()">&#9654; Launch</button>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Modal JS:**

```js
function openCampaignLaunch() {
  if (!scenarios.length) { showToast('Scenarios not loaded yet', 'err'); return; }
  if (!agents.length) { showToast('No agents registered yet', 'err'); return; }
  document.getElementById('cmp-name').value = '';
  document.getElementById('cmp-notes').value = '';
  document.getElementById('cmp-scenario').innerHTML = scenarios.map(function(s) {
    return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>';
  }).join('');
  document.getElementById('cmp-mode').value = 'posture';
  var envs = {};
  agents.forEach(function(a) { if (a.envLabel) envs[a.envLabel] = true; });
  document.getElementById('cmp-filter-env').innerHTML = '<option value="">All environments</option>' +
    Object.keys(envs).map(function(e) { return '<option value="' + x(e) + '">' + x(e) + '</option>'; }).join('');
  _cmpSel = {};
  renderCampaignTargets();
  document.getElementById('campaign-overlay').classList.add('open');
}
function closeCampaignLaunch() { document.getElementById('campaign-overlay').classList.remove('open'); }
var _cmpSel = {};
function cmpAgentOS(a) { var o = (a.osVersion || '').toLowerCase(); return o.indexOf('windows') >= 0 ? 'windows' : (o.indexOf('darwin') >= 0 || o.indexOf('macos') >= 0) ? 'darwin' : 'linux'; }
function cmpFiltered() {
  var os = document.getElementById('cmp-filter-os').value, env = document.getElementById('cmp-filter-env').value;
  return agents.filter(function(a) {
    if (a.status === 'offline') return false;
    if (os && cmpAgentOS(a) !== os) return false;
    if (env && a.envLabel !== env) return false;
    return true;
  });
}
function renderCampaignTargets() {
  var list = cmpFiltered();
  document.getElementById('cmp-targets').innerHTML = list.length ? list.map(function(a) {
    return '<label style="display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0.3rem;cursor:pointer">' +
      '<input type="checkbox" ' + (_cmpSel[a.agentId] ? 'checked' : '') + ' onchange="_cmpSel[\'' + x(a.agentId) + '\']=this.checked;cmpUpdateCount()">' +
      '<code style="font-size:0.72rem">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' · ' + cmpAgentOS(a) + '</span></label>';
  }).join('') : '<div class="empty tiny">No online agents match the filter.</div>';
  cmpUpdateCount();
}
function cmpSelectAllFiltered() { cmpFiltered().forEach(function(a) { _cmpSel[a.agentId] = true; }); renderCampaignTargets(); }
function cmpUpdateCount() {
  var n = Object.keys(_cmpSel).filter(function(k) { return _cmpSel[k]; }).length;
  document.getElementById('cmp-target-cnt').textContent = '(' + n + ' selected)';
}
function submitCampaign() {
  var name = document.getElementById('cmp-name').value.trim();
  var agentIds = Object.keys(_cmpSel).filter(function(k) { return _cmpSel[k]; });
  if (!name) { showToast('Campaign name required', 'err'); return; }
  if (!agentIds.length) { showToast('Select at least one target agent', 'err'); return; }
  var mode = document.getElementById('cmp-mode').value;
  if (mode !== 'posture' && !confirm(mode.toUpperCase() + ' mode runs real techniques and will generate alerts. Continue?')) return;
  var body = {
    name: name, scenarioId: document.getElementById('cmp-scenario').value, agentIds: agentIds,
    mode: mode, confirmLive: mode !== 'posture', confirmLab: mode === 'lab',
    notes: document.getElementById('cmp-notes').value.trim()
  };
  apicall('/api/campaigns', { method: 'POST', body: JSON.stringify(body) }).then(function(res) {
    if (res && res.error) { showToast('Launch failed: ' + res.error, 'err'); return; }
    closeCampaignLaunch();
    showToast('Campaign launched — ' + res.dispatched + ' dispatched, ' + res.skipped + ' skipped', 'ok');
    showTab('campaigns'); loadCampaigns();
  }).catch(function(e) { showToast('Launch failed: ' + e.message, 'err'); });
}
```

- [ ] **Step 3: Validate + commit**

Run: `node -e "...new Function(...)..."`. Expected `OK`.

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): Launch Campaign modal (multi-agent fan-out)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task E4: Dashboard Live/Recent Campaigns widget

**Files:** Modify `orchestrator/wwwroot/index.html`

- [ ] **Step 1: Panel markup** — add a dash-panel inside `tab-dashboard` (after the existing `dash-grid`, before the ATT&CK panel):

```html
        <div class="dash-panel" style="margin-bottom:1.25rem">
          <div class="dash-panel-hdr">Recent Campaigns</div>
          <div class="dash-panel-body flush" id="dash-campaigns"><div class="empty" style="padding:1.25rem">No campaigns yet.</div></div>
        </div>
```

- [ ] **Step 2: Populate in `loadDashboard`** — add a third fetch and render (extend the existing `Promise.all` or add a separate call). Append near the end of `loadDashboard`'s `.then`:

```js
    apicall('/api/campaigns').then(function(cs) {
      var el = document.getElementById('dash-campaigns');
      if (!el) return;
      var recent = (cs || []).slice(0, 5);
      if (!recent.length) { el.innerHTML = '<div class="empty" style="padding:1.25rem">No campaigns yet.</div>'; return; }
      el.innerHTML = recent.map(function(c) {
        var s = c.summary || {};
        return '<div class="dash-run-row" style="cursor:pointer" onclick="openCampaignDetail(\'' + x(c.id) + '\')">' +
          '<span class="sbadge s-' + x(s.status || 'running') + '">' + x(s.status || '—') + '</span>' +
          '<span class="dash-run-name">' + x(c.name) + '</span>' +
          '<span class="tiny muted">' + (s.dispatched || 0) + '/' + (s.targets || 0) + ' agents</span>' +
          '<span style="font-size:0.8rem;font-weight:600;flex-shrink:0">' + (s.progress || 0) + '%</span></div>';
      }).join('');
    }).catch(function() {});
```

- [ ] **Step 3: Validate + commit**

Run: `node -e "...new Function(...)..."`. Expected `OK`.

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): Recent Campaigns widget

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** campaigns table + campaign_id ✓ (A1). Pure DeriveStatus/Aggregate w/ empty status + reconciling Skipped ✓ (B1,B2). dispatchRun (runID,skipReason,error) + RunScenario refactor ✓ (C1). Create/launch fan-out + skips ✓ (D1). list/detail/summary + lazy completed_at + compute-on-read ✓ (D2). Stop ✓ (D3). Nav/list ✓ (E1), detail+stop ✓ (E2), launch modal w/ env+OS filters ✓ (E3), dashboard widget ✓ (E4). Scenario-name snapshot ✓ (A1/D1). Reuse run drawer ✓ (E2). Non-goals (scheduling/suites/groups/retry/jira/tag-filter) excluded ✓.

**Placeholder scan:** no TBD/TODO. C1 Step 2 is an enumerated extraction recipe against named anchors with exact substitutions + the new INSERT and skip-return lines given in full (the moved code is existing, byte-for-byte, so it is not re-pasted — this is intentional, not a placeholder).

**Type consistency:** `ChildRun{Status,Results,Score,DetectedTechs}` defined B1/B2, populated D2. `Skip{AgentID,Reason}` B1, used D1(map form persisted)/D2. `Summary` fields B2 ↔ rendered E1/E2/E4. `dispatchOpts`/`dispatchRun` signature C1 ↔ called D1. `ClassifyDetectionStatus` added D2-Step2, used D2 loader. Routes: read group (D2-Step3) + write group (D1-Step2). `_cmpSel`, `campaignMixBar`, `openCampaignDetail` shared across E1–E4 consistently.

**Risk notes:**
- C1 is the only refactor of working code — gated by `go test ./internal/api/` + unchanged single-run responses. If `CancelRun` signals the agent over WS, reuse that in D3 instead of the inline UPDATE (noted in D3-Step1).
- `detectedTechs` falls back to `ClassifyDetectionStatus` so result-mix Detected works even before any detection sweep is submitted.
