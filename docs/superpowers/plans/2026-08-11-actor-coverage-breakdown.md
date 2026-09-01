# Actor Coverage Breakdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-technique coverage-breakdown table to the Threat Prioritization actor detail view — for each technique in an actor's roster, show what content exists (simulation/detection/compliance) and what real outcomes (prevention/detection verdicts) have been recorded, using data `internal/threatpriority` already computes.

**Architecture:** A pure function (`buildTechniqueCoverage`) in `internal/api/threatpriority_handlers.go` combines the coverage indexes and verdict maps `ThreatPriorityActorDetail` already builds (or can call, already-exported) into one `[]TechniqueCoverage` slice, added to the existing JSON response. The frontend renders it as a new table section in the existing actor-detail drawer — no new tab, no new endpoint, no new engine.

**Tech Stack:** Go (existing `internal/api`/`internal/threatpriority`/`internal/coverage`/`internal/reporting/attackdata` packages), vanilla JS in `orchestrator/wwwroot/index.html`.

## Global Constraints

- No new fleet-wide dashboard tile — actor detail view only.
- No new scoring engine or composite factor — pure read-path addition, `internal/threatpriority`'s scoring/weights/composite untouched.
- `UncoveredTechniques` stays exactly as-is (backward compatibility) — `TechniqueCoverage` is additive on the same response.
- Never use the word "exposure" in any new type/field/UI-label name in this project (naming collision with `internal/analytics`'s existing, unrelated "exposure" concepts — see spec).

---

### Task 1: Backend — `TechniqueCoverage` + `buildTechniqueCoverage` + handler wiring

**Files:**
- Modify: `orchestrator/internal/api/threatpriority_handlers.go` (currently 75 lines, shown in full below)
- Modify: `orchestrator/internal/api/threatpriority_handlers_test.go` (currently 78 lines)

**Interfaces:**
- Consumes: `coverage.BuildSimulationIndex`/`BuildProfileIndex`/`BuildComplianceIndex` (`internal/coverage/matrix.go`, unchanged, already called by this handler). `threatpriority.LoadPreventionVerdicts(ctx, pool *pgxpool.Pool) (map[string]VerdictEntry, error)` and `LoadValidationVerdicts` (same signature) — both already exported (`internal/threatpriority/engine.go:82,115`), not previously called from this file. `threatpriority.VerdictEntry{Verdict string; At time.Time}` (`internal/threatpriority/models.go:26`). `attackdata.Lookup(id string) *attackdata.Enrichment` and `Enrichment.Name string` (`internal/reporting/attackdata/attackdata.go`, unchanged). `Handler.db *pgxpool.Pool` (`internal/api/handlers.go:68`, the field this handler already has access to as `h.db`, not previously used by this handler).
- Produces: `type TechniqueCoverage struct` (JSON shape below) and `func buildTechniqueCoverage(techIDs []string, sim, detect, compliant map[string]bool, prevention, validation map[string]threatpriority.VerdictEntry) []TechniqueCoverage` — both consumed by Task 2 (frontend reads the `technique Coverage` JSON field; no Go-level consumer beyond this file).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/threatpriority_handlers_test.go` (new test functions; existing imports — `net/http/httptest`, `strings`, `testing`, `pgxpool`, `scenario`, `threatpriority`, `ws` — already cover everything these need):

```go
func TestBuildTechniqueCoverage_NoContentIsGap(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{},
	)
	if len(out) != 1 {
		t.Fatalf("want 1 row, got %d", len(out))
	}
	if out[0].Status != "gap-no-content" {
		t.Errorf("Status = %q, want gap-no-content", out[0].Status)
	}
}

func TestBuildTechniqueCoverage_ContentNoVerdictsIsUntested(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{},
	)
	if out[0].Status != "untested" {
		t.Errorf("Status = %q, want untested", out[0].Status)
	}
	if !out[0].HasSimulation {
		t.Error("HasSimulation = false, want true")
	}
}

func TestBuildTechniqueCoverage_PreventionVerdictOnly(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "pass"}}, map[string]threatpriority.VerdictEntry{},
	)
	if out[0].Status != "has-outcomes" {
		t.Errorf("Status = %q, want has-outcomes", out[0].Status)
	}
	if out[0].PreventionVerdict != "pass" {
		t.Errorf("PreventionVerdict = %q, want pass", out[0].PreventionVerdict)
	}
	if out[0].DetectionVerdict != "" {
		t.Errorf("DetectionVerdict = %q, want empty", out[0].DetectionVerdict)
	}
}

func TestBuildTechniqueCoverage_DetectionVerdictOnly(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "Detected"}},
	)
	if out[0].Status != "has-outcomes" {
		t.Errorf("Status = %q, want has-outcomes", out[0].Status)
	}
	if out[0].DetectionVerdict != "Detected" {
		t.Errorf("DetectionVerdict = %q, want Detected", out[0].DetectionVerdict)
	}
	if out[0].PreventionVerdict != "" {
		t.Errorf("PreventionVerdict = %q, want empty", out[0].PreventionVerdict)
	}
}

func TestBuildTechniqueCoverage_BothVerdicts(t *testing.T) {
	out := buildTechniqueCoverage(
		[]string{"T1059.001"},
		map[string]bool{"T1059.001": true}, map[string]bool{}, map[string]bool{},
		map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "fail"}},
		map[string]threatpriority.VerdictEntry{"T1059.001": {Verdict: "NotDetected"}},
	)
	if out[0].Status != "has-outcomes" {
		t.Errorf("Status = %q, want has-outcomes", out[0].Status)
	}
	if out[0].PreventionVerdict != "fail" || out[0].DetectionVerdict != "NotDetected" {
		t.Errorf("got Prevention=%q Detection=%q, want fail/NotDetected", out[0].PreventionVerdict, out[0].DetectionVerdict)
	}
}
```

Also extend the existing `TestThreatPriorityActorDetail_UnknownActor_ReturnsEmptyButOK` (regression + wiring proof) — replace its body with:

```go
func TestThreatPriorityActorDetail_UnknownActor_ReturnsEmptyButOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/Nonexistent-Actor", nil)
		req = withURLParams(req, map[string]string{"name": "Nonexistent-Actor"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"techniqueCoverage":[]`) {
			t.Errorf("body should contain an empty techniqueCoverage array, got: %s", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"uncoveredTechniques":[]`) {
			t.Errorf("body should still contain an empty uncoveredTechniques array (unchanged), got: %s", w.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestBuildTechniqueCoverage|TestThreatPriorityActorDetail_UnknownActor' -v`
Expected: FAIL to compile — `buildTechniqueCoverage` and `TechniqueCoverage` don't exist yet, and the extended assertion looks for a JSON field (`techniqueCoverage`) the current response doesn't emit.

- [ ] **Step 3: Implement `TechniqueCoverage`, `buildTechniqueCoverage`, and wire them into the handler**

Replace the full content of `orchestrator/internal/api/threatpriority_handlers.go` with:

```go
package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/threatpriority"
)

// GET /api/threat-priority/actors
// Ranked list of every actor with a threat_actor_profiles row, sorted Score
// desc then ActorName asc (same determinism convention as
// internal/recommend's sort). Distinct from GET /api/coverage/matrix
// (technique-level content existence) and GET /api/recommend/simulations
// (technique-level ranking) -- this is the actor-level view.
func (h *Handler) ThreatPriorityActors(w http.ResponseWriter, r *http.Request) {
	if h.threatPriorityEngine == nil {
		respond(w, []threatpriority.ActorPriority{})
		return
	}
	scores, err := h.threatPriorityEngine.ScoreAll(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, scores)
}

// TechniqueCoverage is one technique's coverage-breakdown row for a given
// actor -- what content exists for it, and what real outcomes (if any)
// have been recorded. See
// docs/superpowers/specs/2026-08-11-actor-coverage-breakdown-design.md.
// Deliberately never called "exposure" anywhere in this type or its
// fields -- that word already means two unrelated things elsewhere in this
// codebase (internal/analytics.FleetExposure, internal/predict.ExposureWindows).
type TechniqueCoverage struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName,omitempty"`
	HasSimulation bool   `json:"hasSimulation"`
	HasDetection  bool   `json:"hasDetection"`
	HasCompliance bool   `json:"hasCompliance"`
	// PreventionVerdict / DetectionVerdict are independent -- a control
	// blocking an attack (prevention, from scenario_runs) and a stack
	// alerting on it (detection, from verification_history) answer
	// different questions. A technique can have one without the other.
	PreventionVerdict string `json:"preventionVerdict,omitempty"`
	DetectionVerdict  string `json:"detectionVerdict,omitempty"`
	// Status is derived, in priority order: "gap-no-content" (no
	// simulation/detection/compliance content at all) > "untested" (has
	// content, but neither verdict has ever been recorded) > "has-outcomes"
	// (has content and at least one verdict exists).
	Status string `json:"status"`
}

// buildTechniqueCoverage computes the per-technique coverage-breakdown row
// for each of an actor's techniques. Pure function -- sim/detect/compliant
// and prevention/validation are all already computed by the caller (the
// same indexes UncoveredTechniques already relies on, plus the two
// exported verdict loaders internal/correlation already uses this way).
// Coverage indexes are keyed by raw technique-ID casing (matching
// UncoveredTechniques' existing lookups); verdict maps are keyed uppercase
// (matching threatpriority.Engine.scoreActor's own established contract),
// so verdict lookups uppercase the id and coverage lookups don't.
func buildTechniqueCoverage(
	techIDs []string,
	sim, detect, compliant map[string]bool,
	prevention, validation map[string]threatpriority.VerdictEntry,
) []TechniqueCoverage {
	out := make([]TechniqueCoverage, 0, len(techIDs))
	for _, id := range techIDs {
		tc := TechniqueCoverage{
			TechniqueID:   id,
			HasSimulation: sim[id],
			HasDetection:  detect[id],
			HasCompliance: compliant[id],
		}
		if e := attackdata.Lookup(id); e != nil {
			tc.TechniqueName = e.Name
		}
		upper := strings.ToUpper(id)
		if v, ok := prevention[upper]; ok {
			tc.PreventionVerdict = v.Verdict
		}
		if v, ok := validation[upper]; ok {
			tc.DetectionVerdict = v.Verdict
		}
		switch {
		case !tc.HasSimulation && !tc.HasDetection && !tc.HasCompliance:
			tc.Status = "gap-no-content"
		case tc.PreventionVerdict == "" && tc.DetectionVerdict == "":
			tc.Status = "untested"
		default:
			tc.Status = "has-outcomes"
		}
		out = append(out, tc)
	}
	return out
}

// threatPriorityActorDetail is the GET /api/threat-priority/actors/{name}
// response shape: the actor's ActorPriority plus history, the concrete
// list of uncovered techniques, and the full per-technique coverage
// breakdown (feeds the Actor Details "Techniques"/"Coverage" tabs).
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
	TechniqueCoverage   []TechniqueCoverage                    `json:"techniqueCoverage"`
}

// GET /api/threat-priority/actors/{name}
func (h *Handler) ThreatPriorityActorDetail(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if h.threatPriorityEngine == nil {
		respond(w, threatPriorityActorDetail{UncoveredTechniques: []string{}, TechniqueCoverage: []TechniqueCoverage{}})
		return
	}
	ap, err := h.threatPriorityEngine.Score(r.Context(), name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hist, err := h.threatPriorityEngine.History(r.Context(), name, 30)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scenarios := h.engine.List()
	sim := coverage.BuildSimulationIndex(scenarios)
	detect := coverage.BuildProfileIndex(h.engine.Profiles())
	compliant := coverage.BuildComplianceIndex(scenarios)

	uncovered := []string{}
	for _, id := range ap.TechniqueIDs {
		if !sim[id] && !detect[id] && !compliant[id] {
			uncovered = append(uncovered, id)
		}
	}

	prevention, err := threatpriority.LoadPreventionVerdicts(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	validation, err := threatpriority.LoadValidationVerdicts(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	techCoverage := buildTechniqueCoverage(ap.TechniqueIDs, sim, detect, compliant, prevention, validation)

	respond(w, threatPriorityActorDetail{
		ActorPriority: ap, History: hist, UncoveredTechniques: uncovered, TechniqueCoverage: techCoverage,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/api/... && go test ./internal/api/... -run 'TestBuildTechniqueCoverage|TestThreatPriorityActorDetail|TestThreatPriorityActors' -v`
Expected: `go build` succeeds. All 5 new `TestBuildTechniqueCoverage_*` tests pass, plus all 3 pre-existing `TestThreatPriorityActor*` tests pass (including the extended `UnknownActor` test).

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/api/threatpriority_handlers.go internal/api/threatpriority_handlers_test.go
git commit -m "feat(api): add per-technique coverage breakdown to actor detail"
```

---

### Task 2: Frontend — coverage breakdown table

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (two edits: the static drawer markup around line 3454-3462, and `renderThreatPriorityDetail` around line 5448-5478)

**Interfaces:**
- Consumes: `d.techniqueCoverage` (array of `TechniqueCoverage`-shaped objects, Task 1) on the existing `renderThreatPriorityDetail(d)` function's parameter — same `d` already used for `d.factors`, `d.uncoveredTechniques`, `d.history`. Pre-existing helpers reused as-is: `x()` (HTML-escape).
- Produces: no new interface — this is the plan's terminal, UI-facing step.

- [ ] **Step 1: Add the static drawer card**

In `orchestrator/wwwroot/index.html`, insert a new card between the existing "Uncovered Techniques" card and the "History" card. Current (lines 3454-3462):

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Uncovered Techniques</div>
            <div id="tp-detail-uncovered" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>
```

Replace with:

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Uncovered Techniques</div>
            <div id="tp-detail-uncovered" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Technique Coverage Breakdown</div>
            <div id="tp-detail-coverage" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>
```

- [ ] **Step 2: Render the table in `renderThreatPriorityDetail`**

Current (lines 5467-5470):

```js
  var uncovered = (d.uncoveredTechniques || []);
  document.getElementById('tp-detail-uncovered').innerHTML = uncovered.length
    ? uncovered.map(function(t) { return '<span class="tool-tag">' + x(t) + '</span>'; }).join(' ')
    : '<span class="muted">No coverage gaps.</span>';
```

Insert immediately after it (still before the `var hist = ...` block):

```js

  var techCoverage = (d.techniqueCoverage || []);
  document.getElementById('tp-detail-coverage').innerHTML = techCoverage.length
    ? '<table style="width:100%"><thead><tr><th>Technique</th><th>Content</th><th>Prevention</th><th>Detection</th></tr></thead><tbody>' +
      techCoverage.map(function(tc) {
        var content = [
          tc.hasSimulation ? '<span class="tool-tag">Sim</span>' : '',
          tc.hasDetection ? '<span class="tool-tag">Detect</span>' : '',
          tc.hasCompliance ? '<span class="tool-tag">Compliance</span>' : ''
        ].filter(Boolean).join(' ') || '<span class="muted">&mdash;</span>';
        var label = tc.techniqueName ? tc.techniqueName + ' (' + tc.techniqueId + ')' : tc.techniqueId;
        var prevention = tc.preventionVerdict ? x(tc.preventionVerdict) : '<span class="muted">&mdash;</span>';
        var detection = tc.detectionVerdict ? x(tc.detectionVerdict) : '<span class="muted">&mdash;</span>';
        return '<tr><td>' + x(label) + '</td><td>' + content + '</td><td>' + prevention + '</td><td>' + detection + '</td></tr>';
      }).join('') +
      '</tbody></table>'
    : '<span class="muted">No technique data.</span>';
```

- [ ] **Step 3: Verify manually**

This file has no automated frontend test suite (consistent with the rest of the codebase and this session's prior UI steps). Verify by hand if a dev instance is reachable: open the Threat Prioritization tab, click into an actor with at least one technique, and confirm the new "Technique Coverage Breakdown" card renders a table (or the "No technique data." fallback for an actor with zero resolved techniques) without layout shift or console errors. If no dev instance is reachable in this environment, note that explicitly rather than claiming it was checked — add it to the standing Pending Manual QA Backlog.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): render technique coverage breakdown on actor detail"
```

---

## Self-Review Notes

- **Spec coverage:** Data model (`TechniqueCoverage`, `Status` derivation) — Task 1 Step 3. Backend wiring (`LoadPreventionVerdicts`/`LoadValidationVerdicts` calls, `buildTechniqueCoverage`, extended response struct) — Task 1 Step 3. Frontend table — Task 2. All 5 spec test cases — Task 1 Step 1, one test function each. Non-goals respected: no new dashboard tile, no scoring/engine changes, `UncoveredTechniques` untouched (and explicitly regression-tested), no use of the word "exposure" anywhere in new code (confirmed by re-reading Task 1 Step 3's full replacement file).
- **Placeholder scan:** No TBD/TODO; every step has literal, runnable code and exact commands. Task 2 Step 3's manual-verification framing is an honest limitation statement (matches this session's established pattern for the two prior projects' UI steps), not a placeholder.
- **Type consistency:** `TechniqueCoverage` fields/JSON tags identical between Task 1's Go definition and Task 2's JS property reads (`tc.hasSimulation`, `tc.hasDetection`, `tc.hasCompliance`, `tc.preventionVerdict`, `tc.detectionVerdict`, `tc.techniqueName`, `tc.techniqueId`). `buildTechniqueCoverage`'s signature is identical in its Task 1 Step 1 test calls and Step 3 definition. `threatPriorityActorDetail.TechniqueCoverage []TechniqueCoverage` matches what Task 2 reads via `d.techniqueCoverage`.
