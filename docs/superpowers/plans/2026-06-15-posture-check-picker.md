# Posture-Check Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dashboard "Posture check" label a clickable control that opens a dialog to select which built-in posture checks a `local_check` scenario runs, and have the agent run only the selected checks.

**Architecture:** Posture checks are compiled into the agent (`RunScenarioChecks(scenarioID)` → `[]SimCategory` of `SimCheck`), and today `check()` *executes* each check at list-construction time. We (A) defer execution so listing is free, (B) have the agent report a per-scenario check catalog at enroll time, (C) store it server-side and expose it via a read endpoint, (D) plumb a selected-check-ID subset through the simulate command so the agent runs only those, and (E) add the picker UI. The selection key is the existing stable `SimCheck.ID = checkID(techID, name)`.

**Tech Stack:** Go (agent + orchestrator), PostgreSQL (jsonb column + ALTER migration), vanilla JS (dashboard).

---

## Key facts (verified)
- `agent/simulate.go`: `check()` is the **single** constructor for every check and it runs `fn()` eagerly; `SimCheck.ID = checkID(techID,name)` (8-hex, stable). `SimCategory{Phase, Checks []SimCheck}`.
- `agent/agent.go:656 runLocalScan(scenarioID, runID)` is the **only** consumer of `RunScenarioChecks`. The per-OS `RunScenarioChecks`/`RunAllChecks` and the hundreds of `checkX()` funcs return `SimCheck` via `check(...)` and need **no signature change** once `check()` defers.
- `agent/agent.go:794-802`: the `MsgCommandSimulate` handler decodes `{scenarioId, runId}` then `go a.runLocalScan(...)`.
- `orchestrator/internal/api/handlers.go` `RunScenario`: the `if !live && sc.LocalCheck` block (~line 737-755) sends `models.MsgCommandSimulate` with `Data: map[string]string{"scenarioId":…, "runId":…}`. `RunScenario`'s request struct already carries `Techniques`/`Abilities`; add `Checks []string`.
- DB migrations are plain `ALTER TABLE … ADD COLUMN IF NOT EXISTS` in `orchestrator/internal/db/postgres.go`.
- Catalog is **per-agent-OS** (3 simulate builds), so the picker is opened with an agent in context (inside the Run modal), unlike the global ART/Caldera picker.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `agent/simulate.go` | Defer check execution; runner; catalog harvest types/helpers | Modify |
| `agent/agent.go` | `runLocalScan` runs (filtered) checks; simulate handler reads `checks`; enroll sends catalog | Modify |
| `agent/types.go` | `EnrollRequest.PostureCatalog`; `PostureCheckMeta` | Modify |
| `orchestrator/internal/db/postgres.go` | `agents.posture_catalog jsonb` column | Modify |
| `orchestrator/internal/api/handlers.go` | Store catalog on enroll; `GetPostureCatalog`; pass `Checks` into simulate Data | Modify |
| `orchestrator/internal/api/routes.go` | `GET /api/posture/catalog` (Viewer+) | Modify |
| `orchestrator/internal/models/*` | `EnrollRequest.PostureCatalog` mirror if a server-side enroll type exists | Modify (verify) |
| `orchestrator/wwwroot/index.html` | Clickable "Posture check" → run modal → check picker | Modify |
| `agent/simulate_test.go` | Deferred-exec + filter tests | Create/extend |

---

## Part A — Agent: defer check execution + selective runner

### Task 1: Defer execution in `check()`, add a runner

**Files:**
- Modify: `agent/simulate.go`
- Test: `agent/simulate_test.go`

- [ ] **Step 1: Write the failing test**

Create/extend `agent/simulate_test.go`:

```go
package main

import "testing"

func TestCheckDefersExecution(t *testing.T) {
	ran := false
	c := check("T1000", "demo", "execution", "High", "threat", "fix",
		func() (string, string) { ran = true; return "pass", "ok" })
	if ran {
		t.Fatal("check() executed fn eagerly; expected deferred execution")
	}
	if c.ID == "" || c.Technique.ID != "T1000" {
		t.Fatalf("metadata not populated pre-run: %+v", c)
	}
	c.run()
	if !ran || c.Result != "pass" || c.Details != "ok" {
		t.Fatalf("run() did not execute fn / fill result: ran=%v %+v", ran, c)
	}
}

func TestRunChecksFiltersBySelection(t *testing.T) {
	cats := []SimCategory{{Phase: "p", Checks: []SimCheck{
		check("T1", "a", "t", "High", "x", "y", func() (string, string) { return "pass", "" }),
		check("T2", "b", "t", "High", "x", "y", func() (string, string) { return "fail", "" }),
	}}}
	idB := checkID("T2", "b")
	out := runChecks(cats, map[string]bool{idB: true})
	got := 0
	for _, cat := range out {
		got += len(cat.Checks)
	}
	if got != 1 || out[0].Checks[0].ID != idB {
		t.Fatalf("expected only selected check b, got %d: %+v", got, out)
	}
	if out[0].Checks[0].Result != "fail" {
		t.Fatalf("selected check not executed: %+v", out[0].Checks[0])
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd agent && go test ./... -run 'TestCheckDefers|TestRunChecksFilters'`
Expected: FAIL (`check` runs eagerly; `run`/`runChecks` undefined).

- [ ] **Step 3: Implement deferral + runner**

In `agent/simulate.go`: add an unexported `fn` field to `SimCheck`, make `check()` store it without running, and add `run()` + `runChecks()`:

```go
type SimCheck struct {
	ID           string    `json:"id"`
	Technique    Tech      `json:"technique"`
	Result       string    `json:"result"`
	Severity     string    `json:"severity"`
	ThreatImpact string    `json:"threatImpact"`
	Details      string    `json:"details"`
	Remediation  string    `json:"remediation"`
	RawOutput    string    `json:"rawOutput,omitempty"`
	DurationMs   int64     `json:"durationMs"`
	ExecutedAt   time.Time `json:"executedAt"`
	Framework    string    `json:"framework"`
	fn           func() (result, details string) // deferred execution; never serialized
}

func check(techID, name, tactic, severity, threat, fix string,
	fn func() (result, details string)) SimCheck {
	return SimCheck{
		ID:           checkID(techID, name),
		Technique:    Tech{ID: techID, Name: name, Tactic: tactic},
		Severity:     severity,
		ThreatImpact: threat,
		Remediation:  fix,
		Framework:    "custom",
		fn:           fn,
	}
}

// run executes the deferred check, filling result fields. No-op if already run
// or if fn is nil (defensive).
func (c *SimCheck) run() {
	if c.fn == nil {
		return
	}
	start := time.Now()
	c.Result, c.Details = c.fn()
	c.DurationMs = time.Since(start).Milliseconds()
	c.ExecutedAt = time.Now()
}

// runChecks executes the checks in cats. When selected is non-empty, only checks
// whose ID is in selected are run AND kept; categories left empty are dropped.
// When selected is nil/empty, every check is run and all are kept.
func runChecks(cats []SimCategory, selected map[string]bool) []SimCategory {
	out := make([]SimCategory, 0, len(cats))
	for _, cat := range cats {
		kept := make([]SimCheck, 0, len(cat.Checks))
		for i := range cat.Checks {
			if len(selected) > 0 && !selected[cat.Checks[i].ID] {
				continue
			}
			cat.Checks[i].run()
			kept = append(kept, cat.Checks[i])
		}
		if len(kept) > 0 {
			out = append(out, SimCategory{Phase: cat.Phase, Checks: kept})
		}
	}
	return out
}
```

- [ ] **Step 4: Run to confirm pass**

Run: `cd agent && go test ./... -run 'TestCheckDefers|TestRunChecksFilters'`
Expected: PASS.

- [ ] **Step 5: Build the whole agent (all 3 OS tags compile the shared code)**

Run: `cd agent && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...`
Expected: clean (the per-OS `checkX` funcs still return `SimCheck`; only `check()` changed).

- [ ] **Step 6: Commit**

```bash
git add agent/simulate.go agent/simulate_test.go
git commit -m "refactor(agent): defer posture-check execution; add selective runChecks

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2: `runLocalScan` runs the (now-unrun) checks, honoring a selection

**Files:**
- Modify: `agent/agent.go` (`runLocalScan` ~656; simulate handler ~794-802)

- [ ] **Step 1: Make runLocalScan run checks + accept a selection**

Change the signature to `func (a *Agent) runLocalScan(scenarioID, runID string, selected []string)`. Right after `categories := RunScenarioChecks(scenarioID)` (line 673), insert:

```go
	sel := make(map[string]bool, len(selected))
	for _, id := range selected {
		sel[id] = true
	}
	categories = runChecks(categories, sel) // execute (filtered) — checks no longer run at list time
	if len(categories) == 0 {
		log.Printf("[!] local scan %s: no checks matched selection (%d ids) — nothing to run", runID, len(selected))
	}
```

The rest (harvesting `SimCheckResult` from `categories`, submitting) is unchanged — it now reads executed results.

- [ ] **Step 2: Read `checks` in the simulate handler**

In the `MsgCommandSimulate` handler (~794), extend the decoded struct and the call:

```go
				var sim struct {
					ScenarioID string   `json:"scenarioId"`
					RunID      string   `json:"runId"`
					Checks     []string `json:"checks"`
				}
				// … existing unmarshal …
				go func() { defer a.runWG.Done(); a.runLocalScan(sim.ScenarioID, sim.RunID, sim.Checks) }()
```

(Match the existing unmarshal style of the handler — read the surrounding code; only add the `Checks` field and the third arg.)

- [ ] **Step 3: Build all OS targets**

Run: `cd agent && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add agent/agent.go
git commit -m "feat(agent): runLocalScan executes checks and honors a selected subset

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part B — Agent: report the posture catalog at enroll

### Task 3: Catalog types + harvest helper

**Files:**
- Modify: `agent/types.go` (add `PostureCheckMeta`; `EnrollRequest.PostureCatalog`)
- Modify: `agent/simulate.go` (`knownPostureScenarios`, `BuildPostureCatalog`)
- Test: `agent/simulate_test.go`

- [ ] **Step 1: Add the catalog types**

In `agent/types.go`:

```go
// PostureCheckMeta is one selectable posture check (no result — catalog only).
type PostureCheckMeta struct {
	ID        string `json:"id"`
	Phase     string `json:"phase"`
	TechniqueID string `json:"techniqueId"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
}
```
Add to `EnrollRequest`:
```go
	// PostureCatalog maps each local-check scenarioId to its selectable checks.
	PostureCatalog map[string][]PostureCheckMeta `json:"postureCatalog,omitempty"`
```

- [ ] **Step 2: Write the failing test**

Append to `agent/simulate_test.go`:

```go
func TestBuildPostureCatalogHarvestsWithoutRunning(t *testing.T) {
	cat := BuildPostureCatalog()
	if len(cat) == 0 {
		t.Fatal("expected at least one posture scenario in catalog")
	}
	for sid, checks := range cat {
		if len(checks) == 0 {
			t.Errorf("scenario %s has no checks", sid)
		}
		for _, c := range checks {
			if c.ID == "" || c.Name == "" {
				t.Errorf("scenario %s has a check with empty id/name: %+v", sid, c)
			}
		}
	}
}
```

- [ ] **Step 3: Run to confirm failure**

Run: `cd agent && go test ./... -run TestBuildPostureCatalog`
Expected: FAIL (`BuildPostureCatalog` undefined).

- [ ] **Step 4: Implement the harvest**

In `agent/simulate.go`:

```go
// knownPostureScenarios lists the local-check scenario IDs this agent build
// recognizes (mirrors the RunScenarioChecks switch). "" yields RunAllChecks.
func knownPostureScenarios() []string {
	return []string{
		"safe-simulation", "apt36-spearphish", "apt36-kill-chain",
		"ransomware-drill", "ad-credential-access", "upi-fraud-killchain",
		"cscrf-mii-drill", "purplesharp-ad-drill", "lolbin-execution",
		"lolbin-execution-coverage",
	}
}

// BuildPostureCatalog harvests selectable-check metadata for every known posture
// scenario WITHOUT executing any check (checks are deferred since the refactor).
func BuildPostureCatalog() map[string][]PostureCheckMeta {
	out := make(map[string][]PostureCheckMeta)
	for _, sid := range knownPostureScenarios() {
		var metas []PostureCheckMeta
		for _, cat := range RunScenarioChecks(sid) {
			for _, c := range cat.Checks {
				metas = append(metas, PostureCheckMeta{
					ID: c.ID, Phase: cat.Phase, TechniqueID: c.Technique.ID,
					Name: c.Technique.Name, Severity: c.Severity,
				})
			}
		}
		if len(metas) > 0 {
			out[sid] = metas
		}
	}
	return out
}
```
(Confirm the scenario-ID list against the live `RunScenarioChecks` switch in `agent/simulate_windows.go:56-80`; keep them in sync.)

- [ ] **Step 5: Run to confirm pass + build all OS**

Run: `cd agent && go test ./... -run TestBuildPostureCatalog && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...`
Expected: PASS + clean builds.

- [ ] **Step 6: Commit**

```bash
git add agent/types.go agent/simulate.go agent/simulate_test.go
git commit -m "feat(agent): posture-check catalog harvest (metadata, no execution)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4: Send the catalog in the enroll request

**Files:**
- Modify: `agent/agent.go` (`enrollWithServer` ~134)

- [ ] **Step 1: Populate the field**

In `enrollWithServer`, set `PostureCatalog: BuildPostureCatalog()` in the `EnrollRequest{…}` literal (~line 135). Build is cheap now (no checks execute).

- [ ] **Step 2: Build all OS targets**

Run: `cd agent && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add agent/agent.go
git commit -m "feat(agent): advertise posture-check catalog at enroll

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part C — Orchestrator: store + serve the catalog

### Task 5: Persist the catalog on enroll

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (agents column)
- Modify: `orchestrator/internal/api/handlers.go` (`EnrollAgent`; the request struct)
- Verify: `orchestrator/internal/models` for any server-side enroll type that mirrors `EnrollRequest`

- [ ] **Step 1: Add the column**

In `orchestrator/internal/db/postgres.go`, in the agents `ALTER TABLE` migration list, add:

```go
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS posture_catalog jsonb NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 2: Accept + store the catalog in EnrollAgent**

Find the enroll handler (`EnrollAgent`) and the struct it decodes the body into. Add a field mirroring the agent's wire shape:

```go
		PostureCatalog json.RawMessage `json:"postureCatalog"`
```
Store it on the agent row in the same INSERT/UPSERT that records enroll (write `'{}'` when absent). Use `COALESCE(NULLIF($n,''), '{}')::jsonb` or pass `[]byte("{}")` when nil — match the existing column-write style in that handler.

- [ ] **Step 3: Build + existing tests**

Run: `cd orchestrator && go build ./... && go test ./internal/api/ ./internal/db/`
Expected: clean / ok.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/handlers.go
git commit -m "feat(api): persist agent posture-check catalog on enroll

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 6: `GET /api/posture/catalog`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`GetPostureCatalog`)
- Modify: `orchestrator/internal/api/routes.go`

- [ ] **Step 1: Add the handler**

```go
// GET /api/posture/catalog?agentId=<id>&scenario=<id> — the selectable posture
// checks for a scenario, as reported by that agent at enroll. Viewer+.
func (h *Handler) GetPostureCatalog(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	scenario := r.URL.Query().Get("scenario")
	if agentID == "" || scenario == "" {
		jsonError(w, "agentId and scenario are required", http.StatusBadRequest)
		return
	}
	var raw []byte
	err := h.db.QueryRow(r.Context(),
		`SELECT COALESCE(posture_catalog,'{}')::text FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&raw)
	if err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	var cat map[string][]map[string]any
	_ = json.Unmarshal(raw, &cat)
	checks := cat[scenario]
	if checks == nil {
		checks = []map[string]any{}
	}
	respond(w, checks)
}
```

- [ ] **Step 2: Register the route (Viewer+)**

In `routes.go`, alongside the other Viewer+ read routes (near `/api/art/techniques`):

```go
		r.Get("/api/posture/catalog", h.GetPostureCatalog)
```

- [ ] **Step 3: Build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go
git commit -m "feat(api): GET /api/posture/catalog (agent-reported posture checks)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 7: Pass the selected checks into the simulate command

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`RunScenario`)

- [ ] **Step 1: Add `Checks` to the request struct**

In `RunScenario`'s request struct, add:
```go
		Checks      []string `json:"checks"`      // optional posture-check subset (local_check scenarios)
```

- [ ] **Step 2: Include checks in the simulate Data**

In the `if !live && sc.LocalCheck` block, change the dispatch Data from `map[string]string{"scenarioId":…, "runId":…}` to a typed payload carrying the selection:

```go
		sent := h.hub.SendToAgent(req.AgentID, models.WSMessage{
			Type:    models.MsgCommandSimulate,
			AgentID: req.AgentID,
			Data: map[string]any{
				"scenarioId": scenarioID,
				"runId":      runID,
				"checks":     req.Checks, // nil/empty → agent runs all
			},
		})
```
(Confirm `models.WSMessage.Data` accepts `any`/`interface{}` or is marshaled — match how other `SendToAgent` calls build `Data`. If `Data` is `json.RawMessage`, marshal the map first.)

- [ ] **Step 3: Build + tests**

Run: `cd orchestrator && go build ./... && go test ./internal/api/`
Expected: clean / ok.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "feat(run): forward selected posture checks to the agent

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part D — Frontend: clickable "Posture check" → picker

### Task 8: Make the label clickable and wire the posture picker

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

Context: The card mode label is built in `scenarioCardHTML` (the `modeMeta` block; posture scenarios → `modeMeta = 'Posture check'`). The ART/Caldera picker already exists: globals `_runSelection`, functions `openPicker`/`openPickerWith`/`renderPickerList`/`applyPicker`/`renderModalSelection`/`confirmRun`, and a `#picker-overlay`. Posture differs: the catalog is per-agent, so the picker is opened from the **Run modal** (agent selected), not the card. The card label just opens the run modal.

- [ ] **Step 1: Make "Posture check" a button that opens the run modal**

In `scenarioCardHTML`, where `modeMeta` is rendered in the footer (`'<div class="card-meta">' + modeMeta + '</div>'`), for `localCheck` scenarios wrap it as a clickable control:

```js
      var metaHtml = s.localCheck
        ? '<a href="javascript:void(0)" class="desc-toggle" onclick="openModal(\'' + x(s.id) + '\',null)" title="Choose which posture checks to run">' + modeMeta + ' &#9881;</a>'
        : modeMeta;
```
and render `metaHtml` instead of `modeMeta` in that `card-meta` div.

- [ ] **Step 2: Extend the run modal selection logic for posture**

`scenarioFramework(sc)` currently returns 'art'|'caldera'|''. Add posture:
```js
function scenarioFramework(sc) {
  if (!sc) return '';
  if (sc.localCheck) return 'posture';
  if (sc.artAllWindows || (sc.artTechniques || []).length) return 'art';
  if (sc.calderaAllWindows || (sc.calderaAbilities || []).length) return 'caldera';
  return '';
}
```
In `renderModalSelection`, the `noun` for posture is `'checks'`. The Customize link for posture must be enabled only once an agent is selected (catalog is agent-specific). Update it so for `fw === 'posture'` the link reads `Customize — select checks to run` and, when no agent is chosen, is disabled with a hint `(select an agent first)`.

- [ ] **Step 3: Fetch the posture catalog in openPicker**

In `openPicker`, branch on framework. For `fw === 'posture'`, the catalog comes from `/api/posture/catalog?agentId=<modal-agent>&scenario=<scId>` (not the global `artCatalog`/`calderaCatalog`). Read the selected agent from `#modal-agent`; if none, toast `Select a target agent first` and return. Fetch, then `openPickerWith(scId, 'posture', sc, items)`. The catalog item shape is `{id, phase, techniqueId, name, severity}` — `openPickerWith`/`renderPickerList` already key on `it.id` and show `it.name`; for posture show `it.phase`/`it.severity` as the meta line (extend the `meta` computation in `renderPickerList` with a `fw === 'posture'` branch: `meta = [it.phase, it.severity].filter(Boolean).join(' · ')`). Pre-check: all by default (no prior selection).

- [ ] **Step 4: Send `checks` in confirmRun for posture**

In `confirmRun`, where `_runSelection` is attached to the body, add the posture branch:
```js
  if (_runSelection && _runSelection.scId === scenarioId && _runSelection.ids.length) {
    if (_runSelection.fw === 'art') body.techniques = _runSelection.ids;
    else if (_runSelection.fw === 'caldera') body.abilities = _runSelection.ids;
    else if (_runSelection.fw === 'posture') body.checks = _runSelection.ids;
  }
```

- [ ] **Step 5: Manual sanity (no automated FE test in repo)**

Open the dashboard built from this tree (or reason through): a `local_check` scenario card shows "Posture check ⚙" as a link; clicking opens the run modal; selecting an agent enables "Customize — select checks"; the picker lists that agent's checks for the scenario; "Use selection (N)" then Run dispatches with `checks:[…]`. Confirm `git grep` shows no references to removed symbols.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): clickable Posture check opens a check picker (agent-scoped)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** clickable "Posture check" (Task 8.1) → dialog to pick checks (Task 8.3) → agent runs only selected (Tasks 1-2, 7). Catalog availability (Tasks 3-6). ✓

**Placeholder scan:** every Go step has full code; Task 5.2 and Task 7.2 say "match existing style" because the exact enroll-INSERT and `WSMessage.Data` type must be read in-repo — both are concrete verification points, not deferred logic. Task 8 steps reference existing functions by name with the exact edits.

**Type consistency:** `SimCheck.fn` (Task 1) is read by `run()`/`runChecks()` (Task 1), called by `runLocalScan` (Task 2). `PostureCheckMeta` (Task 3) flows agent→`EnrollRequest.PostureCatalog`→server column (Task 5)→`GET /api/posture/catalog` (Task 6)→picker (Task 8). `checks[]` flows picker→`RunScenario.Checks` (Task 7)→simulate `Data.checks`→`runLocalScan(…, selected)` (Task 2)→`runChecks` filter (Task 1). `SimCheck.ID` is the single selection key throughout. Consistent.

**Risk notes:**
- Catalog staleness: reported at enroll; an agent upgraded with new checks must re-enroll (or extend heartbeat to refresh) for the picker to reflect changes. Acceptable for v1; note in the handler comment.
- `WSMessage.Data` type (Task 7.2) — if it's `json.RawMessage`, marshal the map before assigning. Verify before coding.
- Server-side enroll struct (Task 5) may live in `internal/models`; if `EnrollRequest` is shared there, add `PostureCatalog` once and reuse.
