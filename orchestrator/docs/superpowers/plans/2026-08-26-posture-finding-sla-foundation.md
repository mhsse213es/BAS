# Posture Finding SLA Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist CIS Security Configuration + Identity posture findings into a new `posture_findings` table with a real lifecycle (first-failed/recurred/healed/reopened), reusing the existing `internal/findings.Apply` state-machine function unchanged.

**Architecture:** A new file `orchestrator/internal/api/posture_finding_handlers.go` mirrors the existing `finding_handlers.go` (BAS findings) file almost line-for-line: an ingest function hooked into `SubmitScenarioResult` alongside the existing BAS-findings ingest, a per-`(agent_id, check_id)` upsert function that loads current state, calls `findings.Apply` (unchanged, imported from `internal/findings`), and writes the result to a new `posture_findings` table. Two new read-only GET endpoints expose it.

**Tech Stack:** Go, PostgreSQL (pgx), chi router — all pre-existing in this codebase, no new dependencies.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-26-posture-finding-sla-foundation-design.md`

## Global Constraints

- Scope is Security Configuration + Identity categories only (`endpointrisk.CategorySecurityConfig` = `"security-configuration"`, `endpointrisk.CategoryIdentity` = `"identity"`). Any other category (Application Risk, Compliance, BAS Readiness, Patch Management) must be skipped, not persisted.
- `posture_findings.status` only ever takes `"open"` or `"remediated"` — no manual override endpoint ships in this sub-project.
- Reuse `findings.Apply` from `internal/findings` unchanged — do not copy or reimplement its transition logic.
- Both new read endpoints reuse the existing `auth.CanExecuteRemediation` permission — no new permission.
- Build directly on `main`, no branches/PRs. Commit after each task; push after every commit.
- Real Postgres via testcontainers for all tests (this codebase's established convention) — no mocks for DB-touching code.

---

## File Structure

- **Create** `orchestrator/internal/api/posture_finding_handlers.go` — ingest (`upsertPostureFindingsForRun`, `applyPostureFinding`), shared column/scan helpers (`postureFindingCols`, `scanPostureFindings`), and the two HTTP handlers (`ListAgentPostureFindings`, `GetPostureFinding`).
- **Create** `orchestrator/internal/api/posture_finding_handlers_test.go` — all ingest-lifecycle and handler tests.
- **Modify** `orchestrator/internal/db/postgres.go` — one new `CREATE TABLE IF NOT EXISTS posture_findings (...)` plus two indexes, appended to the existing `stmts` migration slice.
- **Modify** `orchestrator/internal/api/handlers.go` — one new line inside `SubmitScenarioResult`, immediately after the existing `h.upsertFindingsForRun(...)` call at line 2362.
- **Modify** `orchestrator/internal/api/routes.go` — two new route registrations.
- **Modify** `orchestrator/internal/api/rbac_matrix_test.go` — two new `routeMatrix` rows.

---

### Task 1: `posture_findings` table migration

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:1618-1619` (immediately after the `fail_reason` ALTER, before the closing `}` of the `stmts` slice)

**Interfaces:**
- Produces: the `posture_findings` table, columns `id, agent_id, check_id, category, title, severity, exposure_state, status, occurrence_count, reopened_count, last_run_id, first_seen, last_seen, last_observed_at, resolved_at, resolved_reason, created_at, tenant_id`, unique constraint `uq_posture_finding (agent_id, check_id)`, indexes `idx_posture_findings_agent (agent_id)` and `idx_posture_findings_status (status)`. All later tasks read/write this table.

- [ ] **Step 1: Add the migration statement**

Open `orchestrator/internal/db/postgres.go`. Find this exact block (around line 1612-1619):

```go
		// fail_reason: a genuine, human-readable explanation for why a run's
		// status became 'failed' (dispatch-time only -- e.g. agent offline,
		// malformed scenario content, every step lab-only in a non-lab mode).
		// Previously status='failed' persisted with zero context -- the
		// Results drawer showed a bare "0 fail / 0 pass" and a red badge with
		// no way to tell "agent was offline" from "scenario is broken".
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS fail_reason text`,
	}
```

Replace it with (adds the new table statement + its two indexes right after, still inside the slice, before the closing `}`):

```go
		// fail_reason: a genuine, human-readable explanation for why a run's
		// status became 'failed' (dispatch-time only -- e.g. agent offline,
		// malformed scenario content, every step lab-only in a non-lab mode).
		// Previously status='failed' persisted with zero context -- the
		// Results drawer showed a bare "0 fail / 0 pass" and a red badge with
		// no way to tell "agent was offline" from "scenario is broken".
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS fail_reason text`,

		// posture_findings: persisted lifecycle for CIS Security Configuration
		// + Identity posture-check findings, keyed (agent_id, check_id) --
		// deliberately narrower than the BAS findings table's
		// (agent_id, technique_id, control_class) key, since a posture check_id
		// maps to exactly one finding per agent (unlike Application Risk, where
		// one check_id can produce many findings -- explicitly out of scope,
		// see docs/superpowers/specs/2026-08-26-posture-finding-sla-foundation-design.md).
		// Reuses internal/findings.Apply's state machine unchanged; this table
		// only differs from `findings` by dropping BAS-specific columns
		// (technique_name/tactic/source_type/attack_data_source/
		// security_product_snapshot/last_campaign_id/resolved_by) that have no
		// posture-check equivalent.
		`CREATE TABLE IF NOT EXISTS posture_findings (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id          text        NOT NULL,
			check_id          text        NOT NULL,
			category          text        NOT NULL DEFAULT '',
			title             text        NOT NULL DEFAULT '',
			severity          text        NOT NULL DEFAULT 'Medium',
			exposure_state    text        NOT NULL DEFAULT 'missed',
			status            text        NOT NULL DEFAULT 'open',
			occurrence_count  int         NOT NULL DEFAULT 1,
			reopened_count    int         NOT NULL DEFAULT 0,
			last_run_id       text,
			first_seen        timestamptz NOT NULL DEFAULT NOW(),
			last_seen         timestamptz NOT NULL DEFAULT NOW(),
			last_observed_at  timestamptz NOT NULL DEFAULT NOW(),
			resolved_at       timestamptz,
			resolved_reason   text,
			created_at        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id         text        NOT NULL DEFAULT 'default',
			CONSTRAINT uq_posture_finding UNIQUE (agent_id, check_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_posture_findings_agent ON posture_findings (agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_posture_findings_status ON posture_findings (status)`,
	}
```

- [ ] **Step 2: Build to confirm no syntax errors**

Run: `cd orchestrator && go build ./...`
Expected: builds clean (this is a pure data change, no Go logic yet — this step only catches a malformed Go string/slice literal).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(db): add posture_findings table for the posture SLA foundation"
git push
```

---

### Task 2: Ingest — state machine wiring and lifecycle tests

**Files:**
- Create: `orchestrator/internal/api/posture_finding_handlers.go`
- Create: `orchestrator/internal/api/posture_finding_handlers_test.go`

**Interfaces:**
- Consumes: `findings.Apply(s findings.State, o findings.Observation) (findings.State, findings.Transition)` from `internal/findings` (unchanged); `h.endpointRiskTaxonomy.CategoryForCheck(checkID string) (category string, weight float64, ok bool)`; `endpointrisk.CategorySecurityConfig`, `endpointrisk.CategoryIdentity` constants; `postureCheckFindingText` map (already defined in `endpointrisk_aggregations.go`, same package — no import needed, just reference it directly); `models.SimulationResult{CheckID, Result, ExecutedAt}`; `models.ResultPass`.
- Produces: `func (h *Handler) upsertPostureFindingsForRun(ctx context.Context, runID string)` — called by Task 3. `postureFindingCols` (string) and `func scanPostureFindings(rows findingScanner) []map[string]any` — consumed by Task 4's handlers. (`findingScanner` is the existing interface already defined in `finding_handlers.go:188-191` — same package, reuse it, don't redefine.)

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/posture_finding_handlers_test.go`. This uses the
exact same real, already-existing test infrastructure `endpointrisk_aggregations_test.go`
and `endpointrisk_handlers_test.go` use: `sharedDB.RunWithPool`, `mustExecAPI`
(`dashboard_handlers_test.go:106`), `New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")`,
and setting `h.endpointRiskTaxonomy` directly from a real `endpointrisk.NewTaxonomy()` —
verified present in this package, not assumed:

```go
package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPostureTestHandler builds a Handler with a real Taxonomy loaded --
// upsertPostureFindingsForRun no-ops when h.endpointRiskTaxonomy is nil.
func newPostureTestHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	tx, err := endpointrisk.NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	h.endpointRiskTaxonomy = tx
	return h
}

// seedPostureCheckRun seeds an agent (idempotent) and a scenario_runs row
// carrying one posture-check result for check_id="windows-firewall-enabled"
// (a real Security Configuration entry in postureCheckFindingText). Mirrors
// the raw-JSON seeding style already used in endpointrisk_aggregations_test.go
// and endpointrisk_handlers_test.go, rather than marshaling a
// models.SimulationResult Go struct.
func seedPostureCheckRun(t *testing.T, pool *pgxpool.Pool, runID, agentID, result string, at time.Time) {
	t.Helper()
	mustExecAPI(t, pool,
		`INSERT INTO agents (agent_id, hostname) VALUES ($1, $2) ON CONFLICT (agent_id) DO NOTHING`,
		agentID, "host-"+agentID)
	mustExecAPI(t, pool,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, completed_at)
		 VALUES ($1, 'pf-scenario', 'PF Run', $2, 'completed', $3::jsonb, $4, $4)`,
		runID, agentID,
		`[{"checkId":"windows-firewall-enabled","result":"`+result+`","executedAt":"`+at.UTC().Format(time.RFC3339)+`"}]`,
		at)
}

func TestUpsertPostureFindingsForRun_FirstFailCreatesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		now := time.Now()
		seedPostureCheckRun(t, pool, "pf-fail-1", "agent-pf-fail", "fail", now)

		h.upsertPostureFindingsForRun(context.Background(), "pf-fail-1")

		var status string
		var occ int
		err := pool.QueryRow(context.Background(),
			`SELECT status, occurrence_count FROM posture_findings WHERE agent_id='agent-pf-fail' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &occ)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" || occ != 1 {
			t.Errorf("status=%q occurrence_count=%d, want open/1", status, occ)
		}
	})
}

func TestUpsertPostureFindingsForRun_SecondFailRecurs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		seedPostureCheckRun(t, pool, "pf-recur-1", "agent-pf-recur", "fail", t1)
		seedPostureCheckRun(t, pool, "pf-recur-2", "agent-pf-recur", "fail", t2)

		h.upsertPostureFindingsForRun(context.Background(), "pf-recur-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-recur-2")

		var status string
		var occ, rowCount int
		err := pool.QueryRow(context.Background(),
			`SELECT status, occurrence_count FROM posture_findings WHERE agent_id='agent-pf-recur' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &occ)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" || occ != 2 {
			t.Errorf("status=%q occurrence_count=%d, want open/2 (same row)", status, occ)
		}
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM posture_findings WHERE agent_id='agent-pf-recur'`).Scan(&rowCount)
		if rowCount != 1 {
			t.Errorf("rowCount=%d, want exactly 1 row (counters, not one row per occurrence)", rowCount)
		}
	})
}

func TestUpsertPostureFindingsForRun_PassHeals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		seedPostureCheckRun(t, pool, "pf-heal-1", "agent-pf-heal", "fail", t1)
		seedPostureCheckRun(t, pool, "pf-heal-2", "agent-pf-heal", "pass", t2)

		h.upsertPostureFindingsForRun(context.Background(), "pf-heal-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-heal-2")

		var status, reason string
		var resolvedAt *time.Time
		err := pool.QueryRow(context.Background(),
			`SELECT status, resolved_at, resolved_reason FROM posture_findings WHERE agent_id='agent-pf-heal' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &resolvedAt, &reason)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "remediated" || resolvedAt == nil || reason != "re-validated pass" {
			t.Errorf("status=%q resolvedAt=%v reason=%q, want remediated/non-nil/\"re-validated pass\"", status, resolvedAt, reason)
		}
	})
}

func TestUpsertPostureFindingsForRun_ReopenAfterHeal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		t3 := t1.Add(2 * time.Hour)
		seedPostureCheckRun(t, pool, "pf-reopen-1", "agent-pf-reopen", "fail", t1)
		seedPostureCheckRun(t, pool, "pf-reopen-2", "agent-pf-reopen", "pass", t2)
		seedPostureCheckRun(t, pool, "pf-reopen-3", "agent-pf-reopen", "fail", t3)

		h.upsertPostureFindingsForRun(context.Background(), "pf-reopen-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-reopen-2")
		h.upsertPostureFindingsForRun(context.Background(), "pf-reopen-3")

		var status string
		var resolvedAt *time.Time
		var reopened int
		err := pool.QueryRow(context.Background(),
			`SELECT status, resolved_at, reopened_count FROM posture_findings WHERE agent_id='agent-pf-reopen' AND check_id='windows-firewall-enabled'`,
		).Scan(&status, &resolvedAt, &reopened)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" || resolvedAt != nil || reopened != 1 {
			t.Errorf("status=%q resolvedAt=%v reopened_count=%d, want open/nil/1", status, resolvedAt, reopened)
		}
	})
}

func TestUpsertPostureFindingsForRun_OutOfOrderRunIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		newer := time.Now()
		older := newer.Add(-time.Hour)
		seedPostureCheckRun(t, pool, "pf-ooo-1", "agent-pf-ooo", "fail", newer)
		seedPostureCheckRun(t, pool, "pf-ooo-2", "agent-pf-ooo", "pass", older)

		h.upsertPostureFindingsForRun(context.Background(), "pf-ooo-1")
		h.upsertPostureFindingsForRun(context.Background(), "pf-ooo-2")

		var status string
		err := pool.QueryRow(context.Background(),
			`SELECT status FROM posture_findings WHERE agent_id='agent-pf-ooo' AND check_id='windows-firewall-enabled'`,
		).Scan(&status)
		if err != nil {
			t.Fatalf("query posture_findings: %v", err)
		}
		if status != "open" {
			t.Errorf("status=%q, want open (the older passing run must not heal a newer failure)", status)
		}
	})
}

func TestUpsertPostureFindingsForRun_OutOfScopeCategoryNeverCreatesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		now := time.Now()
		mustExecAPI(t, pool,
			`INSERT INTO agents (agent_id, hostname) VALUES ('agent-pf-oos', 'host-agent-pf-oos') ON CONFLICT (agent_id) DO NOTHING`)
		mustExecAPI(t, pool,
			`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, completed_at)
			 VALUES ('pf-oos-1', 'pf-scenario', 'PF Run', 'agent-pf-oos', 'completed', $1::jsonb, $2, $2)`,
			`[{"checkId":"windows-installed-software","result":"fail","executedAt":"`+now.UTC().Format(time.RFC3339)+`"}]`,
			now)

		h.upsertPostureFindingsForRun(context.Background(), "pf-oos-1")

		var count int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM posture_findings WHERE agent_id='agent-pf-oos'`).Scan(&count)
		if count != 0 {
			t.Errorf("count=%d, want 0 (windows-installed-software is Application Risk, out of scope)", count)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestUpsertPostureFindingsForRun -v`
Expected: FAIL — compile error, `h.upsertPostureFindingsForRun` undefined.

- [ ] **Step 3: Write the minimal implementation**

Create `orchestrator/internal/api/posture_finding_handlers.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/models"
)

// postureFindingAgg is the run-level aggregate outcome for one check_id,
// carried from upsertPostureFindingsForRun into applyPostureFinding. Unlike
// findingAgg (BAS findings), there is no technique/tactic/control metadata --
// a posture check_id is self-describing via postureCheckFindingText.
type postureFindingAgg struct {
	checkID, category string
}

// upsertPostureFindingsForRun (re)derives posture findings from a run's
// persisted results and applies findings.Apply per (agent, check_id), scoped
// to Security Configuration + Identity categories only. Idempotent, safe to
// call from partial submissions -- mirrors upsertFindingsForRun's contract
// exactly (see handlers.go's SubmitScenarioResult call site comment).
func (h *Handler) upsertPostureFindingsForRun(ctx context.Context, runID string) {
	if h.endpointRiskTaxonomy == nil {
		return
	}
	var agentID string
	var resultsRaw []byte
	var observedAt time.Time
	err := h.db.QueryRow(ctx,
		`SELECT agent_id, results, COALESCE(completed_at, started_at) FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &resultsRaw, &observedAt)
	if err != nil {
		return
	}
	var results []models.SimulationResult
	_ = json.Unmarshal(resultsRaw, &results)
	if len(results) == 0 {
		return
	}

	// Aggregate to one outcome per check_id within this run: any failing
	// result for a check_id makes that check_id "missed" for this run; only
	// if every contributing result for that check_id passed does it count as
	// "prevented". Matches upsertFindingsForRun's own precedent exactly:
	// Pass/Blocked contribute as non-fail, Fail contributes as fail, and
	// Error/Skipped are excluded from consideration entirely (a check_id
	// whose only results this run are error/skipped never gets a byCheck
	// entry at all, so no Observation is generated for it this run --
	// same as the `default: continue // error | skipped` branch in
	// upsertFindingsForRun, finding_handlers.go:85-86).
	type agg struct {
		category string
		anyFail  bool
	}
	byCheck := map[string]*agg{}
	for _, r := range results {
		if r.CheckID == "" {
			continue
		}
		category, _, ok := h.endpointRiskTaxonomy.CategoryForCheck(r.CheckID)
		if !ok || (category != endpointrisk.CategorySecurityConfig && category != endpointrisk.CategoryIdentity) {
			continue
		}
		var isFail bool
		switch r.Result {
		case models.ResultPass, models.ResultBlocked:
			isFail = false
		case models.ResultFail:
			isFail = true
		default: // error | skipped -- excluded from this run's contribution
			continue
		}
		a := byCheck[r.CheckID]
		if a == nil {
			a = &agg{category: category}
			byCheck[r.CheckID] = a
		}
		if isFail {
			a.anyFail = true
		}
	}

	for checkID, a := range byCheck {
		outcome := "prevented"
		if a.anyFail {
			outcome = "missed"
		}
		h.applyPostureFinding(ctx, agentID, &postureFindingAgg{checkID: checkID, category: a.category},
			findings.Observation{Outcome: outcome, RunID: runID, ObservedAt: observedAt})
	}
}

// applyPostureFinding loads the current posture finding for (agentID,
// a.checkID), runs findings.Apply unchanged, and writes the result back
// (insert on create, update otherwise) -- structurally identical to
// applyFinding (finding_handlers.go) minus the BAS-specific columns and the
// dispatchTicketing call (no ticketing integration for posture findings in
// this sub-project).
func (h *Handler) applyPostureFinding(ctx context.Context, agentID string, a *postureFindingAgg, o findings.Observation) {
	var s findings.State
	var resolvedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT status, exposure_state, occurrence_count, reopened_count,
		        COALESCE(last_run_id,''), last_observed_at, resolved_at
		   FROM posture_findings WHERE agent_id=$1 AND check_id=$2`,
		agentID, a.checkID).
		Scan(&s.Status, &s.ExposureState, &s.OccurrenceCount, &s.ReopenedCount, &s.LastRunID, &s.LastObservedAt, &resolvedAt)
	if err == nil {
		s.Exists = true
		s.Resolved = resolvedAt != nil
	}

	next, tr := findings.Apply(s, o)
	if tr == findings.Noop || tr == findings.Stale {
		return
	}
	if tr == findings.Created {
		text := postureCheckFindingText[a.checkID]
		_, _ = h.db.Exec(ctx,
			`INSERT INTO posture_findings (agent_id, check_id, category, title, exposure_state, status,
			        occurrence_count, last_run_id, first_seen, last_seen, last_observed_at)
			 VALUES ($1,$2,$3,$4,$5,'open',1,$6,NOW(),NOW(),$7)
			 ON CONFLICT (agent_id, check_id) DO NOTHING`,
			agentID, a.checkID, a.category, text.Title, next.ExposureState, o.RunID, o.ObservedAt)
		return
	}

	// recurred | healed | reopened -> update. (Refined never occurs here --
	// that transition only fires when a later observation shares the exact
	// same RunID as the stored state, which upsertPostureFindingsForRun never
	// produces since it aggregates each check_id to one Observation per run.)
	var resolvedAtSet *time.Time
	var resolvedReason *string
	clearResolved := tr == findings.Reopened
	if tr == findings.Healed {
		now := time.Now()
		reason := "re-validated pass"
		resolvedAtSet, resolvedReason = &now, &reason
	}
	_, _ = h.db.Exec(ctx,
		`UPDATE posture_findings SET status=$1, exposure_state=$2, occurrence_count=$3, reopened_count=$4,
		        last_run_id=$5, last_seen=NOW(), last_observed_at=$6,
		        resolved_at = CASE WHEN $7 THEN NULL ELSE COALESCE($8, resolved_at) END,
		        resolved_reason = COALESCE($9, resolved_reason)
		   WHERE agent_id=$10 AND check_id=$11`,
		next.Status, next.ExposureState, next.OccurrenceCount, next.ReopenedCount,
		o.RunID, o.ObservedAt,
		clearResolved, resolvedAtSet, resolvedReason,
		agentID, a.checkID)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestUpsertPostureFindingsForRun -v`
Expected: PASS (all 6 subtests).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/posture_finding_handlers.go orchestrator/internal/api/posture_finding_handlers_test.go
git commit -m "feat(api): persist posture findings via reused findings.Apply state machine"
git push
```

---

### Task 3: Hook into `SubmitScenarioResult`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:2362`
- Test: `orchestrator/internal/api/submit_scenario_result_test.go` (extend, or add a new test in the same file if a fitting one doesn't already exist)

**Interfaces:**
- Consumes: `h.upsertPostureFindingsForRun(ctx, runID)` from Task 2.

- [ ] **Step 1: Write the failing test**

`orchestrator/internal/api/submit_scenario_result_test.go` already has
`TestSubmitScenarioResult_FindingsFireOnCompletedRun` (lines 512-538) proving the
BAS-findings hook fires through the real `SubmitScenarioResult` HTTP handler. Mirror
it exactly, swapping the technique-based step for a `CheckID`-based one (`scenario.Step`
has a real `CheckID string` field — confirmed via `internal/scenario/engine_test.go:655`,
`st.CheckID`) and asserting against `posture_findings` instead of `findings`. Reuses
this file's own `minimalLiveScenario`, `seedRunRow`, `submitResultOK` helpers (all
already defined in this file/package) and the same `ExitCode:0, Stdout:"FAIL: ..."`
convention the existing test already uses to force a FAIL verdict for a `custom`-framework
step. Append to `submit_scenario_result_test.go`:

```go
func TestSubmitScenarioResult_CreatesPostureFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", CheckID: "windows-firewall-enabled", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-pf-hook", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx
		agentID := "agent-pf-hook"
		seedRunRow(t, pool, "pf-hook-run", sc.ID, agentID, "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "pf-hook-run", ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("", "step-0"), ExitCode: 0, Stdout: "FAIL: disabled"}},
		})

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM posture_findings WHERE agent_id=$1 AND check_id='windows-firewall-enabled'`, agentID,
		).Scan(&count); err != nil {
			t.Fatalf("count posture_findings: %v", err)
		}
		if count == 0 {
			t.Fatal("expected a posture_findings row -- SubmitScenarioResult must call upsertPostureFindingsForRun")
		}
	})
}
```

Add the `"github.com/audspect/bas/internal/endpointrisk"` import to this file's existing
`import (...)` block if it isn't already imported there.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult_CreatesPostureFinding -v`
Expected: FAIL — `count=0`, since the hook isn't wired yet.

- [ ] **Step 3: Add the hook**

In `orchestrator/internal/api/handlers.go`, find this exact line (2362):

```go
	h.upsertFindingsForRun(r.Context(), raw.RunID)
```

Change it to:

```go
	h.upsertFindingsForRun(r.Context(), raw.RunID)
	h.upsertPostureFindingsForRun(r.Context(), raw.RunID)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult_CreatesPostureFinding -v`
Expected: PASS.

- [ ] **Step 5: Run the full submit_scenario_result_test.go suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult -v`
Expected: PASS, all pre-existing tests in that file still green (this hook is purely additive alongside the existing `upsertFindingsForRun` call).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/submit_scenario_result_test.go
git commit -m "feat(api): wire posture finding ingest into SubmitScenarioResult"
git push
```

---

### Task 4: Read endpoints

**Files:**
- Modify: `orchestrator/internal/api/posture_finding_handlers.go` (append the scan helper and two handlers)
- Modify: `orchestrator/internal/api/posture_finding_handlers_test.go` (append handler tests)
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `postureFindingCols`/`scanPostureFindings` (this task's own new code, defined in Step 3 below, used by both handlers). `findingScanner` interface (already defined in `finding_handlers.go:188-191`, same package — do not redefine).
- Produces: `func (h *Handler) ListAgentPostureFindings(w http.ResponseWriter, r *http.Request)` — `GET /api/agents/{agentId}/posture-findings`. `func (h *Handler) GetPostureFinding(w http.ResponseWriter, r *http.Request)` — `GET /api/posture-findings/{id}`.

- [ ] **Step 1: Write the failing tests**

Uses the same real `withURLParam(httptest.NewRequest(...), key, val) *http.Request`
helper (`event_handlers_test.go:52`, same package, no import needed) that
`endpointrisk_handlers_test.go`'s `TestGetAgentRisk_UnknownAgent404` already uses for
exactly this shape of test. Append to `orchestrator/internal/api/posture_finding_handlers_test.go`
(add `"encoding/json"` and `"net/http/httptest"` to the file's import block):

```go
func TestListAgentPostureFindings_EmptyReturnsEmptyList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('agent-pf-empty', 'host-agent-pf-empty')`)

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "agent-pf-empty")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %d findings, want 0", len(got))
		}
	})
}

func TestListAgentPostureFindings_ReturnsOpenByDefaultAndAllOnFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		t1 := time.Now()
		t2 := t1.Add(time.Hour)
		seedPostureCheckRun(t, pool, "pf-list-1", "agent-pf-list", "fail", t1)
		h.upsertPostureFindingsForRun(context.Background(), "pf-list-1")
		seedPostureCheckRun(t, pool, "pf-list-2", "agent-pf-list", "pass", t2)
		h.upsertPostureFindingsForRun(context.Background(), "pf-list-2")
		// finding is now status=remediated

		reqOpen := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "agent-pf-list")
		wOpen := httptest.NewRecorder()
		h.ListAgentPostureFindings(wOpen, reqOpen)
		var openOnly []map[string]any
		if err := json.Unmarshal(wOpen.Body.Bytes(), &openOnly); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(openOnly) != 0 {
			t.Errorf("default (open-only) got %d, want 0 (finding is remediated)", len(openOnly))
		}

		reqAll := withURLParam(httptest.NewRequest(http.MethodGet, "/x?status=all", nil), "agentId", "agent-pf-list")
		wAll := httptest.NewRecorder()
		h.ListAgentPostureFindings(wAll, reqAll)
		var all []map[string]any
		if err := json.Unmarshal(wAll.Body.Bytes(), &all); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(all) != 1 {
			t.Fatalf("?status=all got %d, want 1", len(all))
		}
		if all[0]["checkId"] != "windows-firewall-enabled" {
			t.Errorf("checkId=%v, want windows-firewall-enabled", all[0]["checkId"])
		}
		if all[0]["status"] != "remediated" {
			t.Errorf("status=%v, want remediated", all[0]["status"])
		}
	})
}

func TestGetPostureFinding_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nonexistent-id")
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("status=%d, want 404", w.Code)
		}
	})
}

func TestGetPostureFinding_ReturnsFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "pf-get-1", "agent-pf-get", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "pf-get-1")

		var id string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='agent-pf-get' AND check_id='windows-firewall-enabled'`).Scan(&id)

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", id)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", w.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["checkId"] != "windows-firewall-enabled" {
			t.Errorf("checkId=%v, want windows-firewall-enabled", got["checkId"])
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestListAgentPostureFindings|TestGetPostureFinding" -v`
Expected: FAIL — compile error, `h.ListAgentPostureFindings`/`h.GetPostureFinding` undefined.

- [ ] **Step 3: Implement the scan helper and handlers**

Append to `orchestrator/internal/api/posture_finding_handlers.go`:

```go
const postureFindingCols = `id, agent_id, check_id, category, title, severity, status,
	occurrence_count, reopened_count, first_seen, last_seen, last_observed_at,
	COALESCE(last_run_id,''), resolved_at, resolved_reason`

func scanPostureFindings(rows findingScanner) []map[string]any {
	out := []map[string]any{}
	for rows.Next() {
		var id, agentID, checkID, category, title, severity, status, lastRunID string
		var occ, reopened int
		var firstSeen, lastSeen, lastObserved time.Time
		var resolvedAt *time.Time
		var resolvedReason *string
		if rows.Scan(&id, &agentID, &checkID, &category, &title, &severity, &status,
			&occ, &reopened, &firstSeen, &lastSeen, &lastObserved, &lastRunID, &resolvedAt, &resolvedReason) != nil {
			continue
		}
		m := map[string]any{
			"id": id, "agentId": agentID, "checkId": checkID, "category": category,
			"title": title, "severity": severity, "status": status,
			"occurrenceCount": occ, "reopenedCount": reopened,
			"firstSeen": firstSeen, "lastSeen": lastSeen, "lastObservedAt": lastObserved,
			"lastRunId": lastRunID,
		}
		if resolvedAt != nil {
			m["resolvedAt"] = *resolvedAt
		}
		if resolvedReason != nil {
			m["resolvedReason"] = *resolvedReason
		}
		out = append(out, m)
	}
	return out
}

// ListAgentPostureFindings returns one agent's posture findings, open-only by
// default (?status=all includes remediated). GET /api/agents/{agentId}/posture-findings
func (h *Handler) ListAgentPostureFindings(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	statusFilter := "open"
	if r.URL.Query().Get("status") == "all" {
		statusFilter = ""
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` FROM posture_findings
		  WHERE agent_id=$1 AND ($2='' OR status=$2)
		  ORDER BY last_seen DESC`,
		agentID, statusFilter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	respond(w, scanPostureFindings(rows))
}

// GetPostureFinding returns one posture finding by ID. GET /api/posture-findings/{id}
func (h *Handler) GetPostureFinding(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` FROM posture_findings WHERE id=$1`, chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list := scanPostureFindings(rows)
	rows.Close()
	if len(list) == 0 {
		jsonError(w, "posture finding not found", http.StatusNotFound)
		return
	}
	respond(w, list[0])
}
```

Add the two new imports this file now needs (`net/http`, `github.com/go-chi/chi/v5`) to the existing `import (...)` block at the top of `posture_finding_handlers.go`.

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, find the drift routes (around line 563-564):

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/checks/{checkId}/drift", h.GetControlDrift)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/drift-summary", h.GetAgentDriftSummary)
```

Add immediately after:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/posture-findings", h.ListAgentPostureFindings)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/posture-findings/{id}", h.GetPostureFinding)
```

- [ ] **Step 5: Add RBAC matrix rows**

In `orchestrator/internal/api/rbac_matrix_test.go`, find the initiatives rows (around line 333-339) and add two new rows immediately after the last one (line 339):

```go
	{http.MethodGet, "/api/agents/{agentId}/posture-findings", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/posture-findings/{id}", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestListAgentPostureFindings|TestGetPostureFinding|TestRBACMatrix_NoDrift" -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/posture_finding_handlers.go orchestrator/internal/api/posture_finding_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add posture finding read endpoints"
git push
```

---

### Task 5: Full-suite verification

**Files:** none (verification only)

**Interfaces:** none — this task consumes everything from Tasks 1-4 as a whole.

- [ ] **Step 1: Run the full internal/api package in isolation**

Run: `cd orchestrator && go test ./internal/api/... -v 2>&1 | tail -60`
Expected: PASS, zero `FAIL` lines. If `gopls.exe` is running and this produces `unexpected EOF`/connection errors, stop it first (`taskkill /F /IM gopls.exe` — safe, auto-restarts) and re-run.

- [ ] **Step 2: Run internal/findings and internal/endpointrisk in isolation**

Run: `cd orchestrator && go test ./internal/findings/... ./internal/endpointrisk/... -v`
Expected: PASS — confirms `findings.Apply` and the taxonomy package are untouched and still green (this plan never modifies either).

- [ ] **Step 3: Confirm no unrelated diff**

Run: `git status --porcelain orchestrator/internal/findings orchestrator/internal/endpointrisk orchestrator/wwwroot`
Expected: empty output — this sub-project is backend-only (no UI, no changes to the reused state machine or taxonomy packages), matching the spec's Scope section.

- [ ] **Step 4: Report completion**

No commit for this task (verification-only). Report the full-suite result to the user, then proceed to `superpowers:finishing-a-development-branch` if the user wants to formally close out the branch step (this repo builds directly on `main`, so that skill's "no worktree to clean up" path applies — see Global Constraints).
