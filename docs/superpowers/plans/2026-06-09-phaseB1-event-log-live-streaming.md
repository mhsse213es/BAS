# Phase B-1 — Event-Sourced Run Log + Live Streaming — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the server + UI a live, persisted view of a run as it executes, and make a run reconstructable after a crash — without touching scoring, reporting, or dispatch.

**Architecture:** The agent emits lifecycle events (run/step queued→started→terminal) over REST to a new `/api/scenarios/events` endpoint. The server persists them to an append-only `run_events` table, maintains denormalized counters on `scenario_runs` via an idempotent insert-and-count statement, and relays each batch to browsers over the existing WS hub. The final `/api/scenarios/result` POST stays authoritative; events are a best-effort live + resilience overlay (POST always wins, no merging).

**Tech Stack:** Go 1.22+, chi router, pgx/pgxpool (PostgreSQL), gorilla/websocket, vanilla JS dashboard.

**Spec:** `docs/superpowers/specs/2026-06-09-phaseB1-event-log-live-streaming-design.md`. Build order follows spec §12a: DB → ingest → summary → relay → emitter → negotiation → UI → tests.

**Conventions used throughout:**
- Run commands from the relevant module dir: `orchestrator/` for server, `agent/` for agent.
- DB-backed tests connect to `TEST_DATABASE_URL` and `t.Skip()` when it is unset, so CI without a database still passes. Locally: `export TEST_DATABASE_URL=postgres://bas:bas@localhost:5432/bas_test` (any reachable empty Postgres).
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Push after each commit (project rule): `git push origin main` (branch first if not already on a feature branch).

---

## File structure

**Create:**
- `orchestrator/internal/models/runevent.go` — `RunEvent` type (server-side decode shape) + `MsgRunEvent` is added to existing `schema.go`.
- `orchestrator/internal/api/event_handlers.go` — `SubmitRunEvents` (POST batch ingest), `ListRunEvents` (GET for reconnect), and the pure `buildRunEventMsg` relay builder.
- `orchestrator/internal/api/event_handlers_test.go` — DB-backed ingest/idempotency/out-of-order/summary tests + pure relay-builder test.
- `agent/events.go` — `RunEvent`, the bounded `eventEmitter`, and `eventForResult` verdict mapping.
- `agent/events_test.go` — emitter bounded-drop/flush/never-block + verdict-mapping tests.

**Modify:**
- `orchestrator/internal/db/postgres.go` — add `run_events` table + `scenario_runs` summary columns to `EnsureSchema`.
- `orchestrator/internal/models/schema.go` — add `MsgRunEvent` constant.
- `orchestrator/internal/api/routes.go` — register the two new routes.
- `orchestrator/internal/api/handlers.go` — `Heartbeat` persists agent `protocol_version`.
- `agent/types.go` — add `ProtocolVersion`/`EmitsEvents` to `Heartbeat`; `protocolVersion` const.
- `agent/agent.go` — construct the emitter, hook emit points in `runScenario`, advertise capability in `sendHeartbeat`.
- `orchestrator/wwwroot/index.html` — live run panel (WS subscribe + progress + timeline).

---

## Task 1: DB migration — `run_events` table + `scenario_runs` summary columns

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (the `stmts` slice inside `EnsureSchema`)
- Test: `orchestrator/internal/db/events_schema_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/db/events_schema_test.go`:

```go
package db

import (
	"context"
	"os"
	"testing"
)

func TestRunEventsSchemaCreated(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("ensure 1: %v", err)
	}
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("ensure 2 (idempotency): %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_name = 'run_events'`,
	).Scan(&n); err != nil || n != 1 {
		t.Fatalf("run_events table missing: n=%d err=%v", n, err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'scenario_runs' AND column_name = 'steps_running'`,
	).Scan(&n); err != nil || n != 1 {
		t.Fatalf("scenario_runs.steps_running missing: n=%d err=%v", n, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && TEST_DATABASE_URL=postgres://bas:bas@localhost:5432/bas_test go test ./internal/db/ -run TestRunEventsSchemaCreated -v`
Expected: FAIL — `run_events table missing` (table not created yet). If `TEST_DATABASE_URL` is unset it SKIPs; set it to actually drive the task.

- [ ] **Step 3: Add the migration statements**

In `orchestrator/internal/db/postgres.go`, inside `EnsureSchema`'s `stmts := []string{ ... }` slice, after the existing `scenario_runs` block and its `ALTER TABLE` lines (around line 88), add:

```go
		// ── Phase B-1: run-event stream + denormalized progress summary ───────
		`CREATE TABLE IF NOT EXISTS run_events (
			run_id       text        NOT NULL,
			seq          bigint      NOT NULL,
			type         text        NOT NULL,
			task_id      text        NOT NULL DEFAULT '',
			technique_id text        NOT NULL DEFAULT '',
			ts           timestamptz NOT NULL,
			payload      jsonb       NOT NULL DEFAULT '{}',
			PRIMARY KEY (run_id, seq)
		)`,

		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_total   int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_done    int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_running int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_passed  int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_failed  int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_timeout int NOT NULL DEFAULT 0`,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && TEST_DATABASE_URL=postgres://bas:bas@localhost:5432/bas_test go test ./internal/db/ -run TestRunEventsSchemaCreated -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/db/events_schema_test.go
git commit -m "feat(db): run_events table + scenario_runs progress summary columns

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 2: `RunEvent` model + `MsgRunEvent` constant (server)

**Files:**
- Create: `orchestrator/internal/models/runevent.go`
- Modify: `orchestrator/internal/models/schema.go:177` (add constant)
- Test: `orchestrator/internal/models/runevent_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/models/runevent_test.go`:

```go
package models

import (
	"encoding/json"
	"testing"
)

func TestRunEventJSONContract(t *testing.T) {
	const in = `{"runId":"r1","seq":7,"type":"completed","taskId":"a1","techniqueId":"T1057","ts":"2026-06-09T16:40:12.512Z","payload":{"verdict":"pass","durationMs":532,"exitCode":0}}`
	var e RunEvent
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.RunID != "r1" || e.Seq != 7 || e.Type != "completed" || e.TaskID != "a1" || e.TechniqueID != "T1057" {
		t.Fatalf("decoded wrong: %+v", e)
	}
	if v, _ := e.Payload["verdict"].(string); v != "pass" {
		t.Fatalf("payload verdict = %v", e.Payload["verdict"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/models/ -run TestRunEventJSONContract -v`
Expected: FAIL — `undefined: RunEvent`.

- [ ] **Step 3: Add the type and constant**

Create `orchestrator/internal/models/runevent.go`:

```go
package models

import "time"

// RunEvent is one lifecycle event in a run's append-only stream. Type is one of:
// run_started, queued, started, completed, timeout, killed, run_completed,
// run_cancelled. Run-level events leave TaskID/TechniqueID empty. Payload carries
// type-specific fields (verdict/durationMs/exitCode/reason/stepsTotal) and is
// stored opaquely so the schema never needs migrating for new fields.
type RunEvent struct {
	RunID       string                 `json:"runId"`
	Seq         int64                  `json:"seq"`
	Type        string                 `json:"type"`
	TaskID      string                 `json:"taskId,omitempty"`
	TechniqueID string                 `json:"techniqueId,omitempty"`
	Ts          time.Time              `json:"ts"`
	Payload     map[string]any         `json:"payload,omitempty"`
}
```

In `orchestrator/internal/models/schema.go`, add to the const block (after `MsgPolicyUpdate`, line 177):

```go
	MsgRunEvent        = "run_event"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/models/ -run TestRunEventJSONContract -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/models/runevent.go orchestrator/internal/models/schema.go orchestrator/internal/models/runevent_test.go
git commit -m "feat(models): RunEvent type + run_event WS message constant

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 3: Ingest endpoint — idempotent insert + summary + GET for reconnect

**Files:**
- Create: `orchestrator/internal/api/event_handlers.go`
- Modify: `orchestrator/internal/api/routes.go` (register routes)
- Test: `orchestrator/internal/api/event_handlers_test.go` (create)

This task implements spec §5.1 (idempotent insert tied to a successful `ON CONFLICT DO NOTHING`), §7 (batch ingest + GET reconnect). Relay to browsers is added in Task 4.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/event_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func eventsTestHandler(t *testing.T) (*Handler, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("schema: %v", err)
	}
	h := New(pool, ws.NewHub(), nil, "")
	return h, pool
}

// seedRun inserts a minimal agent + scenario_runs row so FK-free inserts and the
// summary UPDATE have a row to target.
func seedRun(t *testing.T, pool *pgxpool.Pool, runID string) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ($1,$1)
		ON CONFLICT (agent_id) DO NOTHING`, "agent-x")
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status)
		 VALUES ($1,'sc','agent-x','t','running')`, runID); err != nil {
		t.Fatalf("seed run: %v", err)
	}
}

func postEvents(t *testing.T, h *Handler, evs []map[string]any) {
	t.Helper()
	body, _ := json.Marshal(evs)
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/events", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.SubmitRunEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func summary(t *testing.T, pool *pgxpool.Pool, runID string) (total, done, running, passed, failed, timeout int) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout
		 FROM scenario_runs WHERE id = $1`, runID).
		Scan(&total, &done, &running, &passed, &failed, &timeout)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	return
}

func TestSubmitRunEventsSummaryAndIdempotency(t *testing.T) {
	h, pool := eventsTestHandler(t)
	defer pool.Close()
	runID := "run-sum-1"
	seedRun(t, pool, runID)

	ev := func(seq int, typ string, payload map[string]any) map[string]any {
		return map[string]any{"runId": runID, "seq": seq, "type": typ,
			"ts": "2026-06-09T16:40:12Z", "payload": payload}
	}
	postEvents(t, h, []map[string]any{
		ev(1, "run_started", map[string]any{"stepsTotal": 3}),
		ev(2, "started", nil),
		ev(3, "completed", map[string]any{"verdict": "pass"}),
		ev(4, "started", nil),
		ev(5, "timeout", map[string]any{"reason": "execute"}),
	})

	total, done, running, passed, failed, timeout := summary(t, pool, runID)
	if total != 3 || done != 2 || running != 0 || passed != 1 || failed != 0 || timeout != 1 {
		t.Fatalf("after first batch: total=%d done=%d running=%d passed=%d failed=%d timeout=%d",
			total, done, running, passed, failed, timeout)
	}

	// Replay the same batch: ON CONFLICT DO NOTHING means counters must NOT move.
	postEvents(t, h, []map[string]any{
		ev(3, "completed", map[string]any{"verdict": "pass"}),
		ev(5, "timeout", map[string]any{"reason": "execute"}),
	})
	total2, done2, _, passed2, _, timeout2 := summary(t, pool, runID)
	if total2 != 3 || done2 != 2 || passed2 != 1 || timeout2 != 1 {
		t.Fatalf("after replay (must be unchanged): total=%d done=%d passed=%d timeout=%d",
			total2, done2, passed2, timeout2)
	}
}

func TestSubmitRunEventsRunningCount(t *testing.T) {
	h, pool := eventsTestHandler(t)
	defer pool.Close()
	runID := "run-running-1"
	seedRun(t, pool, runID)
	ev := func(seq int, typ string) map[string]any {
		return map[string]any{"runId": runID, "seq": seq, "type": typ, "ts": "2026-06-09T16:40:12Z"}
	}
	// two starts, one completion -> running should be 1
	postEvents(t, h, []map[string]any{ev(1, "started"), ev(2, "started")})
	if _, _, running, _, _, _ := summary(t, pool, runID); running != 2 {
		t.Fatalf("running after 2 starts = %d, want 2", running)
	}
	postEvents(t, h, []map[string]any{{"runId": runID, "seq": 3, "type": "completed", "ts": "2026-06-09T16:40:12Z", "payload": map[string]any{"verdict": "pass"}}})
	if _, _, running, _, _, _ := summary(t, pool, runID); running != 1 {
		t.Fatalf("running after 1 completion = %d, want 1", running)
	}
}

func TestListRunEventsOrderedBySeq(t *testing.T) {
	h, pool := eventsTestHandler(t)
	defer pool.Close()
	runID := "run-order-1"
	seedRun(t, pool, runID)
	ev := func(seq int) map[string]any {
		return map[string]any{"runId": runID, "seq": seq, "type": "started", "ts": "2026-06-09T16:40:12Z"}
	}
	// deliver out of order: 12, 11, 13
	postEvents(t, h, []map[string]any{ev(12), ev(11), ev(13)})

	req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/events", nil)
	req = withURLParam(req, "runId", runID)
	rec := httptest.NewRecorder()
	h.ListRunEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	seqs := []float64{got[0]["seq"].(float64), got[1]["seq"].(float64), got[2]["seq"].(float64)}
	if seqs[0] != 11 || seqs[1] != 12 || seqs[2] != 13 {
		t.Fatalf("events not ordered by seq: %v", seqs)
	}
}
```

Add the chi URL-param helper at the bottom of the same test file:

```go
import "github.com/go-chi/chi/v5"

func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
```

(Place the extra `import` in the file's import block; do not duplicate it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && TEST_DATABASE_URL=postgres://bas:bas@localhost:5432/bas_test go test ./internal/api/ -run 'SubmitRunEvents|ListRunEvents' -v`
Expected: FAIL — `h.SubmitRunEvents undefined` (compile error).

- [ ] **Step 3: Implement the handlers**

Create `orchestrator/internal/api/event_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)

// SubmitRunEvents ingests a batch of run lifecycle events from an agent. Each
// event is inserted idempotently by (run_id, seq); the run's denormalized
// progress summary is updated ONLY for events that were actually inserted, so a
// network retry of the same seq can never double-count. Best-effort overlay: the
// authoritative results still arrive via /api/scenarios/result.
func (h *Handler) SubmitRunEvents(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch []models.RunEvent
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		jsonError(w, "invalid events payload — expected a JSON array of events", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	for _, e := range batch {
		if e.RunID == "" || e.Type == "" {
			continue
		}
		payload, _ := json.Marshal(e.Payload)
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		// Insert-or-skip, then move counters only when the row was newly inserted.
		_, _ = h.db.Exec(ctx, `
			WITH ins AS (
				INSERT INTO run_events (run_id, seq, type, task_id, technique_id, ts, payload)
				VALUES ($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (run_id, seq) DO NOTHING
				RETURNING type, payload
			)
			UPDATE scenario_runs s SET
				steps_total   = CASE WHEN ins.type='run_started'
				                     THEN COALESCE((ins.payload->>'stepsTotal')::int, s.steps_total)
				                     ELSE s.steps_total END,
				steps_running = s.steps_running
				                + CASE WHEN ins.type='started' THEN 1 ELSE 0 END
				                - CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
				steps_done    = s.steps_done    + CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
				steps_passed  = s.steps_passed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict'='pass' THEN 1 ELSE 0 END,
				steps_failed  = s.steps_failed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict' IN ('fail','blocked') THEN 1 ELSE 0 END,
				steps_timeout = s.steps_timeout + CASE WHEN ins.type='timeout' THEN 1 ELSE 0 END
			FROM ins
			WHERE s.id = $1`,
			e.RunID, e.Seq, e.Type, e.TaskID, e.TechniqueID, e.Ts, payload)
	}

	// Relay to browsers (added in Task 4).
	h.relayRunEvents(batch)

	w.WriteHeader(http.StatusOK)
}

// relayRunEvents is a stub until Task 4 wires the browser broadcast.
func (h *Handler) relayRunEvents(_ []models.RunEvent) {}

// ListRunEvents returns a run's events ordered by seq (for browser reconnect /
// timeline reconstruction). JWT-protected (registered under the auth group).
func (h *Handler) ListRunEvents(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	rows, err := h.db.Query(r.Context(),
		`SELECT seq, type, task_id, technique_id, ts, payload
		 FROM run_events WHERE run_id = $1 ORDER BY seq ASC`, runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := make([]models.RunEvent, 0)
	for rows.Next() {
		var e models.RunEvent
		var payload []byte
		if err := rows.Scan(&e.Seq, &e.Type, &e.TaskID, &e.TechniqueID, &e.Ts, &payload); err != nil {
			continue
		}
		_ = json.Unmarshal(payload, &e.Payload)
		e.RunID = runID
		out = append(out, e)
	}
	respond(w, out)
}
```

In `orchestrator/internal/api/routes.go`, register the POST in the agent-endpoints block (after line 32, `/api/scenarios/result`):

```go
	r.Post("/api/scenarios/events", h.SubmitRunEvents)
```

And register the GET in the authenticated group, next to the other run reads (after line 83, `ExportRunJSON`):

```go
			r.Get("/api/scenarios/runs/{runId}/events", h.ListRunEvents)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && TEST_DATABASE_URL=postgres://bas:bas@localhost:5432/bas_test go test ./internal/api/ -run 'SubmitRunEvents|ListRunEvents' -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/event_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/event_handlers_test.go
git commit -m "feat(api): /api/scenarios/events batch ingest with idempotent progress summary + GET reconnect

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 4: Relay events to browsers over WS

**Files:**
- Modify: `orchestrator/internal/api/event_handlers.go` (replace the `relayRunEvents` stub + add a pure builder)
- Test: `orchestrator/internal/api/event_handlers_test.go` (add a pure test — no DB needed)

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/event_handlers_test.go`:

```go
func TestBuildRunEventMsg(t *testing.T) {
	batch := []models.RunEvent{
		{RunID: "r9", Seq: 1, Type: "started", TaskID: "a1"},
		{RunID: "r9", Seq: 2, Type: "completed", TaskID: "a1"},
	}
	msg := buildRunEventMsg(batch)
	if msg.Type != models.MsgRunEvent {
		t.Fatalf("type = %q, want %q", msg.Type, models.MsgRunEvent)
	}
	data, ok := msg.Data.(map[string]any)
	if !ok {
		t.Fatalf("data not a map: %T", msg.Data)
	}
	if data["runId"] != "r9" {
		t.Fatalf("runId = %v", data["runId"])
	}
	evs, ok := data["events"].([]models.RunEvent)
	if !ok || len(evs) != 2 {
		t.Fatalf("events = %v", data["events"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestBuildRunEventMsg -v`
Expected: FAIL — `undefined: buildRunEventMsg`.

- [ ] **Step 3: Implement the builder + real relay**

In `orchestrator/internal/api/event_handlers.go`, replace the `relayRunEvents` stub with:

```go
// buildRunEventMsg packages a batch into a browser WS frame. Pure (testable
// without a hub). Browsers reconcile against GET /events on (re)connect, so a
// dropped frame is harmless.
func buildRunEventMsg(batch []models.RunEvent) models.WSMessage {
	runID := ""
	if len(batch) > 0 {
		runID = batch[0].RunID
	}
	return models.WSMessage{
		Type: models.MsgRunEvent,
		Data: map[string]any{"runId": runID, "events": batch},
	}
}

// relayRunEvents pushes the batch to all connected browsers (best-effort).
func (h *Handler) relayRunEvents(batch []models.RunEvent) {
	if len(batch) == 0 {
		return
	}
	h.hub.BroadcastBrowsers(buildRunEventMsg(batch))
}
```

(Remove the old stub `func (h *Handler) relayRunEvents(_ []models.RunEvent) {}`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestBuildRunEventMsg -v`
Expected: PASS. Also run the full package build: `cd orchestrator && go build ./...` → no output.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/event_handlers.go orchestrator/internal/api/event_handlers_test.go
git commit -m "feat(api): relay run-event batches to browsers over the WS hub

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 5: Agent — `RunEvent` type, bounded emitter, verdict mapping

**Files:**
- Create: `agent/events.go`
- Test: `agent/events_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `agent/events_test.go`:

```go
package main

import (
	"sync"
	"testing"
	"time"
)

func TestEventForResult(t *testing.T) {
	cases := []struct {
		name    string
		res     ExecResult
		typ     string
		verdict string
	}{
		{"pass", ExecResult{ExitCode: 0}, "completed", "pass"},
		{"fail", ExecResult{ExitCode: 1}, "completed", "fail"},
		{"blocked", ExecResult{ExitCode: -1, Blocked: true}, "completed", "blocked"},
		{"timeout", ExecResult{ExitCode: -1, TimedOut: true}, "timeout", ""},
	}
	for _, c := range cases {
		typ, verdict := eventForResult(c.res)
		if typ != c.typ || verdict != c.verdict {
			t.Errorf("%s: got (%q,%q) want (%q,%q)", c.name, typ, verdict, c.typ, c.verdict)
		}
	}
}

// fakeSender records flushed batches.
type fakeSender struct {
	mu      sync.Mutex
	batches [][]RunEvent
	fail    bool
}

func (f *fakeSender) send(b []RunEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errFakeSend
	}
	cp := make([]RunEvent, len(b))
	copy(cp, b)
	f.batches = append(f.batches, cp)
	return nil
}
func (f *fakeSender) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

var errFakeSend = errFake("send failed")

type errFake string

func (e errFake) Error() string { return string(e) }

func TestEmitterFlushesAndDelivers(t *testing.T) {
	fs := &fakeSender{}
	em := newEventEmitter(fs.send, 100, 10*time.Millisecond)
	for i := 0; i < 5; i++ {
		em.emit(RunEvent{Type: "started", Seq: int64(i)})
	}
	em.close() // flushes remaining and stops
	if fs.total() != 5 {
		t.Fatalf("delivered %d events, want 5", fs.total())
	}
}

func TestEmitterBoundedDropsAndNeverBlocks(t *testing.T) {
	fs := &fakeSender{fail: true} // server "down": nothing drains successfully
	em := newEventEmitter(fs.send, 50, time.Hour) // huge flush interval; rely on close
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100000; i++ { // far exceeds maxQueue
			em.emit(RunEvent{Type: "started", Seq: int64(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("emit blocked — bounded queue must drop, never block the run")
	}
	em.close()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run 'EventForResult|Emitter' -v`
Expected: FAIL — `undefined: eventForResult` / `newEventEmitter`.

- [ ] **Step 3: Implement the emitter**

Create `agent/events.go`:

```go
package main

import (
	"log"
	"sync"
	"time"
)

// RunEvent mirrors the server's models.RunEvent wire shape.
type RunEvent struct {
	RunID       string         `json:"runId"`
	Seq         int64          `json:"seq"`
	Type        string         `json:"type"`
	TaskID      string         `json:"taskId,omitempty"`
	TechniqueID string         `json:"techniqueId,omitempty"`
	Ts          time.Time      `json:"ts"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// eventForResult derives the terminal event type and verdict from a step result.
// Timeout takes priority (an explicit "ran, did not return" verdict); a security
// block is a completed step with verdict "blocked"; otherwise pass/fail by exit.
func eventForResult(r ExecResult) (typ, verdict string) {
	if r.TimedOut {
		return "timeout", ""
	}
	if r.Blocked {
		return "completed", "blocked"
	}
	if r.ExitCode == 0 {
		return "completed", "pass"
	}
	return "completed", "fail"
}

// eventEmitter buffers RunEvents on a bounded channel and flushes them to the
// server in batches. Emitting never blocks the run: if the queue is full (server
// unreachable), the oldest event is dropped and a throttled warning is logged.
type eventEmitter struct {
	send      func([]RunEvent) error
	queue     chan RunEvent
	maxBatch  int
	interval  time.Duration
	done      chan struct{}
	wg        sync.WaitGroup
	dropMu    sync.Mutex
	dropped   int
	lastDropL time.Time
}

func newEventEmitter(send func([]RunEvent) error, maxQueue int, interval time.Duration) *eventEmitter {
	if maxQueue < 1 {
		maxQueue = 1000
	}
	e := &eventEmitter{
		send:     send,
		queue:    make(chan RunEvent, maxQueue),
		maxBatch: 64,
		interval: interval,
		done:     make(chan struct{}),
	}
	e.wg.Add(1)
	go e.loop()
	return e
}

// emit enqueues an event without ever blocking. On a full queue it drops the
// OLDEST event (to keep the most recent state) and counts the drop.
func (e *eventEmitter) emit(ev RunEvent) {
	if ev.Ts.IsZero() {
		ev.Ts = time.Now()
	}
	for {
		select {
		case e.queue <- ev:
			return
		default:
			select {
			case <-e.queue: // drop oldest, make room
				e.noteDrop()
			default:
			}
		}
	}
}

func (e *eventEmitter) noteDrop() {
	e.dropMu.Lock()
	e.dropped++
	if time.Since(e.lastDropL) > 5*time.Second {
		log.Printf("[events] queue full — dropped %d event(s) (server unreachable?)", e.dropped)
		e.dropped = 0
		e.lastDropL = time.Now()
	}
	e.dropMu.Unlock()
}

func (e *eventEmitter) loop() {
	defer e.wg.Done()
	t := time.NewTicker(e.interval)
	defer t.Stop()
	batch := make([]RunEvent, 0, e.maxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = e.send(batch) // best-effort; drop on failure
		batch = batch[:0]
	}
	for {
		select {
		case <-e.done:
			// drain whatever is queued, then flush and exit
			for {
				select {
				case ev := <-e.queue:
					batch = append(batch, ev)
					if len(batch) >= e.maxBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= e.maxBatch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// close flushes remaining events and stops the loop.
func (e *eventEmitter) close() {
	close(e.done)
	e.wg.Wait()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test . -run 'EventForResult|Emitter' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/events.go agent/events_test.go
git commit -m "feat(agent): bounded run-event emitter + verdict mapping

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 6: Agent — hook emit points into `runScenario`

**Files:**
- Modify: `agent/agent.go` (`runScenario`: construct emitter, emit run/step events)
- Test: covered by Task 5 unit tests + Task 9 demos (the hook is glue verified at integration; no new unit test, but `go build` and `go vet` must pass).

This wires the emitter into the existing run loop. The scheduler already drives queued/started/completed transitions; we emit alongside them. Use a single per-run atomic `seq` counter.

- [ ] **Step 1: Add the seq counter + emitter construction**

In `agent/agent.go`, inside `runScenario`, just after `workers` is resolved and before the pool block (near line 261), add:

```go
	// Phase B-1: best-effort live event stream. nextSeq is the per-run monotonic
	// sequence; emit() never blocks the run.
	var nextSeq int64
	seq := func() int64 { return atomic.AddInt64(&nextSeq, 1) }
	emitter := newEventEmitter(
		func(b []RunEvent) error { return a.postJSON("/api/scenarios/events", b) },
		1000, 300*time.Millisecond,
	)
	defer emitter.close()
	emit := func(ev RunEvent) { ev.RunID = cmd.RunID; ev.Seq = seq(); emitter.emit(ev) }

	emit(RunEvent{Type: "run_started", Payload: map[string]any{"stepsTotal": total, "mode": cmd.Mode}})
```

(`atomic` and `time` are already imported in `agent.go`.)

- [ ] **Step 2: Emit `queued` for every step, then `started`/terminal inside the job**

In the `for i := range cmd.Steps` loop where `jobs[i]` is built, immediately before assigning `jobs[i] = sched.Job{...}`, add:

```go
		emit(RunEvent{Type: "queued", TaskID: step.TaskID, TechniqueID: step.TechniqueID})
```

Inside the job's `Run` closure, right after the existing progress/log lines at the top (after `a.localSt.UpdateProgress(...)`), add:

```go
				emit(RunEvent{Type: "started", TaskID: step.TaskID, TechniqueID: step.TechniqueID})
```

At the **end** of the `Run` closure, where it currently sets `results[i] = r; ran[i] = true`, add the terminal event right after:

```go
				typ, verdict := eventForResult(r)
				payload := map[string]any{"durationMs": r.DurationMs, "exitCode": r.ExitCode}
				if verdict != "" {
					payload["verdict"] = verdict
				}
				if typ == "timeout" {
					payload["reason"] = "execute"
				}
				emit(RunEvent{Type: typ, TaskID: step.TaskID, TechniqueID: step.TechniqueID, Payload: payload})
```

Also, in the early-return quarantine branch inside the closure (`results[i] = ExecResult{... Blocked ...}; ran[i] = true; return`), add before the `return`:

```go
				emit(RunEvent{Type: "completed", TaskID: step.TaskID, TechniqueID: step.TechniqueID,
					Payload: map[string]any{"verdict": "blocked"}})
```

And in the `OnScheduleTimeout` closure added in Phase A (which sets a TimedOut result), add after `ran[i] = true`:

```go
				emit(RunEvent{Type: "timeout", TaskID: step.TaskID, TechniqueID: step.TechniqueID,
					Payload: map[string]any{"reason": "schedule"}})
```

- [ ] **Step 3: Emit the run terminal event**

After `sched.Run(...)` returns and `partial` is computed (near line 329, before `revertFromSnapshot`), add:

```go
	if partial {
		emit(RunEvent{Type: "run_cancelled", Payload: map[string]any{"stepsDone": len(final)}})
	} else {
		emit(RunEvent{Type: "run_completed", Payload: map[string]any{"stepsDone": len(final), "partial": false}})
	}
```

- [ ] **Step 4: Build + vet (both platforms)**

Run:
```
cd agent && go build ./... && GOOS=linux go build ./... && go vet ./... && go test . -count=1
```
Expected: builds clean for windows + linux; vet clean (the pre-existing `dismiss_windows.go:118` unsafe.Pointer note is unrelated); existing + Task 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add agent/agent.go
git commit -m "feat(agent): emit run/step lifecycle events from runScenario

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 7: Capability negotiation — advertise + persist

**Files:**
- Modify: `agent/types.go` (Heartbeat fields + `protocolVersion` const)
- Modify: `agent/agent.go` (`sendHeartbeat` sets the fields)
- Modify: `orchestrator/internal/db/postgres.go` (agents column)
- Modify: `orchestrator/internal/api/handlers.go` (`Heartbeat` persists it)
- Test: `agent/events_test.go` (add a heartbeat-shape test)

- [ ] **Step 1: Write the failing test**

Add to `agent/events_test.go`:

```go
import "encoding/json"

func TestHeartbeatAdvertisesCapability(t *testing.T) {
	hb := Heartbeat{AgentID: "a", ProtocolVersion: protocolVersion, EmitsEvents: true}
	raw, _ := json.Marshal(hb)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["protocolVersion"] != float64(2) {
		t.Errorf("protocolVersion = %v, want 2", m["protocolVersion"])
	}
	if m["emitsEvents"] != true {
		t.Errorf("emitsEvents = %v, want true", m["emitsEvents"])
	}
}
```

(Add `encoding/json` to the test file's imports if not already present.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestHeartbeatAdvertisesCapability -v`
Expected: FAIL — `unknown field ProtocolVersion` / `undefined: protocolVersion`.

- [ ] **Step 3: Add the fields + constant + advertise + persist**

In `agent/types.go`, add the const near `schemaVersion` (line 13):

```go
// protocolVersion advertises the agent's run-protocol capabilities to the server.
// 2 = emits run-event stream (Phase B-1).
const protocolVersion = 2
```

In the `Heartbeat` struct (after `SchemaVersion int`):

```go
	ProtocolVersion int  `json:"protocolVersion,omitempty"`
	EmitsEvents     bool `json:"emitsEvents,omitempty"`
```

In `agent/agent.go` `sendHeartbeat`, in the `Heartbeat{...}` literal, add:

```go
		ProtocolVersion: protocolVersion,
		EmitsEvents:     true,
```

In `orchestrator/internal/db/postgres.go` `EnsureSchema` stmts, after the agents table block, add:

```go
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS protocol_version int NOT NULL DEFAULT 1`,
```

In `orchestrator/internal/api/handlers.go` `Heartbeat`, the handler decodes a heartbeat into a struct and upserts the agent. Add `ProtocolVersion int json:"protocolVersion"` to that decode struct, and include it in the agents UPSERT (the `INSERT ... ON CONFLICT ... DO UPDATE` near line 312): add `protocol_version` to the column list/values and `protocol_version = EXCLUDED.protocol_version` to the update set. (Match the existing column/placeholder pattern in that statement.)

- [ ] **Step 4: Run test + build**

Run:
```
cd agent && go test . -run TestHeartbeatAdvertisesCapability -v && go build ./...
cd ../orchestrator && go build ./...
```
Expected: PASS; both build clean.

- [ ] **Step 5: Commit**

```bash
git add agent/types.go agent/agent.go agent/events_test.go orchestrator/internal/db/postgres.go orchestrator/internal/api/handlers.go
git commit -m "feat: advertise + persist agent protocolVersion/emitsEvents capability

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 8: Live UI — run panel (progress + timeline)

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (add a run panel module + a hook from the existing run row)

The panel: on open, fetch persisted events (reconnect-safe), then subscribe to the browser WS for live `run_event` frames; render counts (`done/total`, `failed`, `running`) and a per-step state list. Verified manually via Task 9 demos.

- [ ] **Step 1: Add the panel script**

In `orchestrator/wwwroot/index.html`, before the closing `</body>`, add a `<script>` block (or append to the existing app script):

```html
<div id="runPanel" style="display:none">
  <div id="runProgress"></div>
  <ul id="runTimeline"></ul>
</div>
<script>
(function () {
  const state = { runId: null, steps: new Map(), total: 0, done: 0, failed: 0, running: 0 };

  function render() {
    document.getElementById('runProgress').textContent =
      `${state.done}/${state.total} · ${state.failed} failed · ${state.running} running`;
    const ul = document.getElementById('runTimeline');
    ul.innerHTML = '';
    [...state.steps.entries()].forEach(([task, s]) => {
      const li = document.createElement('li');
      li.textContent = `${s.tech || task}: ${s.state}${s.verdict ? ' (' + s.verdict + ')' : ''}`;
      ul.appendChild(li);
    });
  }

  function applyEvent(e) {
    if (e.type === 'run_started') { state.total = (e.payload && e.payload.stepsTotal) || state.total; }
    else if (e.type === 'queued')  { state.steps.set(e.taskId, { tech: e.techniqueId, state: 'queued' }); }
    else if (e.type === 'started') { const s = state.steps.get(e.taskId) || {}; s.tech = e.techniqueId; s.state = 'running'; state.steps.set(e.taskId, s); }
    else if (e.type === 'completed' || e.type === 'timeout' || e.type === 'killed') {
      const s = state.steps.get(e.taskId) || {}; s.tech = e.techniqueId;
      s.state = e.type === 'completed' ? 'done' : e.type;
      s.verdict = e.payload && (e.payload.verdict || e.payload.reason);
      state.steps.set(e.taskId, s);
    }
    // Counters are authoritative from the server summary if present; here we
    // recompute from the step map so reconnect (full replay) stays correct.
    let done = 0, failed = 0, running = 0;
    for (const s of state.steps.values()) {
      if (s.state === 'done' || s.state === 'timeout' || s.state === 'killed') done++;
      if (s.verdict === 'fail' || s.verdict === 'blocked' || s.state === 'timeout') failed++;
      if (s.state === 'running') running++;
    }
    state.done = done; state.failed = failed; state.running = running;
  }

  // Called from the existing run-row click handler.
  window.openRunPanel = async function (runId) {
    state.runId = runId; state.steps = new Map(); state.total = 0;
    document.getElementById('runPanel').style.display = 'block';
    // Reconnect-safe: load persisted events first (ordered by seq server-side).
    try {
      const r = await fetch(`/api/scenarios/runs/${runId}/events`, { credentials: 'include' });
      if (r.ok) (await r.json()).forEach(applyEvent);
    } catch (_) {}
    render();
  };

  // Hook the shared browser WS. If the app already has a WS, call window.onRunEvent
  // from its message handler instead of opening a second socket.
  window.onRunEvent = function (msg) {
    if (!msg || msg.type !== 'run_event' || !msg.data) return;
    if (msg.data.runId !== state.runId) return;
    (msg.data.events || []).forEach(applyEvent);
    render();
  };
})();
</script>
```

- [ ] **Step 2: Wire the hooks into the existing app**

Find the existing browser-WS `onmessage` handler in `index.html` (it already dispatches messages like `scenario_result`/`agentUpdate`). Add a branch:

```js
if (msg.type === 'run_event') { window.onRunEvent(msg); return; }
```

Find the existing run-list row rendering (where a run is clickable to view its report) and add to the click handler:

```js
window.openRunPanel(run.id);
```

- [ ] **Step 3: Manual smoke check**

Run the server locally (or on the dev VM) with a connected agent, start a scenario, and confirm `/runProgress` updates and the timeline lists steps transitioning queued→running→done. (Full acceptance is Task 9.)

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): live run panel — progress (done/total, failed, running) + step timeline

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin main
```

---

## Task 9: Acceptance demos (spec §12b)

**Files:** none (verification). Run against a deployed server + agent (dev VM). Record results in the PR description.

- [ ] **Demo 1 — Live progress:** start a normal scenario; confirm the run panel shows `queued → started → completed` transitions live and counts advance.
- [ ] **Demo 2 — Browser reconnect:** mid-run, reload the dashboard tab; confirm the timeline reconstructs from `GET /api/scenarios/runs/{runId}/events` (state matches pre-reload).
- [ ] **Demo 3 — Agent crash mid-run:** kill the agent partway; confirm previously completed steps remain visible and counted (query `SELECT type,count(*) FROM run_events WHERE run_id=$1 GROUP BY type`).
- [ ] **Demo 4 — Duplicate replay:** re-POST a captured event batch to `/api/scenarios/events`; confirm `scenario_runs` counters are unchanged (idempotent). Example:
  ```bash
  curl -s -X POST "$SERVER/api/scenarios/events" -H "X-Agent-Token: $AGENT_SECRET" \
    -H "Content-Type: application/json" -d @batch.json
  # then re-run the same curl; counts must not change
  ```
- [ ] **Demo 5 — Legacy agent:** run a scenario with an agent build that does NOT emit events (pre-B-1 binary); confirm the run still completes and scores correctly via the final POST, with no live timeline.
- [ ] **Demo 6 — Full ART sweep timing (Phase A regression check):** run the `art-full-windows` scenario end-to-end against one endpoint and record wall-clock + completion. This is the original "1210 steps, only ~10 finished, very slow" problem; confirm it is closed *with a number*, not just "feels faster".
  - **Completeness:** the run reaches `completed` (not `partial`) and `steps_done == steps_total`. Verify no truncation:
    ```bash
    psql "$DATABASE_URL" -c "SELECT status, steps_total, steps_done, steps_failed, steps_timeout FROM scenario_runs WHERE id='<runId>';"
    ```
    Expect `status=completed` and `steps_done = steps_total` (one representative atomic per technique, ~full ATT&CK breadth — NOT 1210).
  - **Concurrency guard:** while the sweep is running, POST a second run to the same agent and confirm **409** (the in-flight sweep is not cancelled/truncated):
    ```bash
    curl -s -o /dev/null -w '%{http_code}\n' -X POST "$SERVER/api/scenarios/art-full-windows/run" \
      -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
      -d '{"agentId":"<agentId>"}'   # expect 409 while the sweep is still running
    ```
  - **Wall-clock:** capture start→finish from the run row (`startedAt`/`completedAt`) and record minutes in the PR. If a pre-Phase-A baseline run exists, note the before/after; otherwise this run is the new baseline.
  - **No hangs:** `steps_timeout` should be small/zero; any timeout is an explicit verdict (supervisor working), not a stalled run.

- [ ] **Commit (docs):** record demo evidence (including Demo 6 wall-clock) in the PR; no code commit required.

---

## Notes for the implementer

- **Authority rule (spec §3):** never reconcile the final results POST against events. `/api/scenarios/result` is unchanged and authoritative; events are overlay only.
- **Idempotency is load-bearing (spec §5.1):** the counter UPDATE must remain inside the same statement as the `ON CONFLICT DO NOTHING` insert (via the `ins` CTE), so retries/out-of-order/duplicate delivery can never double-count. Do not split them.
- **Emitter must never block the run (spec §6):** `emit` drops on a full queue; a flush failure drops the batch. The run's wall-clock must not depend on server reachability (Task 5 `TestEmitterBoundedDropsAndNeverBlocks`).
- **No scheduler/Job changes:** `workerId` is intentionally out of scope (spec §13). Do not thread worker identity through `sched.Job`.
- **DB tests skip without `TEST_DATABASE_URL`** so CI stays green; run them locally against a throwaway Postgres before marking Tasks 1/3 done.
