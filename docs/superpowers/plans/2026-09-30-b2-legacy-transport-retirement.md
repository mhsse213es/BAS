# B2 Legacy Transport Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the measurement/evidence subsystem that proves when the `:9000` legacy plaintext listener has zero fleet dependency for 30 consecutive days, surface it to an operator, and give them a safe, auditable, reversible way to disable it.

**Architecture:** A new Postgres-backed log (one row per agent per day, plus a separate unattributed-traffic counter) fed by extending the orchestrator's existing `RequestLoggingMiddleware` — no new middleware layer. A read-side eligibility query and API endpoint surface the evidence; a new dashboard panel displays it. A config flag (`BAS_LEGACY_LISTENER_ENABLED`), checked once at startup right before the legacy listener binds, is the actual retirement action — reversible with one restart.

**Tech Stack:** Go (orchestrator), Postgres (pgxpool), chi router, vanilla JS/HTML (wwwroot dashboard).

**Spec:** `docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md`

## Global Constraints

- Population semantics: any successful (2xx) request matching the exact allowlisted route set below counts as legacy usage for that agent on that UTC day — not a blind "any 2xx on :9000" rule.
- Observation window: 30 consecutive days with zero legacy traffic fleet-wide (attributed or unattributed) makes the deployment eligible for retirement *review* — never an automatic action.
- Unattributed legacy traffic (a matched, successful legacy-protocol request with no extractable agent identity) must block retirement exactly like a named agent would — it is never silently dropped from the eligibility calculation.
- Eligibility is computed live from `MAX(last_seen_at)` at query time, never cached/frozen — this is what makes the race guard (a legacy request arriving between an operator's review and their restart) correct by construction.
- One row per agent per UTC day in the attributed log (upsert on `(agent_id, day)`), not one row per request.
- The retirement action in this plan stops at disabling the listener + recording that in the audit trail. Deleting `:9000`'s code, the `agentSecret` fallback, or the agent's legacy dial path is explicitly out of scope — future, separately-scoped work.
- Exact legacy-protocol route allowlist (verified against `orchestrator/internal/api/routes.go:79-97`, use verbatim, do not re-derive):
  ```
  POST /api/agents/enroll
  POST /api/agents/enroll-csr
  POST /api/agents/unenroll
  POST /api/agents/{agentId}/uninstall-result
  POST /api/agents/events
  POST /api/heartbeat
  POST /api/scenarios/result
  POST /api/scenarios/events
  POST /api/scenarios/runs/{runId}/detections
  POST /api/attackpath/collect
  POST /api/attackpath/sharphound
  POST /api/attackpath/jobs/{id}/ack
  GET  /ws/agent
  GET  /api/agents/ping
  ```

## Review Focus

- A legacy request to a non-allowlisted route on `:9000` (e.g. `/health`, a dashboard static asset, an admin API someone hits through the wrong port by mistake) must never be logged as agent usage — Task 3's tests must prove this explicitly, not just prove the allowlisted routes work.
- Two legacy requests from the same agent on the same day, arriving out of order (an older request's response completing after a newer one due to real network jitter — not contrived), must never move `last_seen_at` backwards — Task 2's `GREATEST()` upsert must be tested with an explicit out-of-order write, not just two in-order writes.
- A legacy-protocol POST whose JSON body is present but genuinely carries no agent identity (malformed/unexpected payload, not merely a missing field) must land in the unattributed table, not silently vanish and not crash the middleware — Task 3 needs a test for a malformed/unparseable body specifically, not just a well-formed one with an empty `agentId`.
- The eligibility query at exactly the 30-day boundary (as opposed to comfortably inside or outside it) is the one an operator will actually hit in practice and is exactly where an off-by-one in a naive implementation would hide — Task 4 needs a boundary test (29 days 23 hours = not eligible; 30 days exactly = eligible), not just a "very old" vs "very recent" case.
- `BAS_LEGACY_LISTENER_ENABLED` unset (the default/every-existing-deployment case) must behave identically to `BAS_LEGACY_LISTENER_ENABLED=true` — Task 5 needs an explicit test for the unset case, not just explicit `true`/`false`.

---

### Task 1: Legacy transport log schema

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` — add two `CREATE TABLE IF NOT EXISTS` statements to the `stmts` slice inside `EnsureSchema` (the slice currently ends at line 1825, just before line 1826's closing `}` and the execution loop at line 1828 — see `execution_attempts`'s indexes immediately above as the exact insertion point).
- Test: `orchestrator/internal/db/legacy_transport_schema_test.go`

**Interfaces:**
- Produces: two tables, `legacy_transport_log(agent_id text, day date, last_seen_at timestamptz, endpoint text, UNIQUE(agent_id, day))` and `legacy_transport_unattributed(day date PRIMARY KEY, last_seen_at timestamptz, request_count int)`. Task 2 writes to both; Task 4 reads both.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/db/legacy_transport_schema_test.go
package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/audspect/bas/internal/db"
)

func setupTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "bas_user",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "bas_platform",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { container.Terminate(ctx) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	dsn := "postgres://bas_user:test@" + host + ":" + port.Port() + "/bas_platform?sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return pool
}

func TestLegacyTransportLog_SchemaExists(t *testing.T) {
	pool := setupTestPool(t)
	ctx := context.Background()

	_, err := pool.Exec(ctx,
		`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint)
		 VALUES ($1, $2, $3, $4)`,
		"agent-1", time.Now().UTC().Truncate(24*time.Hour), time.Now().UTC(), "/api/heartbeat")
	if err != nil {
		t.Fatalf("insert into legacy_transport_log: %v", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count)
		 VALUES ($1, $2, $3)`,
		time.Now().UTC().Truncate(24*time.Hour), time.Now().UTC(), 1)
	if err != nil {
		t.Fatalf("insert into legacy_transport_unattributed: %v", err)
	}
}

func TestLegacyTransportLog_UniqueConstraintEnforced(t *testing.T) {
	pool := setupTestPool(t)
	ctx := context.Background()
	day := time.Now().UTC().Truncate(24 * time.Hour)

	_, err := pool.Exec(ctx,
		`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
		"agent-1", day, time.Now().UTC(), "/api/heartbeat")
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
		"agent-1", day, time.Now().UTC(), "/api/heartbeat")
	if err == nil {
		t.Fatal("expected a second insert for the same (agent_id, day) to violate the UNIQUE constraint, got nil error -- " +
			"Task 2's upsert relies on this constraint existing for ON CONFLICT to have something to conflict on")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestLegacyTransportLog -v`
Expected: FAIL — `relation "legacy_transport_log" does not exist` (table doesn't exist yet)

- [ ] **Step 3: Add the tables to EnsureSchema**

In `orchestrator/internal/db/postgres.go`, insert immediately before the `}` that closes the `stmts` slice (right after the existing `idx_execution_attempts_status` index line):

```go
		// ── Legacy transport retirement (B2) ──────────────────────────────────
		// One row per agent per UTC day, not per request -- a heartbeating-every-
		// 30s agent would otherwise produce ~2,880 rows/day/agent for no benefit;
		// the retirement decision only ever needs "did this agent touch legacy
		// today." Upserted via GREATEST() in internal/api's recordLegacyUsage so
		// an out-of-order (delayed) request can never move last_seen_at
		// backwards. See docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md.
		`CREATE TABLE IF NOT EXISTS legacy_transport_log (
			agent_id     text        NOT NULL,
			day          date        NOT NULL,
			last_seen_at timestamptz NOT NULL,
			endpoint     text        NOT NULL,
			UNIQUE (agent_id, day)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_legacy_transport_log_day ON legacy_transport_log (day)`,

		// A matched, successful legacy-protocol request that cannot be resolved
		// to an agent_id still represents real, unexplained legacy dependency --
		// tracked here (not discarded, not folded into legacy_transport_log as
		// agent_id='') so it blocks the retirement eligibility calculation
		// exactly like a named agent would, rather than silently disappearing
		// from it.
		`CREATE TABLE IF NOT EXISTS legacy_transport_unattributed (
			day           date        PRIMARY KEY,
			last_seen_at  timestamptz NOT NULL,
			request_count int         NOT NULL DEFAULT 1
		)`,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestLegacyTransportLog -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/db/legacy_transport_schema_test.go
git commit -m "feat(b2): add legacy_transport_log and legacy_transport_unattributed tables"
git push
```

---

### Task 2: Legacy usage recording function

**Files:**
- Create: `orchestrator/internal/api/legacy_transport.go`
- Test: `orchestrator/internal/api/legacy_transport_test.go`

**Interfaces:**
- Consumes: `h.db *pgxpool.Pool` (existing `Handler` field, `handlers.go:79`); Task 1's two tables.
- Produces: `func (h *Handler) recordLegacyUsage(ctx context.Context, agentID, endpoint string, seenAt time.Time)` — fire-and-forget (async, matching `auditLogAs`'s existing pattern in `audit.go:28-45`), writes to `legacy_transport_log` when `agentID != ""`, else to `legacy_transport_unattributed`. Task 3 calls this from the request-logging middleware. Task 4's eligibility query reads what this writes.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/legacy_transport_test.go
package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/audspect/bas/internal/db"
)

func setupAPITestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "bas_user",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "bas_platform",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { container.Terminate(ctx) })
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	dsn := "postgres://bas_user:test@" + host + ":" + port.Port() + "/bas_platform?sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return pool
}

// waitForAsyncWrite polls for up to 2s for a row matching whereClause to
// appear in table -- recordLegacyUsage writes in a goroutine (matching
// auditLogAs's existing fire-and-forget pattern), so its effect isn't
// guaranteed visible the instant the calling function returns.
func waitForAsyncWrite(t *testing.T, pool *pgxpool.Pool, table, whereClause string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var exists bool
		err := pool.QueryRow(context.Background(),
			"SELECT EXISTS(SELECT 1 FROM "+table+" WHERE "+whereClause+")",
		).Scan(&exists)
		if err == nil && exists {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a row matching %q in %s", whereClause, table)
}

func TestRecordLegacyUsage_AttributedUpsertsOnePerAgentPerDay(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()
	day := time.Now().UTC().Truncate(24 * time.Hour)
	first := day.Add(10 * time.Hour)
	second := day.Add(14 * time.Hour)

	h.recordLegacyUsage(ctx, "agent-1", "/api/heartbeat", first)
	h.recordLegacyUsage(ctx, "agent-1", "/api/heartbeat", second)
	waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-1'")

	var count int
	var lastSeen time.Time
	err := pool.QueryRow(ctx,
		`SELECT COUNT(*), MAX(last_seen_at) FROM legacy_transport_log WHERE agent_id = 'agent-1'`,
	).Scan(&count, &lastSeen)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row for agent-1's day (upsert, not insert-per-call), got %d", count)
	}
	if !lastSeen.Equal(second) {
		t.Errorf("expected last_seen_at to be the later of the two writes (%v), got %v", second, lastSeen)
	}
}

func TestRecordLegacyUsage_OutOfOrderWriteNeverMovesTimeBackwards(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()
	day := time.Now().UTC().Truncate(24 * time.Hour)
	later := day.Add(14 * time.Hour)
	earlier := day.Add(10 * time.Hour) // arrives AFTER 'later' due to network jitter, not test ordering

	h.recordLegacyUsage(ctx, "agent-2", "/api/heartbeat", later)
	waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-2'")
	h.recordLegacyUsage(ctx, "agent-2", "/api/heartbeat", earlier) // the delayed, older-timestamped request
	waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-2'")

	var lastSeen time.Time
	if err := pool.QueryRow(ctx,
		`SELECT last_seen_at FROM legacy_transport_log WHERE agent_id = 'agent-2'`,
	).Scan(&lastSeen); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !lastSeen.Equal(later) {
		t.Errorf("an out-of-order (delayed) write moved last_seen_at backwards to %v -- expected it to stay at %v (GREATEST() should have rejected the older value)", lastSeen, later)
	}
}

func TestRecordLegacyUsage_UnattributedIncrementsCount(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()
	day := time.Now().UTC().Truncate(24 * time.Hour)

	h.recordLegacyUsage(ctx, "", "/api/heartbeat", day.Add(9*time.Hour))
	waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "day = '"+day.Format("2006-01-02")+"'")
	h.recordLegacyUsage(ctx, "", "/ws/agent", day.Add(11*time.Hour))
	waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "request_count = 2")

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT request_count FROM legacy_transport_unattributed WHERE day = $1`, day,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 2 {
		t.Errorf("expected request_count 2 after two unattributed writes on the same day, got %d", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestRecordLegacyUsage -v`
Expected: FAIL — `undefined: (*Handler).recordLegacyUsage` (compile error)

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/api/legacy_transport.go
package api

import (
	"context"
	"time"
)

// recordLegacyUsage records one successful legacy-protocol request (see
// routes.go:79-97's allowlist) against agentID's day, or against the
// fleet-level unattributed counter when agentID is empty. Fire-and-forget,
// matching auditLogAs's existing async pattern (audit.go) -- a slow or
// failed write here must never add latency or an error path to the actual
// agent-facing response.
//
// The GREATEST() upsert means an out-of-order write (an older request's
// response completing after a newer one, due to real network jitter) can
// never move last_seen_at backwards -- see the spec's schema section for
// why this matters for the 30-day eligibility window's correctness.
func (h *Handler) recordLegacyUsage(ctx context.Context, agentID, endpoint string, seenAt time.Time) {
	day := seenAt.UTC().Truncate(24 * time.Hour)
	if agentID != "" {
		go func() {
			_, _ = h.db.Exec(context.Background(),
				`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint)
				 VALUES ($1, $2, $3, $4)
				 ON CONFLICT (agent_id, day) DO UPDATE
				   SET last_seen_at = GREATEST(legacy_transport_log.last_seen_at, EXCLUDED.last_seen_at),
				       endpoint     = CASE WHEN EXCLUDED.last_seen_at > legacy_transport_log.last_seen_at
				                           THEN EXCLUDED.endpoint ELSE legacy_transport_log.endpoint END`,
				agentID, day, seenAt.UTC(), endpoint)
		}()
		return
	}
	go func() {
		_, _ = h.db.Exec(context.Background(),
			`INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count)
			 VALUES ($1, $2, 1)
			 ON CONFLICT (day) DO UPDATE
			   SET last_seen_at  = GREATEST(legacy_transport_unattributed.last_seen_at, EXCLUDED.last_seen_at),
			       request_count = legacy_transport_unattributed.request_count + 1`,
			day, seenAt.UTC())
	}()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -run TestRecordLegacyUsage -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/legacy_transport.go orchestrator/internal/api/legacy_transport_test.go
git commit -m "feat(b2): add recordLegacyUsage with order-safe upsert and unattributed tracking"
git push
```

---

### Task 3: Wire recording into the request-logging middleware

**Files:**
- Modify: `orchestrator/internal/api/observability.go:97` (`RequestLoggingMiddleware` becomes a `*Handler` method)
- Modify: `orchestrator/internal/api/routes.go:34,56` (both `r.Use(RequestLoggingMiddleware)` call sites)
- Test: `orchestrator/internal/api/legacy_transport_middleware_test.go`

**Interfaces:**
- Consumes: Task 2's `h.recordLegacyUsage`; the existing `isLegacyListener(r)` (`observability.go:89`).
- Produces: every successful, allowlisted `:9000` request now calls `recordLegacyUsage`. No new exported interface — this task's deliverable is the wiring itself, verified by its tests writing real rows.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/legacy_transport_middleware_test.go
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func newTestRouterWithHandler(h *Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(h.RequestLoggingMiddleware)
	r.Post("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func legacyRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	return req.WithContext(context.WithValue(req.Context(), ctxKeyLegacyListener, true))
}

func TestMiddleware_AllowlistedRouteWithJSONBody_RecordsAttributed(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	router := newTestRouterWithHandler(h)

	req := legacyRequest(http.MethodPost, "/api/heartbeat", []byte(`{"agentId":"agent-mw-1"}`))
	router.ServeHTTP(httptest.NewRecorder(), req)
	waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-mw-1'")
}

func TestMiddleware_NonAllowlistedRoute_NeverRecorded(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	router := newTestRouterWithHandler(h)

	req := legacyRequest(http.MethodGet, "/health", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	time.Sleep(200 * time.Millisecond) // give any (incorrect) async write a chance to land
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM legacy_transport_log`).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("a request to /health (not in the legacy-protocol allowlist) was recorded as agent usage -- expected 0 rows, got %d", count)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM legacy_transport_unattributed`).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("a request to /health was recorded as unattributed legacy traffic -- expected 0 rows, got %d", count)
	}
}

func TestMiddleware_MalformedBody_RecordsUnattributedNotDropped(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	router := newTestRouterWithHandler(h)

	req := legacyRequest(http.MethodPost, "/api/heartbeat", []byte(`not valid json at all`))
	router.ServeHTTP(httptest.NewRecorder(), req)
	waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "request_count >= 1")
}

func TestMiddleware_QueryParamAgentID_RecordsAttributed(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	router := newTestRouterWithHandler(h)

	req := legacyRequest(http.MethodGet, "/ws/agent?agentId=agent-mw-ws", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)
	waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-mw-ws'")
}

func TestMiddleware_NonLegacyListener_NeverRecorded(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	router := newTestRouterWithHandler(h)

	// No ctxKeyLegacyListener set -- an ordinary request on the mTLS/dashboard listener.
	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader([]byte(`{"agentId":"agent-not-legacy"}`)))
	router.ServeHTTP(httptest.NewRecorder(), req)

	time.Sleep(200 * time.Millisecond)
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM legacy_transport_log WHERE agent_id = 'agent-not-legacy'`).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("a non-legacy-listener request was recorded as legacy usage -- expected 0 rows, got %d", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestMiddleware_ -v`
Expected: FAIL — `undefined: (*Handler).RequestLoggingMiddleware` (compile error — it's still a bare function, not a method)

- [ ] **Step 3: Convert RequestLoggingMiddleware to a method and add the recording logic**

In `orchestrator/internal/api/observability.go`, replace the existing function (keep every line of its current body exactly as-is — only the signature changes and new logic is appended before the closing `})`):

```go
// legacyProtocolRoutes is the exact, verified allowlist from
// docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md
// -- routes.go:79-97's agent-protocol block plus /ws/agent. Deliberately
// NOT "any 2xx on :9000": that listener's handler is the same full router
// every other listener uses (main.go:948-950), so it also serves /health,
// dashboard statics, and admin endpoints that say nothing about legacy
// agent dependency.
var legacyProtocolRoutes = map[string]bool{
	"/api/agents/enroll":                    true,
	"/api/agents/enroll-csr":                true,
	"/api/agents/unenroll":                  true,
	"/api/agents/{agentId}/uninstall-result": true,
	"/api/agents/events":                    true,
	"/api/heartbeat":                        true,
	"/api/scenarios/result":                 true,
	"/api/scenarios/events":                 true,
	"/api/scenarios/runs/{runId}/detections": true,
	"/api/attackpath/collect":               true,
	"/api/attackpath/sharphound":            true,
	"/api/attackpath/jobs/{id}/ack":         true,
	"/ws/agent":                             true,
	"/api/agents/ping":                      true,
}

// legacyBodyAgentID is the minimal shape needed to opportunistically read
// an agent identity out of a legacy-protocol POST body without depending
// on any specific handler's own request struct -- every one of this
// codebase's ~30 AgentID-carrying JSON structs uses one of these two key
// spellings (verified: grep across orchestrator/internal/api and
// orchestrator/internal/models turned up "agentId" as the overwhelming
// convention with exactly two "agent_id" outliers, neither on a legacy
// route).
type legacyBodyAgentID struct {
	AgentIDCamel string `json:"agentId"`
	AgentIDSnake string `json:"agent_id"`
}

// RequestLoggingMiddleware replaces chi's default middleware.Logger
// (routes.go). One instrumentation point per completed request feeds both
// a structured slog line and the two HTTP metrics above -- and, as of B2,
// the legacy-transport-retirement evidence log for requests on the :9000
// listener. A *Handler method (not a bare function) specifically so it can
// reach h.db and h.recordLegacyUsage; routes.go's two r.Use call sites
// updated accordingly.
func (h *Handler) RequestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Legacy POST bodies are peeked here, before dispatch, then restored
		// so the real handler downstream reads them completely normally --
		// this is the only way to see a JSON body's agentId field without
		// requiring every one of the ~11 legacy-protocol POST handlers to
		// separately cooperate with this middleware.
		var legacyBody []byte
		if isLegacyListener(r) && r.Method == http.MethodPost && r.Body != nil {
			legacyBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(legacyBody))
		}

		next.ServeHTTP(ww, r)
		duration := time.Since(start)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched" // avoids one label value per raw 404 path
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		httpRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, route).Observe(duration.Seconds())

		slog.Info("http request",
			"component", "http",
			"method", r.Method,
			"route", route,
			"status", status,
			"duration_ms", duration.Milliseconds(),
		)

		if isLegacyListener(r) {
			legacyListenerRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
			slog.Info("legacy listener request",
				"component", "http",
				"listener", "legacy",
				"method", r.Method,
				"route", route,
				"status", status,
				"remote_addr", r.RemoteAddr,
				"agent_id", r.URL.Query().Get("agentId"),
			)

			if status >= 200 && status < 300 && legacyProtocolRoutes[route] {
				agentID := chi.URLParam(r, "agentId")
				if agentID == "" {
					agentID = r.URL.Query().Get("agentId")
				}
				if agentID == "" && len(legacyBody) > 0 {
					var parsed legacyBodyAgentID
					if json.Unmarshal(legacyBody, &parsed) == nil {
						if parsed.AgentIDCamel != "" {
							agentID = parsed.AgentIDCamel
						} else {
							agentID = parsed.AgentIDSnake
						}
					}
					// A json.Unmarshal error here is not itself logged/handled --
					// it just leaves agentID empty, which correctly routes this
					// request to the unattributed table below rather than being
					// dropped. See this task's malformed-body test.
				}
				h.recordLegacyUsage(r.Context(), agentID, route, time.Now())
			}
		}
	})
}
```

Add `"bytes"` and `"io"` to `observability.go`'s existing import block (alongside `"context"`, `"encoding/json"`, `"log/slog"`, `"net/http"`, `"strconv"`, `"time"`).

Update both call sites in `orchestrator/internal/api/routes.go`:

```go
// line 34, inside MountEnrollment:
	r.Use(h.RequestLoggingMiddleware)
```

```go
// line 56, inside Mount:
	r.Use(h.RequestLoggingMiddleware)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -run TestMiddleware_ -v`
Expected: PASS (all five tests)

- [ ] **Step 5: Run the full existing observability + routing test suites to confirm no regression**

Run: `go test ./internal/api/... -run TestRequestLogging -v` and `go test ./internal/api/...` (full package)
Expected: PASS — this task changed an existing, widely-used middleware's signature; every existing caller (both `r.Use` sites) was updated in this same step, so nothing else should reference the old bare-function form. Confirm real output, not assumed.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/observability.go orchestrator/internal/api/routes.go orchestrator/internal/api/legacy_transport_middleware_test.go
git commit -m "feat(b2): record legacy transport usage from RequestLoggingMiddleware"
git push
```

---

### Task 4: Eligibility computation and API endpoint

**Files:**
- Create: `orchestrator/internal/api/legacy_migration_status.go`
- Modify: `orchestrator/internal/api/routes.go` (add the new route in the JWT-authenticated group, right after `r.Get("/api/agents", h.GetAgents)` at line 209)
- Test: `orchestrator/internal/api/legacy_migration_status_test.go`

**Interfaces:**
- Consumes: `legacy_transport_log` and `legacy_transport_unattributed` (Task 1); reads directly via `h.db`, independent of Task 2/3's write path (tests seed rows directly with SQL).
- Produces: `func (h *Handler) GetLegacyMigrationStatus(w http.ResponseWriter, r *http.Request)`, mounted at `GET /api/agents/legacy-migration-status`. Task 6's dashboard panel consumes this endpoint's JSON response, whose exact shape is defined in Step 3 below.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/legacy_migration_status_test.go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLegacyMigrationStatus_NoTrafficEver_Eligible(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}

	req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
	rec := httptest.NewRecorder()
	h.GetLegacyMigrationStatus(rec, req)

	var body legacyMigrationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Eligible {
		t.Error("expected eligible=true when no legacy traffic has ever been recorded")
	}
	if body.LastLegacySeenAt != nil {
		t.Errorf("expected LastLegacySeenAt nil with no traffic, got %v", body.LastLegacySeenAt)
	}
}

func TestLegacyMigrationStatus_ExactlyAtThirtyDayBoundary(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()

	// Exactly 30 days ago, to the second -- the actual boundary an operator
	// will hit in practice, not a comfortably-inside/outside case.
	exactlyThirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour)
	_, err := pool.Exec(ctx,
		`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
		"boundary-agent", exactlyThirtyDaysAgo.Truncate(24*time.Hour), exactlyThirtyDaysAgo, "/api/heartbeat")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
	rec := httptest.NewRecorder()
	h.GetLegacyMigrationStatus(rec, req)

	var body legacyMigrationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Eligible {
		t.Error("expected eligible=true at exactly 30 days since last legacy traffic (>= 30 days is the rule)")
	}
}

func TestLegacyMigrationStatus_TwentyNineDaysNotEligible(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()

	recentEnough := time.Now().UTC().Add(-29*24*time.Hour - 23*time.Hour) // 29d23h ago -- just short
	_, err := pool.Exec(ctx,
		`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
		"almost-agent", recentEnough.Truncate(24*time.Hour), recentEnough, "/api/heartbeat")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
	rec := httptest.NewRecorder()
	h.GetLegacyMigrationStatus(rec, req)

	var body legacyMigrationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Eligible {
		t.Error("expected eligible=false at 29 days 23 hours since last legacy traffic -- still inside the 30-day window")
	}
	if len(body.BlockingAgents) != 1 || body.BlockingAgents[0].AgentID != "almost-agent" {
		t.Errorf("expected almost-agent in BlockingAgents, got %+v", body.BlockingAgents)
	}
}

func TestLegacyMigrationStatus_UnattributedTrafficBlocksEligibility(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()

	recent := time.Now().UTC().Add(-1 * time.Hour)
	_, err := pool.Exec(ctx,
		`INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count) VALUES ($1, $2, $3)`,
		recent.Truncate(24*time.Hour), recent, 3)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
	rec := httptest.NewRecorder()
	h.GetLegacyMigrationStatus(rec, req)

	var body legacyMigrationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Eligible {
		t.Error("expected eligible=false when unattributed legacy traffic exists inside the window, even with zero named blocking agents")
	}
	if body.UnattributedRequests == nil || body.UnattributedRequests.Count != 3 {
		t.Errorf("expected UnattributedRequests.Count=3, got %+v", body.UnattributedRequests)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestLegacyMigrationStatus -v`
Expected: FAIL — `undefined: legacyMigrationStatusResponse` (compile error)

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/api/legacy_migration_status.go
package api

import (
	"net/http"
	"time"
)

type legacyMigrationBlockingAgent struct {
	AgentID  string    `json:"agentId"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"lastSeen"`
}

type legacyMigrationUnattributed struct {
	LastSeen time.Time `json:"lastSeen"`
	Count    int       `json:"count"`
}

type legacyMigrationStatusResponse struct {
	Eligible             bool                           `json:"eligible"`
	LastLegacySeenAt     *time.Time                     `json:"lastLegacySeenAt"`
	DaysClean            int                            `json:"daysClean"`
	DaysRequired         int                            `json:"daysRequired"`
	BlockingAgents       []legacyMigrationBlockingAgent `json:"blockingAgents"`
	UnattributedRequests *legacyMigrationUnattributed   `json:"unattributedRequests"`
}

const legacyRetirementWindowDays = 30

// GetLegacyMigrationStatus is GET /api/agents/legacy-migration-status.
// Eligibility is computed live from MAX(last_seen_at) across BOTH the
// attributed and unattributed tables at query time -- never cached or
// frozen at the moment it first became eligible -- so a legacy request
// arriving after an operator's review but before they act on it correctly
// flips this back to false on the very next check. See the spec's
// "Retirement procedure" section's race-guard explanation.
func (h *Handler) GetLegacyMigrationStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var lastAttributed, lastUnattributed *time.Time
	_ = h.db.QueryRow(ctx, `SELECT MAX(last_seen_at) FROM legacy_transport_log`).Scan(&lastAttributed)
	_ = h.db.QueryRow(ctx, `SELECT MAX(last_seen_at) FROM legacy_transport_unattributed`).Scan(&lastUnattributed)

	lastSeen := latestNonNil(lastAttributed, lastUnattributed)

	eligible := true
	daysClean := legacyRetirementWindowDays
	if lastSeen != nil {
		elapsed := time.Since(*lastSeen)
		eligible = elapsed >= legacyRetirementWindowDays*24*time.Hour
		daysClean = int(elapsed.Hours() / 24)
		if daysClean > legacyRetirementWindowDays {
			daysClean = legacyRetirementWindowDays
		}
	}

	blocking := []legacyMigrationBlockingAgent{}
	if !eligible {
		rows, err := h.db.Query(ctx, `
			SELECT l.agent_id, COALESCE(a.hostname, ''), MAX(l.last_seen_at) AS last_seen
			FROM legacy_transport_log l
			LEFT JOIN agents a ON a.agent_id = l.agent_id
			WHERE l.last_seen_at >= NOW() - ($1 || ' days')::interval
			GROUP BY l.agent_id, a.hostname
			ORDER BY last_seen DESC`, legacyRetirementWindowDays)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var b legacyMigrationBlockingAgent
				if rows.Scan(&b.AgentID, &b.Hostname, &b.LastSeen) == nil {
					blocking = append(blocking, b)
				}
			}
		}
	}

	var unattributed *legacyMigrationUnattributed
	if lastUnattributed != nil && time.Since(*lastUnattributed) < legacyRetirementWindowDays*24*time.Hour {
		var count int
		_ = h.db.QueryRow(ctx,
			`SELECT COALESCE(SUM(request_count), 0) FROM legacy_transport_unattributed
			 WHERE last_seen_at >= NOW() - ($1 || ' days')::interval`, legacyRetirementWindowDays,
		).Scan(&count)
		unattributed = &legacyMigrationUnattributed{LastSeen: *lastUnattributed, Count: count}
	}

	respond(w, legacyMigrationStatusResponse{
		Eligible:             eligible,
		LastLegacySeenAt:     lastSeen,
		DaysClean:            daysClean,
		DaysRequired:         legacyRetirementWindowDays,
		BlockingAgents:       blocking,
		UnattributedRequests: unattributed,
	})
}

func latestNonNil(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.After(*b) {
		return a
	}
	return b
}
```

Add the route in `orchestrator/internal/api/routes.go`, immediately after line 209's `r.Get("/api/agents", h.GetAgents)`:

```go
		r.Get("/api/agents/legacy-migration-status", h.GetLegacyMigrationStatus)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -run TestLegacyMigrationStatus -v`
Expected: PASS (all four tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/legacy_migration_status.go orchestrator/internal/api/legacy_migration_status_test.go orchestrator/internal/api/routes.go
git commit -m "feat(b2): add GET /api/agents/legacy-migration-status eligibility endpoint"
git push
```

---

### Task 5: BAS_LEGACY_LISTENER_ENABLED config flag, startup wiring, and audit trail

**Files:**
- Modify: `orchestrator/config/config.go` (new field + env loading, same location/pattern as `PKI_DIR`/`BAS_SERVER_SANS` from tonight's earlier work)
- Modify: `orchestrator/internal/api/audit.go` (new `auditLogSystem` helper)
- Modify: `orchestrator/cmd/server/main.go` (check the flag before `legacySrv.ListenAndServe()`)
- Modify: `packaging/compose/docker-compose.yml` (environment wiring, mirroring `BAS_CONFIRM_NEW_CA`/`BAS_CONFIRM_NEW_SIGNING_KEY`)
- Test: `orchestrator/config/config_test.go`, `orchestrator/cmd/server/legacy_listener_flag_test.go`, `orchestrator/internal/api/audit_system_test.go`

**Interfaces:**
- Consumes: nothing new from earlier tasks.
- Produces: `cfg.LegacyListenerEnabled bool` (default `true`); `func legacyListenerShouldStart(cfg config.Config) bool` (a small, directly-unit-testable pure function `main.go` calls — mirrors tonight's `splitServerSANs` pattern of extracting startup logic into a testable helper rather than leaving it inline in `main()`); `func (h *Handler) auditLogSystem(ctx context.Context, action, resource string, detail map[string]any, outcome string)`.

- [ ] **Step 1: Write the failing test for the config field**

Add to the existing `orchestrator/config/config_test.go` (read `TestLoad_PKIDefaults`/`TestLoad_DashboardDefaults` in that file first and match their exact `Load(...)` call signature — do not guess it):

```go
func TestLoad_LegacyListenerEnabledDefaultsTrue(t *testing.T) {
	os.Unsetenv("BAS_LEGACY_LISTENER_ENABLED")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.LegacyListenerEnabled {
		t.Error("expected LegacyListenerEnabled to default true when BAS_LEGACY_LISTENER_ENABLED is unset -- every existing deployment must behave unchanged")
	}
}

func TestLoad_LegacyListenerEnabledFalseOverride(t *testing.T) {
	t.Setenv("BAS_LEGACY_LISTENER_ENABLED", "false")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LegacyListenerEnabled {
		t.Error("expected LegacyListenerEnabled=false when BAS_LEGACY_LISTENER_ENABLED=false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/... -run TestLoad_LegacyListener -v`
Expected: FAIL — `cfg.LegacyListenerEnabled undefined` (compile error)

- [ ] **Step 3: Add the config field**

In `orchestrator/config/config.go`, add near `ServerSANs` (added earlier tonight):

```go
	// LegacyListenerEnabled (BAS_LEGACY_LISTENER_ENABLED) gates the :9000
	// plaintext legacy listener. Defaults true -- every existing deployment
	// keeps working unchanged. An operator sets this false as Step 3 of the
	// B2 retirement procedure, after the /api/agents/legacy-migration-status
	// endpoint has reported 30 consecutive clean days AND they've reviewed
	// the evidence -- see
	// docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md.
	// Reversible: setting it back to true (or unsetting it) and restarting
	// re-enables the listener.
	LegacyListenerEnabled bool `json:"legacy_listener_enabled,omitempty"`
```

And in `Load`'s env-parsing section (near where other bools are parsed, e.g. the `SFTP_SINK_ENABLED`/`SMTP_SINK_ENABLED` pattern at lines 300-308 — set the *default* first since this one defaults to `true`, unlike those which default to their zero value):

```go
	cfg.LegacyListenerEnabled = true
	if v := os.Getenv("BAS_LEGACY_LISTENER_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.LegacyListenerEnabled = b
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./config/... -run TestLoad_LegacyListener -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for auditLogSystem**

```go
// orchestrator/internal/api/audit_system_test.go
package api

import (
	"context"
	"testing"
)

func TestAuditLogSystem_WritesWithSystemActor(t *testing.T) {
	pool := setupAPITestPool(t)
	h := &Handler{db: pool}
	ctx := context.Background()

	h.auditLogSystem(ctx, "legacy_listener.disabled", "", map[string]any{"reason": "operator retirement"}, "ok")
	waitForAsyncWrite(t, pool, "audit_logs", "action = 'legacy_listener.disabled'")

	var actorID, outcome string
	err := pool.QueryRow(ctx,
		`SELECT actor_id, outcome FROM audit_logs WHERE action = 'legacy_listener.disabled'`,
	).Scan(&actorID, &outcome)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if actorID != "" {
		t.Errorf("expected empty actor_id for a system/startup event (renders as 'system' per the existing COALESCE in GetAuditLogs), got %q", actorID)
	}
	if outcome != "ok" {
		t.Errorf("expected outcome 'ok', got %q", outcome)
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestAuditLogSystem -v`
Expected: FAIL — `undefined: (*Handler).auditLogSystem` (compile error)

- [ ] **Step 7: Add auditLogSystem**

In `orchestrator/internal/api/audit.go`, add after the existing `auditLogAs`:

```go
// auditLogSystem records a system/startup-time event with no HTTP request
// in scope (e.g. main.go detecting BAS_LEGACY_LISTENER_ENABLED=false at
// boot) -- auditLogAs above requires *http.Request (it reads r.Header and
// r.RemoteAddr unconditionally, so passing nil would panic), which no
// startup-time caller has. actor_id is left empty; GetAuditLogs' existing
// query already renders an empty actor_id as "system"
// (COALESCE(u.username, CASE WHEN a.actor_id='' THEN 'system' ...)), so
// this needs no new display-side handling.
func (h *Handler) auditLogSystem(ctx context.Context, action, resource string, detail map[string]any, outcome string) {
	detailJSON := []byte("{}")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			detailJSON = b
		}
	}
	go func() {
		_, _ = h.db.Exec(context.Background(),
			`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
			 VALUES ('', $1, $2, $3, '', $4)`,
			action, resource, detailJSON, outcome)
	}()
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/api/... -run TestAuditLogSystem -v`
Expected: PASS

- [ ] **Step 9: Write the failing test for the startup gate**

```go
// orchestrator/cmd/server/legacy_listener_flag_test.go
package main

import (
	"testing"

	"github.com/audspect/bas/config"
)

func TestLegacyListenerShouldStart_DefaultTrue(t *testing.T) {
	cfg := config.Config{LegacyListenerEnabled: true}
	if !legacyListenerShouldStart(cfg) {
		t.Error("expected the legacy listener to start when LegacyListenerEnabled is true")
	}
}

func TestLegacyListenerShouldStart_DisabledFalse(t *testing.T) {
	cfg := config.Config{LegacyListenerEnabled: false}
	if legacyListenerShouldStart(cfg) {
		t.Error("expected the legacy listener NOT to start when LegacyListenerEnabled is false")
	}
}
```

- [ ] **Step 10: Run test to verify it fails**

Run: `go test ./cmd/server/... -run TestLegacyListenerShouldStart -v`
Expected: FAIL — `undefined: legacyListenerShouldStart` (compile error)

- [ ] **Step 11: Write the minimal implementation and wire it into main()**

Add near `splitServerSANs` in `orchestrator/cmd/server/main.go`:

```go
// legacyListenerShouldStart is Step 4 of the B2 retirement procedure
// (docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md):
// an operator sets BAS_LEGACY_LISTENER_ENABLED=false after reviewing 30
// consecutive clean days' evidence from GET /api/agents/legacy-migration-status,
// then restarts -- this is the single check point that decides whether the
// goroutine below ever calls legacySrv.ListenAndServe() at all. Extracted
// as its own function (rather than left inline) so it's directly
// unit-testable without needing a live listener or database.
func legacyListenerShouldStart(cfg config.Config) bool {
	return cfg.LegacyListenerEnabled
}
```

In `main()`, replace the existing legacy listener startup goroutine (around line 997's `if err := legacySrv.ListenAndServe(); ...`) with a gated version, and record the audit entry when it's disabled. Before writing this edit, confirm the exact variable name of the `*api.Handler` already constructed earlier in `main()` (it is passed as `api.MountEnrollment(handler)`'s argument around line 935 — read that line first and use whatever name is actually there; it may not literally be `handler`):

```go
	go func() {
		if !legacyListenerShouldStart(*cfg) {
			log.Printf("[*] Legacy listener disabled via BAS_LEGACY_LISTENER_ENABLED=false -- :%d not bound", cfg.LegacyHTTPPort)
			handler.auditLogSystem(context.Background(), "legacy_listener.disabled", "",
				map[string]any{"port": cfg.LegacyHTTPPort}, "ok")
			return
		}
		log.Printf("[*] BAS Orchestrator legacy listener on :%d (temporary — retired by B2)", cfg.LegacyHTTPPort)
		if err := legacySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] legacy listener: %v", err)
		}
	}()
```

- [ ] **Step 12: Run test to verify it passes**

Run: `go test ./cmd/server/... -run TestLegacyListenerShouldStart -v`
Expected: PASS

- [ ] **Step 13: Wire the docker-compose.yml environment variable**

In `packaging/compose/docker-compose.yml`, add immediately after the `BAS_CONFIRM_NEW_CA` line added earlier tonight:

```yaml
      # ── Legacy listener retirement (B2) — operator override ─────────────────
      # BAS_LEGACY_LISTENER_ENABLED=false: Step 3 of the B2 retirement
      # procedure, set only after GET /api/agents/legacy-migration-status
      # reports 30 consecutive clean days and an operator has reviewed the
      # evidence. Defaults true (every existing deployment unaffected). See
      # cmd/server/main.go's legacyListenerShouldStart and
      # docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md.
      BAS_LEGACY_LISTENER_ENABLED: ${BAS_LEGACY_LISTENER_ENABLED:-}
```

- [ ] **Step 14: Validate the compose file still parses**

Run: `cd packaging/compose && DNS_SINK_BIND_IP=127.0.0.1 docker compose -f docker-compose.yml config --quiet; echo "EXIT:$?"`
Expected: `EXIT:0` (matching the same validation technique used earlier tonight for the other two environment-variable additions)

- [ ] **Step 15: Run the full build to confirm everything compiles together**

Run: `cd orchestrator && go build ./...`
Expected: clean (no output)

- [ ] **Step 16: Commit**

```bash
git add orchestrator/config/config.go orchestrator/config/config_test.go orchestrator/internal/api/audit.go orchestrator/internal/api/audit_system_test.go orchestrator/cmd/server/main.go orchestrator/cmd/server/legacy_listener_flag_test.go packaging/compose/docker-compose.yml
git commit -m "feat(b2): add BAS_LEGACY_LISTENER_ENABLED retirement flag with startup audit trail"
git push
```

---

### Task 6: Dashboard migration-status panel

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (new panel + fetch call on the Agents page; do NOT modify the existing per-agent "Legacy transport" badge from earlier tonight's work — this is a separate, new panel)

**Interfaces:**
- Consumes: Task 4's `GET /api/agents/legacy-migration-status` (exact response shape defined in Task 4 Step 3).
- Produces: a rendered panel; no new interface other tasks depend on (this is the last task).

- [ ] **Step 1: Find the Agents page's existing render function**

```bash
grep -n "function renderAgentsPage\|Simulation agents" orchestrator/wwwroot/index.html
```

Locate where the Agents page's top-level container renders (the same page the earlier-tonight "⚠ Legacy transport" per-agent badge lives on) — this task adds a new, separate panel there, not a modification of that existing badge code.

- [ ] **Step 2: Add the fetch + render function**

Add near the other `apicall(...)`-based render functions in the same file (match the existing `apicall`/`showToast` helper usage exactly as used elsewhere in this file — do not introduce a different fetch pattern):

```javascript
function renderLegacyMigrationPanel() {
  var el = document.getElementById('legacy-migration-panel');
  if (!el) return;
  apicall('/api/agents/legacy-migration-status').then(function(status) {
    var blockingHtml = (status.blockingAgents || []).map(function(a) {
      return '<div class="legacy-blocking-row"><span>' + (a.hostname || a.agentId) + '</span>' +
             '<span class="legacy-blocking-time">' + new Date(a.lastSeen).toLocaleString() + '</span></div>';
    }).join('');
    var unattributedHtml = status.unattributedRequests
      ? '<div class="legacy-unattributed-warning">⚠ Unattributed legacy activity: ' +
        status.unattributedRequests.count + ' request(s) — retirement blocked</div>'
      : '';
    el.innerHTML =
      '<div class="legacy-migration-header">Legacy Transport Migration</div>' +
      '<div class="legacy-migration-days">Days clean: ' + status.daysClean + ' / ' + status.daysRequired + '</div>' +
      '<div class="legacy-migration-status ' + (status.eligible ? 'eligible' : 'not-eligible') + '">' +
        (status.eligible ? 'ELIGIBLE FOR REVIEW' : 'NOT YET ELIGIBLE') +
      '</div>' +
      unattributedHtml +
      (blockingHtml ? '<div class="legacy-blocking-list">' + blockingHtml + '</div>' : '');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 3: Add the panel's container to the Agents page markup**

In the Agents page's HTML (near the existing per-agent list container found in Step 1), add:

```html
<div id="legacy-migration-panel" class="legacy-migration-panel"></div>
```

Call `renderLegacyMigrationPanel()` from wherever the Agents page's existing data already gets refreshed (the same function that currently loads the agent list) so the panel updates alongside it, rather than only on initial page load.

- [ ] **Step 4: Add minimal styling**

Add near the existing legacy-badge CSS from earlier tonight's work (match the file's existing CSS variable usage — dark theme, existing warning-color variable — rather than hardcoding new colors):

```css
.legacy-migration-panel { border: 1px solid var(--border-color, #333); border-radius: 6px; padding: 12px; margin: 12px 0; }
.legacy-migration-header { font-weight: 600; margin-bottom: 8px; }
.legacy-migration-status.eligible { color: var(--success-color, #2ecc71); }
.legacy-migration-status.not-eligible { color: var(--warning-color, #e67e22); }
.legacy-unattributed-warning { color: var(--danger-color, #e74c3c); margin-top: 8px; }
.legacy-blocking-row { display: flex; justify-content: space-between; padding: 4px 0; }
```

- [ ] **Step 5: Manual verification**

Per this project's established `run` skill for this codebase: launch the orchestrator, log into the dashboard, navigate to the Agents page, confirm the panel renders without a JS console error and shows "ELIGIBLE FOR REVIEW" on a fresh database (no legacy traffic recorded yet) or the correct blocking-agent list against seeded data. This is a frontend-only change with no Go tests — this manual check is the verification, matching how this session's earlier per-agent legacy badge was verified.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(b2): add legacy transport migration-status dashboard panel"
git push
```

---

## Final Verification

- [ ] Run the full orchestrator test suite: `cd orchestrator && go test ./... 2>&1 | tail -60` — expect all PASS, no regressions in any package this plan touched (`internal/db`, `internal/api`, `config`, `cmd/server`).
- [ ] Run `go build ./...` and `go vet ./...` — expect clean (the one pre-existing unrelated `internal/observability` vet failure from earlier tonight is not introduced by this plan and is out of scope to fix here).
- [ ] Confirm `docker compose config --quiet` still exits 0 with the new environment variable present.
