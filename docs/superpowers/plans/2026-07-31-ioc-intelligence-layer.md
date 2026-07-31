# IOC Intelligence Layer (Phase D, Final) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add expiration, suppression awareness, and customer IOC import to the registry — the three genuinely new, real pieces of the "Intelligence Layer" that close out the whole IOC Handling initiative.

**Architecture:** `iocs` gains `suppressed`/`suppression_reason` columns. A daily background sweep (mirroring `internal/detect/retention.go`'s exact shape) transitions stale rows to `expired`. Two near-duplicate `INSERT INTO iocs` statements (Phase 0+A's `upsertIOC`, Phase C's `RegisterGenerated`) consolidate into one `upsertIOCFull` before a third caller (`ImportManual`) is added. Two new admin-only endpoints (`suppress`, `import`) share one new permission.

**Tech Stack:** Go (`internal/iocregistry`, `internal/analytics`, `internal/api`, `internal/auth`, `internal/db`, `cmd/server`), `*pgxpool.Pool`.

## Global Constraints

- No export formats (STIX/YARA/Suricata/Snort/CEF/LEEF/etc.) — no consumer, explicitly out of scope per the spec.
- No MISP/OpenCTI-style import — that domain belongs to `internal/ioc`/`ioc_enrichment`, a separate pre-existing system.
- No confidence/severity/maliciousness scoring — nothing computes a real value for any of these.
- No IOC versioning.
- No frontend — backend-only, matching every foundation phase this initiative.
- `POST /api/iocs/{id}/suppress` and `POST /api/iocs/import` are both admin-only, gated by a single new `auth.CanManageIOCs` permission.
- Every task ends with a commit + `git push`.
- **This is the last plan of the whole IOC Handling initiative.** Task 6's completion report confirms all 4 phases (0+A, B, C, D) are done — not that more phases remain.

---

### Task 1: Schema + `SetSuppressed`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (2 `ALTER TABLE` + 1 partial index, in `EnsureSchema`)
- Create: `orchestrator/internal/iocregistry/suppress.go`
- Test: `orchestrator/internal/iocregistry/suppress_test.go`

**Interfaces:**
- Produces: `func iocregistry.SetSuppressed(ctx context.Context, pool *pgxpool.Pool, iocID string, suppressed bool, reason string) error`. Task 2's handler calls this directly.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/iocregistry/suppress_test.go`:

```go
package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSetSuppressed_SetsFlagAndReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO iocs (type, value, source) VALUES ('command_line', 'known-lab-tool', 'detection_alert') RETURNING id`).
			Scan(&id); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}

		if err := SetSuppressed(context.Background(), pool, id, true, "known lab tool"); err != nil {
			t.Fatalf("SetSuppressed: %v", err)
		}

		var suppressed bool
		var reason string
		if err := pool.QueryRow(context.Background(),
			`SELECT suppressed, suppression_reason FROM iocs WHERE id = $1`, id).Scan(&suppressed, &reason); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !suppressed || reason != "known lab tool" {
			t.Errorf("suppressed/reason = %v/%q, want true/\"known lab tool\"", suppressed, reason)
		}
	})
}

func TestSetSuppressed_UnsuppressClearsReasonRegardlessOfArgument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO iocs (type, value, source) VALUES ('command_line', 'previously-suppressed', 'detection_alert') RETURNING id`).
			Scan(&id); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		if err := SetSuppressed(context.Background(), pool, id, true, "reason A"); err != nil {
			t.Fatalf("first SetSuppressed: %v", err)
		}

		// Unsuppressing with a non-empty reason argument still clears it --
		// a reason only makes sense while suppressed.
		if err := SetSuppressed(context.Background(), pool, id, false, "irrelevant text"); err != nil {
			t.Fatalf("second SetSuppressed: %v", err)
		}

		var suppressed bool
		var reason string
		if err := pool.QueryRow(context.Background(),
			`SELECT suppressed, suppression_reason FROM iocs WHERE id = $1`, id).Scan(&suppressed, &reason); err != nil {
			t.Fatalf("query: %v", err)
		}
		if suppressed || reason != "" {
			t.Errorf("suppressed/reason = %v/%q, want false/\"\"", suppressed, reason)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/iocregistry/... -run TestSetSuppressed -v`
Expected: FAIL — build error, `SetSuppressed` undefined, and `suppressed`/`suppression_reason` columns don't exist yet.

- [ ] **Step 3: Add the schema columns**

In `orchestrator/internal/db/postgres.go`, find:

```go
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_technique ON ioc_sightings (technique_id)`,
```

Immediately after it, insert:

```go
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_technique ON ioc_sightings (technique_id)`,

		// Phase D: suppression awareness (iochandling.txt §22) -- an operator's
		// judgment that an IOC is a known false-positive/environment-specific
		// exception, distinct from the lifecycle Status column. See
		// docs/superpowers/specs/2026-07-31-ioc-intelligence-layer-design.md.
		`ALTER TABLE iocs ADD COLUMN IF NOT EXISTS suppressed boolean NOT NULL DEFAULT false`,
		`ALTER TABLE iocs ADD COLUMN IF NOT EXISTS suppression_reason text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_suppressed ON iocs (suppressed) WHERE suppressed = true`,
```

- [ ] **Step 4: Implement `SetSuppressed`**

Create `orchestrator/internal/iocregistry/suppress.go`:

```go
package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SetSuppressed sets or clears an IOC's suppression state. reason is stored verbatim when
// suppressing; cleared (empty string) when un-suppressing, regardless of what's passed --
// a reason only makes sense while actually suppressed.
func SetSuppressed(ctx context.Context, pool *pgxpool.Pool, iocID string, suppressed bool, reason string) error {
	if !suppressed {
		reason = ""
	}
	_, err := pool.Exec(ctx,
		`UPDATE iocs SET suppressed = $1, suppression_reason = $2 WHERE id = $3`,
		suppressed, reason, iocID)
	return err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/iocregistry/... -v`
Expected: build/vet clean; every test in the package PASSES, including the 2 new ones and every pre-existing Phase 0+A/B/C test.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/iocregistry/suppress.go orchestrator/internal/iocregistry/suppress_test.go
git commit -m "feat(ioc): add suppression columns and SetSuppressed

suppressed/suppression_reason are a separate axis from Status --
lifecycle vs. an operator's judgment that a detection gap is a known,
accepted exception. iochandling.txt §22.

Phase D (Intelligence Layer, final phase) of the IOC handling
initiative, piece 1/5."
git push
```

---

### Task 2: Suppression endpoint

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go` (new `CanManageIOCs` permission, admin-only)
- Modify: `orchestrator/internal/auth/permissions_test.go` (matching admin-grant entry)
- Create: `orchestrator/internal/api/ioc_suppress_handler.go`
- Test: `orchestrator/internal/api/ioc_suppress_handler_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `iocregistry.SetSuppressed` (Task 1).
- Produces: `auth.CanManageIOCs` — Task 5's import handler reuses this same permission.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/ioc_suppress_handler_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSetIOCSuppressed_SetsFlagAndReturnsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO iocs (type, value, source) VALUES ('command_line', 'suppress-me', 'detection_alert') RETURNING id`).
			Scan(&id); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}

		h := &Handler{db: pool}
		body := `{"suppressed":true,"reason":"known lab tool"}`
		req := httptest.NewRequest(http.MethodPost, "/api/iocs/"+id+"/suppress", strings.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rec := httptest.NewRecorder()
		h.SetIOCSuppressed(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["suppressed"] != true || got["reason"] != "known lab tool" {
			t.Errorf("response = %+v, want suppressed=true reason=\"known lab tool\"", got)
		}

		var suppressed bool
		if err := pool.QueryRow(context.Background(), `SELECT suppressed FROM iocs WHERE id = $1`, id).Scan(&suppressed); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !suppressed {
			t.Error("iocs.suppressed = false after suppress call")
		}
	})
}

func TestSetIOCSuppressed_InvalidBody_Returns400(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/iocs/x/suppress", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.SetIOCSuppressed(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSetIOCSuppressed -v`
Expected: FAIL — `h.SetIOCSuppressed` undefined (compile error).

- [ ] **Step 3: Add the `CanManageIOCs` permission**

In `orchestrator/internal/auth/permissions.go`, find:

```go
	// Admin-only: global search reindex trigger.
	CanReindexSearch Permission = "search:reindex"
```

Replace with:

```go
	// Admin-only: global search reindex trigger.
	CanReindexSearch Permission = "search:reindex"

	// Admin-only: IOC registry management (suppress/unsuppress, customer import).
	CanManageIOCs Permission = "iocs:manage"
```

Then find (inside the `RoleAdmin` grant block):

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanViewTamperEvents: true,
```

Replace with:

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanManageIOCs: true, CanViewTamperEvents: true,
```

In `orchestrator/internal/auth/permissions_test.go`, find the matching line (the test's own copy of the same admin-grant list):

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanViewTamperEvents: true,
```

Replace with:

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanManageIOCs: true, CanViewTamperEvents: true,
```

- [ ] **Step 4: Implement the handler**

Create `orchestrator/internal/api/ioc_suppress_handler.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/iocregistry"
)

// POST /api/iocs/{id}/suppress -- {"suppressed": true, "reason": "known lab tool"}.
// Admin-only (CanManageIOCs).
func (h *Handler) SetIOCSuppressed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Suppressed bool   `json:"suppressed"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := iocregistry.SetSuppressed(r.Context(), h.db, id, body.Suppressed, body.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"id": id, "suppressed": body.Suppressed, "reason": body.Reason})
}
```

- [ ] **Step 5: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/iocs", h.GetIOCs)
		r.Get("/api/analytics/iocs", h.GetIOCAnalytics)
```

Replace with:

```go
		r.Get("/api/iocs", h.GetIOCs)
		r.Get("/api/analytics/iocs", h.GetIOCAnalytics)
		r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/{id}/suppress", h.SetIOCSuppressed)
```

- [ ] **Step 6: Add the RBAC matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/analytics/iocs", tierAny, ""},
```

Replace with:

```go
	{http.MethodGet, "/api/analytics/iocs", tierAny, ""},
	{http.MethodPost, "/api/iocs/{id}/suppress", tierPermission, auth.CanManageIOCs},
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/auth/... ./internal/api/... -run "TestSetIOCSuppressed|TestRBACMatrix_NoDrift|TestRole" -v`
Expected: build/vet clean; every matched test PASSES, including `internal/auth`'s existing role-permission tests (confirms `CanManageIOCs`'s grant didn't break any existing role assertion).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/auth/permissions.go orchestrator/internal/auth/permissions_test.go orchestrator/internal/api/ioc_suppress_handler.go orchestrator/internal/api/ioc_suppress_handler_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add POST /api/iocs/{id}/suppress, admin-only

New CanManageIOCs permission -- also used by Task 5's import endpoint.

Phase D of the IOC handling initiative, piece 2/5."
git push
```

---

### Task 3: Surface suppression in `GetIOCs` and `IOCAnalytics`

**Files:**
- Modify: `orchestrator/internal/api/ioc_handlers.go`
- Modify: `orchestrator/internal/api/ioc_handlers_test.go`
- Modify: `orchestrator/internal/analytics/ioc.go`
- Modify: `orchestrator/internal/analytics/ioc_test.go`

**Interfaces:**
- Consumes: `iocs.suppressed`/`suppression_reason` (Task 1).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing tests**

In `orchestrator/internal/api/ioc_handlers_test.go`, add this test (append to the end of the file):

```go
func TestGetIOCs_ExposesSuppressionState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "suppressed-value", "agent-1", "sc-1")
		mustExecAPI(t, pool, `UPDATE iocs SET suppressed = true, suppression_reason = 'known lab tool' WHERE value = 'suppressed-value'`)

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?value=suppressed-value", nil))
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %+v, want exactly 1 row", got)
		}
		if got[0]["suppressed"] != true || got[0]["suppressionReason"] != "known lab tool" {
			t.Errorf("row = %+v, want suppressed=true suppressionReason=\"known lab tool\"", got[0])
		}
	})
}
```

In `orchestrator/internal/analytics/ioc_test.go`, add this test (append to the end of the file):

```go
func TestIOCAnalytics_HighestBypassRate_ExcludesSuppressedButFrequentlyReusedIncludesIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		id := seedIOCAnalytics(t, pool, "command_line", "cmd-suppressed-bypass", 7, "undetected", "missed", "NOW()")
		mustExec(t, pool, `UPDATE iocs SET suppressed = true, suppression_reason = 'known lab tool' WHERE id = $1`, id)

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		for _, e := range got.HighestBypassRate {
			if e.Value == "cmd-suppressed-bypass" {
				t.Errorf("HighestBypassRate = %+v, want the suppressed IOC excluded", got.HighestBypassRate)
			}
		}
		found := false
		for _, e := range got.FrequentlyReused {
			if e.Value == "cmd-suppressed-bypass" {
				found = true
			}
		}
		if !found {
			t.Errorf("FrequentlyReused = %+v, want the suppressed IOC still included (only bypass-rate excludes suppressed)", got.FrequentlyReused)
		}
	})
}
```

`seedIOCAnalytics` (from `internal/analytics/ioc_test.go`, Phase B) already returns the seeded row's `id` (`func seedIOCAnalytics(...) string`) — use it directly as above, no signature change needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... ./internal/analytics/... -run "TestGetIOCs_ExposesSuppressionState|TestIOCAnalytics_HighestBypassRate_ExcludesSuppressed" -v`
Expected: FAIL — `iocRow` has no `suppressed`/`suppressionReason` fields yet (build error or nil map access), and the suppressed IOC still appears in `HighestBypassRate`.

- [ ] **Step 3: Update `iocRow` and `GetIOCs`'s query**

In `orchestrator/internal/api/ioc_handlers.go`, find:

```go
type iocRow struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	Source        string `json:"source"`
	Origin        string `json:"origin"`
	Status        string `json:"status"`
	FirstSeen     time.Time `json:"firstSeen"`
	LastSeen      time.Time `json:"lastSeen"`
	SightingCount int       `json:"sightingCount"`
}
```

Replace with:

```go
type iocRow struct {
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	Value             string    `json:"value"`
	Source            string    `json:"source"`
	Origin            string    `json:"origin"`
	Status            string    `json:"status"`
	FirstSeen         time.Time `json:"firstSeen"`
	LastSeen          time.Time `json:"lastSeen"`
	SightingCount     int       `json:"sightingCount"`
	Suppressed        bool      `json:"suppressed"`
	SuppressionReason string    `json:"suppressionReason"`
}
```

Then find:

```go
	query := `SELECT DISTINCT i.id, i.type, i.value, i.source, i.origin, i.status,
	                  i.first_seen, i.last_seen, i.sighting_count
	          FROM iocs i`
```

Replace with:

```go
	query := `SELECT DISTINCT i.id, i.type, i.value, i.source, i.origin, i.status,
	                  i.first_seen, i.last_seen, i.sighting_count, i.suppressed, i.suppression_reason
	          FROM iocs i`
```

Then find:

```go
		if err := rows.Scan(&row.ID, &row.Type, &row.Value, &row.Source, &row.Origin,
			&row.Status, &row.FirstSeen, &row.LastSeen, &row.SightingCount); err != nil {
			continue
		}
```

Replace with:

```go
		if err := rows.Scan(&row.ID, &row.Type, &row.Value, &row.Source, &row.Origin,
			&row.Status, &row.FirstSeen, &row.LastSeen, &row.SightingCount,
			&row.Suppressed, &row.SuppressionReason); err != nil {
			continue
		}
```

- [ ] **Step 4: Exclude suppressed IOCs from `HighestBypassRate` only**

In `orchestrator/internal/analytics/ioc.go`, find:

```go
	bypassed, err := iocsByVerdict(ctx, pool, limit, "undetected")
	if err != nil {
		return result, err
	}
	result.HighestBypassRate = bypassed
```

Replace with:

```go
	bypassed, err := iocsByVerdictExcludingSuppressed(ctx, pool, limit, "undetected")
	if err != nil {
		return result, err
	}
	result.HighestBypassRate = bypassed
```

Then find:

```go
func iocsByVerdict(ctx context.Context, pool *pgxpool.Pool, limit int, verdicts ...string) ([]IOCAnalyticsEntry, error) {
	return scanIOCEntries(ctx, pool, `
		SELECT DISTINCT i.id, i.type, i.value, i.sighting_count
		FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id
		WHERE s.detection_verdict = ANY($2)
		ORDER BY i.sighting_count DESC LIMIT $1`, limit, verdicts)
}
```

Replace with:

```go
func iocsByVerdict(ctx context.Context, pool *pgxpool.Pool, limit int, verdicts ...string) ([]IOCAnalyticsEntry, error) {
	return scanIOCEntries(ctx, pool, `
		SELECT DISTINCT i.id, i.type, i.value, i.sighting_count
		FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id
		WHERE s.detection_verdict = ANY($2)
		ORDER BY i.sighting_count DESC LIMIT $1`, limit, verdicts)
}

// iocsByVerdictExcludingSuppressed mirrors iocsByVerdict but excludes suppressed IOCs --
// only used for HighestBypassRate (iochandling.txt §22: an operator-accepted exception
// must not be reported as an undetected bypass). MostDetected still uses the unfiltered
// iocsByVerdict; a suppressed IOC that was actually detected isn't a misleading count.
func iocsByVerdictExcludingSuppressed(ctx context.Context, pool *pgxpool.Pool, limit int, verdicts ...string) ([]IOCAnalyticsEntry, error) {
	return scanIOCEntries(ctx, pool, `
		SELECT DISTINCT i.id, i.type, i.value, i.sighting_count
		FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id
		WHERE s.detection_verdict = ANY($2) AND NOT i.suppressed
		ORDER BY i.sighting_count DESC LIMIT $1`, limit, verdicts)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... ./internal/analytics/... -v`
Expected: build/vet clean; every test in both packages PASSES, including the 2 new ones and every pre-existing Phase 0+A/B/C test.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/ioc_handlers.go orchestrator/internal/api/ioc_handlers_test.go orchestrator/internal/analytics/ioc.go orchestrator/internal/analytics/ioc_test.go
git commit -m "feat(ioc): surface suppression in GetIOCs, exclude it from HighestBypassRate

GetIOCs shows suppressed/suppressionReason on every row -- an
operator must be able to see suppression state via the same read path
they already use. IOCAnalytics.HighestBypassRate excludes suppressed
rows (the literal 'don't incorrectly report a detection gap' scenario
from iochandling.txt §22); the other 3 lists stay unfiltered.

Phase D of the IOC handling initiative, piece 3/5."
git push
```

---

### Task 4: Expiration sweep

**Files:**
- Create: `orchestrator/internal/iocregistry/expire.go`
- Test: `orchestrator/internal/iocregistry/expire_test.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Produces: `func iocregistry.StartExpiration(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration)`, `const iocregistry.DefaultStaleAfter`. Wired once at server startup; nothing else depends on this.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/iocregistry/expire_test.go`:

```go
package iocregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedIOCWithLastSeen(t *testing.T, pool *pgxpool.Pool, value, status string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO iocs (type, value, source, status, last_seen)
		VALUES ('command_line', $1, 'detection_alert', $2, $3)
		RETURNING id`, value, status, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed ioc %s: %v", value, err)
	}
	return id
}

func TestExpireStale_TransitionsOldObservedRowsToExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		staleID := seedIOCWithLastSeen(t, pool, "cmd-stale", "observed", time.Now().Add(-60*24*time.Hour))
		freshID := seedIOCWithLastSeen(t, pool, "cmd-fresh", "observed", time.Now())
		archivedID := seedIOCWithLastSeen(t, pool, "cmd-already-archived", "archived", time.Now().Add(-60*24*time.Hour))

		expireStale(context.Background(), pool, 30*24*time.Hour)

		var staleStatus, freshStatus, archivedStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM iocs WHERE id = $1`, staleID).Scan(&staleStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM iocs WHERE id = $1`, freshID).Scan(&freshStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM iocs WHERE id = $1`, archivedID).Scan(&archivedStatus)

		if staleStatus != "expired" {
			t.Errorf("stale IOC status = %q, want expired", staleStatus)
		}
		if freshStatus != "observed" {
			t.Errorf("fresh IOC status = %q, want unchanged observed", freshStatus)
		}
		if archivedStatus != "archived" {
			t.Errorf("already-archived IOC status = %q, want unchanged archived (not re-touched)", archivedStatus)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/iocregistry/... -run TestExpireStale -v`
Expected: FAIL — build error, `expireStale` undefined.

- [ ] **Step 3: Implement the expiration sweep**

Create `orchestrator/internal/iocregistry/expire.go`:

```go
package iocregistry

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultStaleAfter matches internal/detect/retention.go's own precedent for how long
// operational data stays relevant before it's no longer worth surfacing as "current."
const DefaultStaleAfter = 30 * 24 * time.Hour

// StartExpiration prunes stale IOCs once a day, mirroring internal/detect/retention.go's
// exact shape. Best-effort; logs and continues on error.
func StartExpiration(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		expireStale(ctx, pool, staleAfter)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				expireStale(ctx, pool, staleAfter)
			}
		}
	}()
}

func expireStale(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) {
	// make_interval(secs => ...) avoids any ambiguity from feeding Go's
	// time.Duration string format ("720h0m0s") into Postgres's interval
	// literal parser -- a plain float8 seconds value has one unambiguous
	// interpretation.
	ct, err := pool.Exec(ctx, `
		UPDATE iocs SET status = $1
		WHERE last_seen < NOW() - make_interval(secs => $2)
		  AND status NOT IN ($1, $3)`,
		string(StatusExpired), staleAfter.Seconds(), string(StatusArchived))
	if err != nil {
		log.Printf("[iocregistry] expiration sweep failed: %v", err)
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		log.Printf("[iocregistry] expired %d stale IOC(s)", n)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/iocregistry/... -v`
Expected: build/vet clean; every test in the package PASSES.

- [ ] **Step 5: Wire `StartExpiration` into server startup**

In `orchestrator/cmd/server/main.go`, find:

```go
	// ── Detection Retention ───────────────────────────────────────────────
	// Prunes raw detection alert blobs older than 30 days daily (summaries are
	// kept forever) so large BAS environments don't accumulate huge JSON blobs.
	detect.StartRetention(context.Background(), pool)
```

Replace with:

```go
	// ── Detection Retention ───────────────────────────────────────────────
	// Prunes raw detection alert blobs older than 30 days daily (summaries are
	// kept forever) so large BAS environments don't accumulate huge JSON blobs.
	detect.StartRetention(context.Background(), pool)

	// ── IOC Expiration ───────────────────────────────────────────────────
	// Transitions stale iocs rows to 'expired' daily -- the first real use of
	// that lifecycle status since Phase 0+A defined it.
	iocregistry.StartExpiration(context.Background(), pool, iocregistry.DefaultStaleAfter)
```

Then find the import block:

```go
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/license"
```

Replace with:

```go
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/iocregistry"
	"github.com/audspect/bas/internal/license"
```

- [ ] **Step 6: Run the full build to confirm `cmd/server` compiles**

Run: `cd orchestrator && go build ./...`
Expected: clean build, no errors.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/iocregistry/expire.go orchestrator/internal/iocregistry/expire_test.go orchestrator/cmd/server/main.go
git commit -m "feat(ioc): add daily expiration sweep, wired at server startup

StartExpiration mirrors internal/detect/retention.go's exact ticker
shape. Transitions stale iocs rows (last_seen older than 30 days,
not already expired/archived) to Status=expired -- the first real
lifecycle transition since Phase 0+A defined the states.

Phase D of the IOC handling initiative, piece 4/5."
git push
```

---

### Task 5: Consolidate INSERTs + customer import

**Files:**
- Modify: `orchestrator/internal/iocregistry/extract.go` (new `upsertIOCFull`, `upsertIOC` becomes a thin wrapper)
- Modify: `orchestrator/internal/iocregistry/generate.go` (`RegisterGenerated` calls `upsertIOCFull`)
- Create: `orchestrator/internal/iocregistry/import.go`
- Test: `orchestrator/internal/iocregistry/import_test.go`
- Create: `orchestrator/internal/api/ioc_import_handler.go`
- Test: `orchestrator/internal/api/ioc_import_handler_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `auth.CanManageIOCs` (Task 2).
- Produces: `func iocregistry.ImportManual(ctx context.Context, pool *pgxpool.Pool, entries []ImportEntry) (written int, err error)`, `type iocregistry.ImportEntry struct{Type Type; Value string}`. Terminal task of Phase D — nothing later depends on this.

- [ ] **Step 1: Write the failing consolidation + import test**

Create `orchestrator/internal/iocregistry/import_test.go`:

```go
package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestImportManual_WritesEntriesWithCustomerOriginAndDraftStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		entries := []ImportEntry{
			{Type: TypeFilename, Value: "customer-known-tool.exe"},
			{Type: TypeMutex, Value: `Global\customer-known-mutex`},
		}
		written, err := ImportManual(context.Background(), pool, entries)
		if err != nil {
			t.Fatalf("ImportManual: %v", err)
		}
		if written != 2 {
			t.Errorf("written = %d, want 2", written)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE origin = 'customer' AND status = 'draft'`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 2 {
			t.Errorf("iocs with origin=customer status=draft = %d, want 2", count)
		}
	})
}

func TestImportManual_DedupesAgainstExistingRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := upsertIOC(context.Background(), pool, TypeFilename, "already-exists.exe", SourceDetectionAlert, nil); err != nil {
			t.Fatalf("seed existing ioc: %v", err)
		}

		written, err := ImportManual(context.Background(), pool, []ImportEntry{
			{Type: TypeFilename, Value: "already-exists.exe"},
		})
		if err != nil {
			t.Fatalf("ImportManual: %v", err)
		}
		if written != 1 {
			t.Errorf("written = %d, want 1 (upsert still counts as written)", written)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE type = 'filename' AND value = 'already-exists.exe'`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("iocs rows for the same value = %d, want 1 (dedup, no duplicate row)", count)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/iocregistry/... -run TestImportManual -v`
Expected: FAIL — build error, `ImportManual`/`ImportEntry` undefined.

- [ ] **Step 3: Consolidate the INSERT into `upsertIOCFull`**

In `orchestrator/internal/iocregistry/extract.go`, find:

```go
// upsertIOC inserts a new iocs row or, if (type, value) already exists,
// bumps last_seen/sighting_count -- the dedup contract. metadata is only
// applied on insert (first observation); it is not merged on repeat
// sightings, since a later observation of the same command line carrying a
// different threatName would otherwise silently overwrite the first.
func upsertIOC(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, metadata map[string]any) (string, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	var id string
	err = pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, metadata)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(source), metaJSON,
	).Scan(&id)
	return id, err
}
```

Replace with:

```go
// upsertIOC inserts a new iocs row or, if (type, value) already exists,
// bumps last_seen/sighting_count -- the dedup contract. metadata is only
// applied on insert (first observation); it is not merged on repeat
// sightings, since a later observation of the same command line carrying a
// different threatName would otherwise silently overwrite the first.
// Thin wrapper over upsertIOCFull with this package's original defaults --
// unchanged behavior for every Phase 0+A/B/C caller.
func upsertIOC(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, metadata map[string]any) (string, error) {
	return upsertIOCFull(ctx, pool, t, value, source, OriginBuiltIn, StatusObserved, metadata)
}

// upsertIOCFull is the one INSERT INTO iocs statement -- upsertIOC (above),
// RegisterGenerated (generate.go), and ImportManual (import.go) all call this
// instead of each maintaining their own near-identical SQL.
func upsertIOCFull(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, origin Origin, status Status, metadata map[string]any) (string, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	var id string
	err = pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, origin, status, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(source), string(origin), string(status), metaJSON,
	).Scan(&id)
	return id, err
}
```

In `orchestrator/internal/iocregistry/generate.go`, find:

```go
func RegisterGenerated(ctx context.Context, pool *pgxpool.Pool, t Type, value, scenarioID, runID, agentID, techniqueID string) error {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, origin, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(SourceVariant), string(OriginGenerated), string(StatusGenerated),
	).Scan(&id)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id)
		VALUES ($1, $2, $3, $4, $5)`,
		id, scenarioID, runID, agentID, techniqueID)
	return err
}
```

Replace with:

```go
func RegisterGenerated(ctx context.Context, pool *pgxpool.Pool, t Type, value, scenarioID, runID, agentID, techniqueID string) error {
	id, err := upsertIOCFull(ctx, pool, t, value, SourceVariant, OriginGenerated, StatusGenerated, nil)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id)
		VALUES ($1, $2, $3, $4, $5)`,
		id, scenarioID, runID, agentID, techniqueID)
	return err
}
```

- [ ] **Step 4: Implement `ImportManual`**

Create `orchestrator/internal/iocregistry/import.go`:

```go
package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ImportEntry is one caller-supplied (type, value) pair to register.
type ImportEntry struct {
	Type  Type   `json:"type"`
	Value string `json:"value"`
}

// ImportManual writes each entry as Origin=customer, Status=draft, Source=manual --
// customer-provided IOCs meant to drive future simulations, not observations of anything
// that has happened yet. Best-effort per-entry; returns the count actually written and
// the first error encountered, if any (partial success is reported, not silently lost).
func ImportManual(ctx context.Context, pool *pgxpool.Pool, entries []ImportEntry) (written int, err error) {
	for _, e := range entries {
		if _, ierr := upsertIOCFull(ctx, pool, e.Type, e.Value, SourceManual, OriginCustomer, StatusDraft, nil); ierr != nil {
			if err == nil {
				err = ierr
			}
			continue
		}
		written++
	}
	return written, err
}
```

- [ ] **Step 5: Run `iocregistry` tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/iocregistry/... -v`
Expected: build/vet clean; every test in the package PASSES, including the 2 new import tests and every pre-existing Phase 0+A/B/C/D test (this is the regression check for the `upsertIOCFull` consolidation — `extract_test.go` and `generate_test.go` must both still pass unchanged).

- [ ] **Step 6: Write the failing handler test**

Create `orchestrator/internal/api/ioc_import_handler_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestImportIOCs_WritesEntriesAndReturnsCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		body := `{"entries":[{"type":"filename","value":"import-test-1.exe"},{"type":"mutex","value":"Global\\import-test-2"}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/iocs/import", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ImportIOCs(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["written"] != float64(2) {
			t.Errorf("written = %v, want 2", got["written"])
		}
	})
}

func TestImportIOCs_InvalidBody_Returns400(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/iocs/import", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.ImportIOCs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
```

(The `pgxpool` import is required by `sharedDB.RunWithPool`'s callback signature even though this file's other test doesn't use it directly — matches every other handler test file's import block in this package.)

- [ ] **Step 7: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestImportIOCs -v`
Expected: FAIL — `h.ImportIOCs` undefined (compile error).

- [ ] **Step 8: Implement the handler, route, and RBAC entry**

Create `orchestrator/internal/api/ioc_import_handler.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/iocregistry"
)

// POST /api/iocs/import -- {"entries":[{"type":"filename","value":"..."}]}. Admin-only
// (CanManageIOCs). Writes each entry as Origin=customer, Status=draft.
func (h *Handler) ImportIOCs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entries []iocregistry.ImportEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	written, err := iocregistry.ImportManual(r.Context(), h.db, body.Entries)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"written": written})
}
```

In `orchestrator/internal/api/routes.go`, find:

```go
		r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/{id}/suppress", h.SetIOCSuppressed)
```

Replace with:

```go
		r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/{id}/suppress", h.SetIOCSuppressed)
		r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/import", h.ImportIOCs)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodPost, "/api/iocs/{id}/suppress", tierPermission, auth.CanManageIOCs},
```

Replace with:

```go
	{http.MethodPost, "/api/iocs/{id}/suppress", tierPermission, auth.CanManageIOCs},
	{http.MethodPost, "/api/iocs/import", tierPermission, auth.CanManageIOCs},
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run "TestImportIOCs|TestRBACMatrix_NoDrift" -v`
Expected: build/vet clean; both tests PASS.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/iocregistry/extract.go orchestrator/internal/iocregistry/generate.go orchestrator/internal/iocregistry/import.go orchestrator/internal/iocregistry/import_test.go orchestrator/internal/api/ioc_import_handler.go orchestrator/internal/api/ioc_import_handler_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(ioc): consolidate INSERT INTO iocs into upsertIOCFull, add customer import

upsertIOC and RegisterGenerated both had their own near-identical
INSERT -- now both call one upsertIOCFull. ImportManual (Origin=
customer, Status=draft, both reserved since Phase 0+A) is the third
caller. POST /api/iocs/import, admin-only, narrowed from
iochandling.txt §17's full MISP/OpenCTI/STIX/CSV ambition -- that
domain already belongs to internal/ioc/ioc_enrichment.

Phase D of the IOC handling initiative, piece 5/5 -- Phase D complete
pending Task 6's full regression."
git push
```

---

### Task 6: Full regression — IOC Handling initiative complete

**Files:** none (verification only)

- [ ] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
If down, start Docker Desktop and poll: `timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"`

- [ ] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If any package fails only under full-suite load (Docker resource contention across concurrent testcontainers was seen repeatedly across Phases 0+A/B/C — `internal/api`, `internal/relationships`), re-run that package standalone: `go test ./internal/<pkg>/... -count=1 -timeout 20m`. A standalone pass confirms it was contention, not a regression.

- [ ] **Step 3: Report completion — the IOC Handling initiative is done**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that the entire IOC Handling initiative (`iochandling.txt`) is now complete across all 4 phases:

- **Phase 0+A** (registry): canonical `IOC` model, `iocs`/`ioc_sightings` tables, extraction from `DetectionAlert`, `GET /api/iocs`.
- **Phase B** (relationships & analytics): technique/verdict correlation, `threatgraph` IOC node, extended `GET /api/iocs` filters, `GET /api/analytics/iocs` dashboard.
- **Phase C** (generation engine): curated ART-argument substitution mechanism, 4 non-network artifact generators, dispatch-time wiring — the curated table itself is empty pending future ART-content review (a stated, honest limitation, not a bug).
- **Phase D** (intelligence layer): expiration, suppression awareness, customer import.

Also flag, as a summary for the user's own tracking (not further work in this plan): the honest, stated non-goals across all 4 phases that remain out of scope for the whole initiative if ever revisited — network-touching artifact generation (domain/IP/URL/certificate), MISP/OpenCTI-style IOC-specific import/export, IOC Timeline/Variants/Versioning, confidence/severity scoring, and a frontend for any of this.
