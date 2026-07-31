# IOC Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the canonical IOC model and registry storage, and populate it by extracting IOC-shaped data (command lines, process names) that already flows through `SubmitRunDetections` today — no new generation capability, just making existing data queryable.

**Architecture:** New `internal/ioc` package owns the canonical `IOC` type and extraction logic. Two new tables (`iocs`, one row per distinct `(type, value)`; `ioc_sightings`, one row per observation) store it, following this codebase's existing dedup-by-unique-index and loose-text-column-linkage conventions. `SubmitRunDetections` calls the extractor best-effort, right after its existing `UPDATE scenario_runs` write. A new `GET /api/iocs` exposes flat search.

**Tech Stack:** Go (`internal/ioc`, `internal/api`, `internal/db`), `*pgxpool.Pool`.

## Global Constraints

- `iocs.type` uses the full 14-value taxonomy from the spec, but only `command_line` and `process` will actually be populated by this plan — no other producer exists yet. Don't build extraction logic for types with no real data source.
- `ThreatName` is never extracted as its own IOC — it's a classification label, not an indicator. It's stored in the `command_line` row's `metadata` JSONB.
- Dedup on `(type, value)`: the same literal value seen across multiple runs updates one `iocs` row's `last_seen`/`sighting_count` and adds a new `ioc_sightings` row — it never creates a second `iocs` row.
- No FK constraints from `ioc_sightings` to `scenario_runs`/`agents` (plain text columns, matching `action_requests.target_identifier`'s existing convention) — and specifically no `ON DELETE CASCADE`, since `scenario_runs`'s existing cascade to `agents` was flagged as a real risk earlier this session (auto-retire-on-uninstall work).
- Extraction failure must never fail the `SubmitRunDetections` request itself — best-effort, logged.
- New route registered `tierAny` (Viewer+), matching every other read-only endpoint.
- Backend-only — no frontend in this phase.
- Every task ends with a commit + `git push`.

---

### Task 1: Canonical model + storage + extraction

**Files:**
- Create: `orchestrator/internal/ioc/types.go`
- Create: `orchestrator/internal/ioc/extract.go`
- Test: `orchestrator/internal/ioc/extract_test.go`
- Modify: `orchestrator/internal/db/postgres.go` (new tables, in `EnsureSchema`)

**Interfaces:**
- Consumes: `models.SimulationResult` (`internal/models/schema.go:36`), specifically its `DetectionAlert *models.DetectionAlert` field (`schema.go:99-109`: `CommandLine`, `ProcessName`, `ThreatName`).
- Produces: `type ioc.Type string`, `type ioc.Source string`, `type ioc.Origin string`, `type ioc.Status string`, `type ioc.IOC struct{...}` (all per the spec), `func ioc.ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool, scenarioID, runID, agentID string, res models.SimulationResult) error`. Task 2 calls this function directly. Task 3's handler queries the `iocs`/`ioc_sightings` tables this task creates.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/ioc/extract_test.go`:

```go
package ioc

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

func detectionResult(commandLine, processName, threatName string) models.SimulationResult {
	return models.SimulationResult{
		DetectionAlert: &models.DetectionAlert{
			CommandLine: commandLine,
			ProcessName: processName,
			ThreatName:  threatName,
		},
	}
}

func TestExtractFromDetectionAlert_CreatesCommandLineAndProcessRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("powershell -enc AAAA", "powershell.exe", "Trojan:Win32/Meterpreter")
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}

		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM iocs`).Scan(&count); err != nil {
			t.Fatalf("count iocs: %v", err)
		}
		if count != 2 {
			t.Errorf("iocs count = %d, want 2 (command_line + process)", count)
		}

		var metaThreatName string
		if err := pool.QueryRow(context.Background(),
			`SELECT metadata->>'threatName' FROM iocs WHERE type = 'command_line' AND value = $1`,
			"powershell -enc AAAA").Scan(&metaThreatName); err != nil {
			t.Fatalf("query command_line row: %v", err)
		}
		if metaThreatName != "Trojan:Win32/Meterpreter" {
			t.Errorf("metadata.threatName = %q, want Trojan:Win32/Meterpreter", metaThreatName)
		}

		var sightingCount int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM ioc_sightings`).Scan(&sightingCount); err != nil {
			t.Fatalf("count sightings: %v", err)
		}
		if sightingCount != 2 {
			t.Errorf("ioc_sightings count = %d, want 2", sightingCount)
		}
	})
}

func TestExtractFromDetectionAlert_DedupesAcrossRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("whoami /all", "cmd.exe", "")

		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", res); err != nil {
			t.Fatalf("first extract: %v", err)
		}
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-2", "agent-2", res); err != nil {
			t.Fatalf("second extract: %v", err)
		}

		var iocCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE type = 'command_line' AND value = 'whoami /all'`).Scan(&iocCount); err != nil {
			t.Fatalf("count: %v", err)
		}
		if iocCount != 1 {
			t.Errorf("iocs rows for the same value = %d, want 1 (dedup)", iocCount)
		}

		var sightingCount int
		if err := pool.QueryRow(context.Background(), `
			SELECT COUNT(*) FROM ioc_sightings s JOIN iocs i ON i.id = s.ioc_id
			WHERE i.type = 'command_line' AND i.value = 'whoami /all'`).Scan(&sightingCount); err != nil {
			t.Fatalf("count sightings: %v", err)
		}
		if sightingCount != 2 {
			t.Errorf("sightings for the same value across 2 runs = %d, want 2", sightingCount)
		}

		var storedSightingCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT sighting_count FROM iocs WHERE type = 'command_line' AND value = 'whoami /all'`).Scan(&storedSightingCount); err != nil {
			t.Fatalf("query sighting_count: %v", err)
		}
		if storedSightingCount != 2 {
			t.Errorf("iocs.sighting_count = %d, want 2", storedSightingCount)
		}
	})
}

func TestExtractFromDetectionAlert_NilAlert_NoRowsWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := models.SimulationResult{} // DetectionAlert is nil
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM iocs`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Errorf("iocs count = %d, want 0 for a nil DetectionAlert", count)
		}
	})
}

func TestExtractFromDetectionAlert_EmptyFields_Skipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("", "svchost.exe", "") // no CommandLine
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM iocs`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("iocs count = %d, want 1 (only process, empty CommandLine skipped)", count)
		}
	})
}
```

`sharedDB` will be declared by `TestMain` in Step 3 below.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/ioc/... -run TestExtractFromDetectionAlert -v`
Expected: FAIL — build errors (`ExtractFromDetectionAlert`/`sharedDB` undefined).

- [ ] **Step 3: Add the test boilerplate**

Create `orchestrator/internal/ioc/testmain_test.go` (matching the exact pattern every other Postgres-backed package this session uses):

```go
package ioc

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}
```

- [ ] **Step 4: Add the `iocs`/`ioc_sightings` tables**

In `orchestrator/internal/db/postgres.go`, find:

```go
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_variant_findings_run_task ON variant_findings (variant_run_id, task_id)`,
```

Immediately after it, insert:

```go
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_variant_findings_run_task ON variant_findings (variant_run_id, task_id)`,

		// iocs / ioc_sightings: canonical IOC registry (Phase 0+A of the IOC
		// handling initiative). One iocs row per distinct (type, value);
		// ioc_sightings is the per-observation junction, never deduped --
		// the same value seen on 2 agents is 2 sightings, 1 IOC. See
		// docs/superpowers/specs/2026-07-31-ioc-registry-design.md.
		`CREATE TABLE IF NOT EXISTS iocs (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type           text        NOT NULL,
			value          text        NOT NULL,
			source         text        NOT NULL,
			origin         text        NOT NULL DEFAULT 'built-in',
			status         text        NOT NULL DEFAULT 'observed',
			first_seen     timestamptz NOT NULL DEFAULT NOW(),
			last_seen      timestamptz NOT NULL DEFAULT NOW(),
			sighting_count int         NOT NULL DEFAULT 1,
			metadata       jsonb       NOT NULL DEFAULT '{}'
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs (type, value)`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs (status)`,

		`CREATE TABLE IF NOT EXISTS ioc_sightings (
			id          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			ioc_id      text        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
			scenario_id text        NOT NULL DEFAULT '',
			run_id      text        NOT NULL DEFAULT '',
			agent_id    text        NOT NULL DEFAULT '',
			observed_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_ioc   ON ioc_sightings (ioc_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_run   ON ioc_sightings (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_agent ON ioc_sightings (agent_id)`,
```

(The `ioc_sightings.ioc_id → iocs.id` cascade is intentional and safe — deleting an `iocs` row should always take its own sightings with it; this is not the risky pattern flagged elsewhere, since nothing external points at `iocs`.)

- [ ] **Step 5: Implement the canonical model**

Create `orchestrator/internal/ioc/types.go`:

```go
package ioc

import "time"

type Type string

const (
	TypeFileHash    Type = "file_hash"
	TypeDomain      Type = "domain"
	TypeURL         Type = "url"
	TypeIP          Type = "ip"
	TypeRegistryKey Type = "registry_key"
	TypeMutex       Type = "mutex"
	TypeService     Type = "service"
	TypeProcess     Type = "process"
	TypeCommandLine Type = "command_line"
	TypeJA3         Type = "ja3"
	TypeUserAgent   Type = "user_agent"
	TypeEmail       Type = "email"
	TypeDNSRecord   Type = "dns_record"
	TypeCertificate Type = "certificate"
)

type Source string

const (
	SourceDetectionAlert Source = "detection_alert"
	SourceScenario       Source = "scenario"
	SourceVariant        Source = "variant"
	SourceManual         Source = "manual"
)

type Origin string

const (
	OriginBuiltIn    Origin = "built-in"
	OriginGenerated  Origin = "generated"
	OriginOpenAEV    Origin = "openaev"
	OriginMISP       Origin = "misp"
	OriginOpenCTI    Origin = "opencti"
	OriginManual     Origin = "manual"
	OriginThreatFeed Origin = "threat-feed"
	OriginCustomer   Origin = "customer"
)

// Status is the lifecycle state. Extraction from already-completed runs
// starts rows at Observed directly -- Draft/Generated/Assigned/Executed
// describe pre-execution stages that, for extracted data, already happened
// before this row existed.
type Status string

const (
	StatusDraft     Status = "draft"
	StatusGenerated Status = "generated"
	StatusAssigned  Status = "assigned"
	StatusExecuted  Status = "executed"
	StatusObserved  Status = "observed"
	StatusDetected  Status = "detected"
	StatusMissed    Status = "missed"
	StatusExpired   Status = "expired"
	StatusArchived  Status = "archived"
)

// IOC is the canonical model every producer (Detection Validation, Variant
// Engine, future Threat Intel imports, Purple Team, DLP validation, Attack
// Path) must emit -- never invent a parallel shape.
type IOC struct {
	ID    string
	Type  Type
	Value string

	Source Source
	Origin Origin

	FirstSeen time.Time
	LastSeen  time.Time

	ScenarioID string
	VariantID  string
	RunID      string
	AgentID    string

	Status   Status
	Metadata map[string]any
}
```

- [ ] **Step 6: Implement extraction**

Create `orchestrator/internal/ioc/extract.go`:

```go
package ioc

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// ExtractFromDetectionAlert pulls IOC-shaped values out of res.DetectionAlert
// (if present) into the iocs/ioc_sightings tables. Best-effort by design of
// its caller (SubmitRunDetections) -- a nil DetectionAlert or empty fields
// are not errors, just nothing to extract.
func ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool, scenarioID, runID, agentID string, res models.SimulationResult) error {
	if res.DetectionAlert == nil {
		return nil
	}
	alert := res.DetectionAlert

	if alert.CommandLine != "" {
		meta := map[string]any{}
		if alert.ThreatName != "" {
			meta["threatName"] = alert.ThreatName
		}
		id, err := upsertIOC(ctx, pool, TypeCommandLine, alert.CommandLine, SourceDetectionAlert, meta)
		if err != nil {
			return err
		}
		if err := recordSighting(ctx, pool, id, scenarioID, runID, agentID); err != nil {
			return err
		}
	}

	if alert.ProcessName != "" {
		id, err := upsertIOC(ctx, pool, TypeProcess, alert.ProcessName, SourceDetectionAlert, nil)
		if err != nil {
			return err
		}
		if err := recordSighting(ctx, pool, id, scenarioID, runID, agentID); err != nil {
			return err
		}
	}

	return nil
}

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

func recordSighting(ctx context.Context, pool *pgxpool.Pool, iocID, scenarioID, runID, agentID string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id)
		VALUES ($1, $2, $3, $4)`,
		iocID, scenarioID, runID, agentID)
	return err
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/ioc/... -v`
Expected: build succeeds; all 4 tests PASS.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/ioc/ orchestrator/internal/db/postgres.go
git commit -m "feat(ioc): add canonical IOC model, registry tables, and extraction

New internal/ioc package: the canonical IOC type every future producer
(Detection Validation, Variant Engine, Threat Intel imports, Purple
Team, DLP validation, Attack Path) must emit, plus the iocs/
ioc_sightings storage and extraction from the one real data source
that exists today -- DetectionAlert.CommandLine/ProcessName. ThreatName
is stored as metadata on the command_line row, not as its own IOC --
it's a classification label, not an indicator.

Phase 0+A of the IOC handling initiative; Phases B/C/D (analytics,
generation, intelligence) are separate, later work."
git push
```

---

### Task 2: Wire extraction into `SubmitRunDetections`

**Files:**
- Modify: `orchestrator/internal/api/detection_handlers.go`
- Test: `orchestrator/internal/api/detection_handlers_test.go` (existing file — add to it if present, else create)

**Interfaces:**
- Consumes: `ioc.ExtractFromDetectionAlert(ctx, pool, scenarioID, runID, agentID, res)` (Task 1).
- Produces: nothing new for later tasks — Task 3's handler reads the tables Task 1 created directly.

- [ ] **Step 1: Confirm current test coverage**

Run: `cd orchestrator && ls internal/api/detection_handlers_test.go 2>&1`

If the file doesn't exist, Step 2 creates it fresh with just the new test. If it exists, add the new test function to it without disturbing existing tests.

- [ ] **Step 2: Write the failing test**

Add this test (to the existing file, or a new `orchestrator/internal/api/detection_handlers_test.go` with `package api` and the same imports pattern as `unenroll_agent_handler_test.go` if starting fresh):

```go
func TestSubmitRunDetections_ExtractsIOCs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results)
			VALUES ('run-ioc-1', 'sc-1', 'agent-1', 'test run', 'completed', $1)`,
			`[{"technique":{"id":"T1059"},"result":"fail","executedAt":"2026-07-31T00:00:00Z"}]`)

		h := &Handler{db: pool}
		body := `{"alerts":[{"channel":"edr","provider":"crowdstrike","eventId":1,
			"timestamp":"2026-07-31T00:00:05Z","threatName":"Trojan:Test",
			"processName":"powershell.exe","commandLine":"whoami /all"}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/run-ioc-1/detections", strings.NewReader(body))
		req = req.WithContext(context.Background())
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "run-ioc-1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE value IN ('whoami /all', 'powershell.exe')`).Scan(&count); err != nil {
			t.Fatalf("count iocs: %v", err)
		}
		if count != 2 {
			t.Errorf("iocs extracted = %d, want 2", count)
		}

		var sightingScenario string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.scenario_id FROM ioc_sightings s JOIN iocs i ON i.id = s.ioc_id
			WHERE i.value = 'whoami /all'`).Scan(&sightingScenario); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if sightingScenario != "sc-1" {
			t.Errorf("sighting scenario_id = %q, want sc-1", sightingScenario)
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitRunDetections_ExtractsIOCs -v`
Expected: FAIL — either a compile error if `detection_handlers_test.go` is new (missing imports get resolved next) or a real failure showing 0 IOCs extracted (extraction not yet wired).

- [ ] **Step 4: Extend the scenario_runs query and wire the extractor**

In `orchestrator/internal/api/detection_handlers.go`, find:

```go
	runID := chi.URLParam(r, "runId")
	var body struct {
		Alerts    []detect.AlertRecord `json:"alerts"`
		Truncated bool                 `json:"truncated"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid detections payload", http.StatusBadRequest)
		return
	}

	// Load the run's executed results to correlate against.
	var resultsRaw []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT results FROM scenario_runs WHERE id = $1`, runID).Scan(&resultsRaw); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
```

Replace with:

```go
	runID := chi.URLParam(r, "runId")
	var body struct {
		Alerts    []detect.AlertRecord `json:"alerts"`
		Truncated bool                 `json:"truncated"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid detections payload", http.StatusBadRequest)
		return
	}

	// Load the run's executed results to correlate against. scenarioID/agentID
	// are also needed for IOC-sighting ownership below.
	var resultsRaw []byte
	var scenarioID, agentID string
	if err := h.db.QueryRow(r.Context(),
		`SELECT scenario_id, agent_id, results FROM scenario_runs WHERE id = $1`, runID).
		Scan(&scenarioID, &agentID, &resultsRaw); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
```

- [ ] **Step 5: Call the extractor after the existing detection-results write**

Find:

```go
	// Refresh findings now that detection verdicts are known — fails that were
	// caught flip missed → detected_only (same-run refinement, idempotent).
	h.upsertFindingsForRun(r.Context(), runID)
	respond(w, map[string]any{
```

Replace with:

```go
	// Refresh findings now that detection verdicts are known — fails that were
	// caught flip missed → detected_only (same-run refinement, idempotent).
	h.upsertFindingsForRun(r.Context(), runID)

	// Best-effort IOC extraction -- never fails the request. See
	// docs/superpowers/specs/2026-07-31-ioc-registry-design.md.
	for i := range results {
		if err := ioc.ExtractFromDetectionAlert(r.Context(), h.db, scenarioID, runID, agentID, results[i]); err != nil {
			log.Printf("[ioc] extraction failed for run %s: %v", runID, err)
		}
	}

	respond(w, map[string]any{
```

Find the file's import block:

```go
import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)
```

Replace with:

```go
import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run TestSubmitRunDetections -v`
Expected: build/vet clean; test PASSES, alongside any pre-existing `TestSubmitRunDetections*` tests still passing.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/detection_handlers.go orchestrator/internal/api/detection_handlers_test.go
git commit -m "feat(api): extract IOCs during detection ingestion

SubmitRunDetections now calls ioc.ExtractFromDetectionAlert for every
result carrying a DetectionAlert, right after the existing
scenario_runs write. Best-effort -- extraction failure is logged, not
returned to the caller, since detection ingestion must never fail
because of a secondary indexing concern."
git push
```

---

### Task 3: `GET /api/iocs` query API

**Files:**
- Create: `orchestrator/internal/api/ioc_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/ioc_handlers_test.go`

**Interfaces:**
- Consumes: `iocs`/`ioc_sightings` tables (Task 1).
- Produces: nothing new for later tasks — this is the terminal task of Phase 0+A.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/ioc_handlers_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedIOC(t *testing.T, pool *pgxpool.Pool, iocType, value, agentID, scenarioID string) {
	t.Helper()
	var id string
	mustExecAPIReturning(t, pool, &id, `
		INSERT INTO iocs (type, value, source) VALUES ($1, $2, 'detection_alert')
		ON CONFLICT (type, value) DO UPDATE SET last_seen = NOW() RETURNING id`,
		iocType, value)
	mustExecAPI(t, pool, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, agent_id) VALUES ($1, $2, $3)`,
		id, scenarioID, agentID)
}

func TestGetIOCs_FiltersByType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "whoami /all", "agent-1", "sc-1")
		seedIOC(t, pool, "process", "powershell.exe", "agent-1", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?type=process", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 || got[0]["type"] != "process" {
			t.Errorf("got %+v, want exactly 1 process IOC", got)
		}
	})
}

func TestGetIOCs_FiltersByAgentId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-a", "agent-a", "sc-1")
		seedIOC(t, pool, "command_line", "cmd-b", "agent-b", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?agentId=agent-a", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 || got[0]["value"] != "cmd-a" {
			t.Errorf("got %+v, want exactly 1 IOC (cmd-a, seen by agent-a)", got)
		}
	})
}

func TestGetIOCs_NoResults_ReturnsEmptyArrayNotNull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?type=domain", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() == "null" {
			t.Error("body is literal \"null\" -- must be an empty JSON array")
		}
	})
}
```

This introduces `mustExecAPIReturning` — check whether `internal/api`'s existing test suite already has a `QueryRow`-based helper before adding a new one; if `mustExecAPI` (`dashboard_handlers_test.go:102`) only wraps `Exec` (no return value), add this small helper alongside it in the same file:

```go
func mustExecAPIReturning(t *testing.T, pool *pgxpool.Pool, dest *string, sql string, args ...any) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(dest); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
}
```

(Add `"context"` to that file's imports if not already present.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetIOCs -v`
Expected: FAIL — `h.GetIOCs undefined` (compile error).

- [ ] **Step 3: Implement the handler**

Create `orchestrator/internal/api/ioc_handlers.go`:

```go
package api

import (
	"net/http"
	"strconv"
)

type iocRow struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	Source        string `json:"source"`
	Origin        string `json:"origin"`
	Status        string `json:"status"`
	FirstSeen     string `json:"firstSeen"`
	LastSeen      string `json:"lastSeen"`
	SightingCount int    `json:"sightingCount"`
}

// GET /api/iocs?type=&value=&scenarioId=&agentId=&limit= -- flat IOC search.
// Viewer+. Full timeline/correlation views are a later phase; this is a
// direct query over the iocs/ioc_sightings tables only.
func (h *Handler) GetIOCs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	query := `SELECT DISTINCT i.id, i.type, i.value, i.source, i.origin, i.status,
	                  i.first_seen, i.last_seen, i.sighting_count
	          FROM iocs i`
	var joins, where string
	var args []any

	if scenarioID := q.Get("scenarioId"); scenarioID != "" {
		joins = " JOIN ioc_sightings s ON s.ioc_id = i.id"
		args = append(args, scenarioID)
		where += " AND s.scenario_id = $" + strconv.Itoa(len(args))
	}
	if agentID := q.Get("agentId"); agentID != "" {
		if joins == "" {
			joins = " JOIN ioc_sightings s ON s.ioc_id = i.id"
		}
		args = append(args, agentID)
		where += " AND s.agent_id = $" + strconv.Itoa(len(args))
	}
	if iocType := q.Get("type"); iocType != "" {
		args = append(args, iocType)
		where += " AND i.type = $" + strconv.Itoa(len(args))
	}
	if value := q.Get("value"); value != "" {
		args = append(args, "%"+value+"%")
		where += " AND i.value ILIKE $" + strconv.Itoa(len(args))
	}

	query += joins + " WHERE true" + where + " ORDER BY i.last_seen DESC LIMIT " + strconv.Itoa(limit)

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []iocRow{}
	for rows.Next() {
		var row iocRow
		if err := rows.Scan(&row.ID, &row.Type, &row.Value, &row.Source, &row.Origin,
			&row.Status, &row.FirstSeen, &row.LastSeen, &row.SightingCount); err != nil {
			continue
		}
		out = append(out, row)
	}
	respond(w, out)
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/analytics/endpoint-posture", h.GetEndpointPosture)
```

Replace with:

```go
		r.Get("/api/analytics/endpoint-posture", h.GetEndpointPosture)

		// IOC Registry -- flat search over the canonical IOC model
		// (Phase 0+A of the IOC handling initiative).
		r.Get("/api/iocs", h.GetIOCs)
```

- [ ] **Step 5: Add the RBAC matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/analytics/endpoint-posture", tierAny, ""},
```

Replace with:

```go
	{http.MethodGet, "/api/analytics/endpoint-posture", tierAny, ""},
	{http.MethodGet, "/api/iocs", tierAny, ""},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run "TestGetIOCs|TestRBACMatrix_NoDrift" -v`
Expected: build/vet clean; all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/ioc_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/ioc_handlers_test.go
git commit -m "feat(api): add GET /api/iocs flat search

Query by type/value(substring)/scenarioId/agentId over the IOC
registry built in Task 1. Full timeline/correlation/relationship
views are Phase B, not this endpoint."
git push
```

---

### Task 4: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
If down, start Docker Desktop and poll: `timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"`

- [ ] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If `internal/api` alone times out under full-suite load (the known 10-minute-per-package artifact seen repeatedly this session), re-run it standalone: `go test ./internal/api/... -count=1 -timeout 20m`.

- [ ] **Step 3: Report completion**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that Phase 0+A (IOC Registry) is complete, and that Phase B (Relationships & Analytics), Phase C (Generation Engine), and Phase D (Intelligence Layer) remain as the next parts of the roadmap, in that order.
