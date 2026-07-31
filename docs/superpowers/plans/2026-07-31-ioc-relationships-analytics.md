# IOC Relationships & Analytics (Phase B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the IOC registry built in Phase 0+A (`internal/iocregistry`, `iocs`/`ioc_sightings`) correlatable by technique/scenario/run/agent, searchable by more filter axes, and summarized on a ranked-list dashboard — by extending three existing systems (`internal/threatgraph`, `internal/analytics`, `GET /api/iocs`), not building new ones.

**Architecture:** `ioc_sightings` gains `technique_id`/`detection_verdict` columns, populated from data `SubmitRunDetections` already computes. `internal/threatgraph` gains an `ioc` node type reusing its existing `Neighborhood`/`Lookup` machinery and existing route. `internal/analytics` gains an 8th category file (`ioc.go`) following the exact shape of the other 7. `GET /api/iocs` gains 5 more filters using its existing builder pattern.

**Tech Stack:** Go (`internal/iocregistry`, `internal/threatgraph`, `internal/analytics`, `internal/api`, `internal/db`), `*pgxpool.Pool`.

## Global Constraints

- No frontend — backend-only, matching every foundation phase this session.
- No `internal/search` integration for IOCs — explicitly rejected in the spec (IOC values aren't title-like free text; one IOC belongs to many scenarios via `ioc_sightings`, which doesn't fit `search_documents`' one-row-per-entity model).
- No IOC Timeline or IOC Variants/families — explicitly deferred in the spec (nothing transitions `iocs.status` today; domain/hash families need Phase C's generated data to be meaningful).
- New `GET /api/analytics/iocs` route registered `tierAny` (Viewer+), matching every other analytics endpoint.
- `threatgraph`'s new node types (`ioc`, `scenario`, `run`, `agent`) are wired only into `IOCNeighborhood` this phase — not retrofitted onto actor/campaign/malware/tool neighborhoods.
- Every task ends with a commit + `git push`.

---

### Task 1: `ioc_sightings` schema + extraction signature

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (2 `ALTER TABLE` + 1 index, in `EnsureSchema`)
- Modify: `orchestrator/internal/iocregistry/extract.go` (`ExtractFromDetectionAlert`, `recordSighting` signatures)
- Modify: `orchestrator/internal/iocregistry/extract_test.go` (existing 4 tests updated for the new params; 1 new test)

**Interfaces:**
- Produces: `func iocregistry.ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool, scenarioID, runID, agentID, techniqueID, detectionVerdict string, res models.SimulationResult) error`. Task 2 updates its one call site to this signature.

- [ ] **Step 1: Update the test file for the new signature, and add a new test**

Replace the full contents of `orchestrator/internal/iocregistry/extract_test.go`:

```go
package iocregistry

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
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
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

		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
			t.Fatalf("first extract: %v", err)
		}
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-2", "agent-2", "T1059", "undetected", res); err != nil {
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
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
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
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1059", "detected", res); err != nil {
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

func TestExtractFromDetectionAlert_RecordsTechniqueAndVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		res := detectionResult("net user /add evil", "net.exe", "")
		if err := ExtractFromDetectionAlert(context.Background(), pool, "sc-1", "run-1", "agent-1", "T1136", "prevented", res); err != nil {
			t.Fatalf("ExtractFromDetectionAlert: %v", err)
		}

		var techniqueID, verdict string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.technique_id, s.detection_verdict FROM ioc_sightings s
			JOIN iocs i ON i.id = s.ioc_id WHERE i.type = 'command_line' AND i.value = 'net user /add evil'`).
			Scan(&techniqueID, &verdict); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if techniqueID != "T1136" {
			t.Errorf("technique_id = %q, want T1136", techniqueID)
		}
		if verdict != "prevented" {
			t.Errorf("detection_verdict = %q, want prevented", verdict)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/iocregistry/... -v`
Expected: FAIL — build error, `ExtractFromDetectionAlert` called with 7 args, wants 5 (too many arguments in call).

- [ ] **Step 3: Add the schema columns**

In `orchestrator/internal/db/postgres.go`, find:

```go
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_agent ON ioc_sightings (agent_id)`,
```

Immediately after it, insert:

```go
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_agent ON ioc_sightings (agent_id)`,

		// Phase B: correlation/analytics need to know which technique produced
		// a sighting and what its detection verdict was -- both already
		// computed by SubmitRunDetections at extraction time, just not
		// captured until now. See
		// docs/superpowers/specs/2026-07-31-ioc-relationships-analytics-design.md.
		`ALTER TABLE ioc_sightings ADD COLUMN IF NOT EXISTS technique_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE ioc_sightings ADD COLUMN IF NOT EXISTS detection_verdict text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_technique ON ioc_sightings (technique_id)`,
```

- [ ] **Step 4: Update the extraction signature**

Replace the full contents of `orchestrator/internal/iocregistry/extract.go`:

```go
package iocregistry

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// ExtractFromDetectionAlert pulls IOC-shaped values out of res.DetectionAlert
// (if present) into the iocs/ioc_sightings tables. Best-effort by design of
// its caller (SubmitRunDetections) -- a nil DetectionAlert or empty fields
// are not errors, just nothing to extract. techniqueID/detectionVerdict come
// from the same SimulationResult the alert was matched against -- passed
// separately since they live on the result, not the alert.
func ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool, scenarioID, runID, agentID, techniqueID, detectionVerdict string, res models.SimulationResult) error {
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
		if err := recordSighting(ctx, pool, id, scenarioID, runID, agentID, techniqueID, detectionVerdict); err != nil {
			return err
		}
	}

	if alert.ProcessName != "" {
		id, err := upsertIOC(ctx, pool, TypeProcess, alert.ProcessName, SourceDetectionAlert, nil)
		if err != nil {
			return err
		}
		if err := recordSighting(ctx, pool, id, scenarioID, runID, agentID, techniqueID, detectionVerdict); err != nil {
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

func recordSighting(ctx context.Context, pool *pgxpool.Pool, iocID, scenarioID, runID, agentID, techniqueID, detectionVerdict string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id, detection_verdict)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		iocID, scenarioID, runID, agentID, techniqueID, detectionVerdict)
	return err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/iocregistry/... -v`
Expected: build succeeds; all 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/iocregistry/
git commit -m "feat(ioc): capture technique_id/detection_verdict on ioc_sightings

Both values are already computed by SubmitRunDetections at extraction
time (results[i].Technique.ID, results[i].DetectionVerdict) but were
dropped before this change. They're the join key Phase B's
correlation graph and analytics both need.

Phase B (Relationships & Analytics) of the IOC handling initiative,
piece 1/5."
git push
```

---

### Task 2: Wire technique/verdict into `SubmitRunDetections`

**Files:**
- Modify: `orchestrator/internal/api/detection_handlers.go`
- Modify: `orchestrator/internal/api/detection_handlers_test.go`

**Interfaces:**
- Consumes: `iocregistry.ExtractFromDetectionAlert(ctx, pool, scenarioID, runID, agentID, techniqueID, detectionVerdict, res)` (Task 1).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Update the test to assert technique/verdict are captured**

Replace the full contents of `orchestrator/internal/api/detection_handlers_test.go`:

```go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubmitRunDetections_ExtractsIOCs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('agent-1', 'HOST-1')`)
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

		var sightingScenario, techniqueID, verdict string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.scenario_id, s.technique_id, s.detection_verdict FROM ioc_sightings s
			JOIN iocs i ON i.id = s.ioc_id WHERE i.value = 'whoami /all'`).
			Scan(&sightingScenario, &techniqueID, &verdict); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if sightingScenario != "sc-1" {
			t.Errorf("sighting scenario_id = %q, want sc-1", sightingScenario)
		}
		if techniqueID != "T1059" {
			t.Errorf("sighting technique_id = %q, want T1059", techniqueID)
		}
		if verdict != "detected" {
			t.Errorf("sighting detection_verdict = %q, want detected", verdict)
		}
	})
}
```

(The seeded run's one result has technique `T1059` with no prior `DetectionVerdict`; `detect.Correlate`, called earlier in the handler, sets `results[i].DetectionVerdict = "detected"` once the posted alert matches it within the 5-minute correlation window — same mechanism `TestSubmitRunDetections_Success` in this file's neighbors already exercises, just asserted here for the IOC side too.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitRunDetections_ExtractsIOCs -v`
Expected: FAIL — build error (`ExtractFromDetectionAlert` call in `detection_handlers.go` now has too few arguments for `iocregistry`'s Task 1 signature).

- [ ] **Step 3: Update the call site**

In `orchestrator/internal/api/detection_handlers.go`, find:

```go
	// Best-effort IOC extraction -- never fails the request. See
	// docs/superpowers/specs/2026-07-31-ioc-registry-design.md.
	for i := range results {
		if err := iocregistry.ExtractFromDetectionAlert(r.Context(), h.db, scenarioID, runID, agentID, results[i]); err != nil {
			log.Printf("[ioc] extraction failed for run %s: %v", runID, err)
		}
	}
```

Replace with:

```go
	// Best-effort IOC extraction -- never fails the request. See
	// docs/superpowers/specs/2026-07-31-ioc-registry-design.md and
	// docs/superpowers/specs/2026-07-31-ioc-relationships-analytics-design.md.
	for i := range results {
		if err := iocregistry.ExtractFromDetectionAlert(r.Context(), h.db, scenarioID, runID, agentID,
			results[i].Technique.ID, results[i].DetectionVerdict, results[i]); err != nil {
			log.Printf("[ioc] extraction failed for run %s: %v", runID, err)
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run TestSubmitRunDetections -v`
Expected: build/vet clean; all `TestSubmitRunDetections*` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/detection_handlers.go orchestrator/internal/api/detection_handlers_test.go
git commit -m "feat(api): pass technique/verdict into IOC extraction

results[i].Technique.ID and results[i].DetectionVerdict were already
computed earlier in this same handler; now flow into
ExtractFromDetectionAlert instead of being dropped.

Phase B of the IOC handling initiative, piece 2/5."
git push
```

---

### Task 3: `GET /api/iocs` new filters

**Files:**
- Modify: `orchestrator/internal/api/ioc_handlers.go`
- Modify: `orchestrator/internal/api/ioc_handlers_test.go`

**Interfaces:**
- Consumes: `ioc_sightings.technique_id`/`detection_verdict` (Task 1).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Update `seedIOC` and add the new filter tests**

Replace the full contents of `orchestrator/internal/api/ioc_handlers_test.go`:

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
	seedIOCFull(t, pool, iocType, value, agentID, scenarioID, "", "")
}

func seedIOCFull(t *testing.T, pool *pgxpool.Pool, iocType, value, agentID, scenarioID, techniqueID, verdict string) {
	t.Helper()
	var id string
	mustExecAPIReturning(t, pool, &id, `
		INSERT INTO iocs (type, value, source) VALUES ($1, $2, 'detection_alert')
		ON CONFLICT (type, value) DO UPDATE SET last_seen = NOW() RETURNING id`,
		iocType, value)
	mustExecAPI(t, pool, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, agent_id, technique_id, detection_verdict) VALUES ($1, $2, $3, $4, $5)`,
		id, scenarioID, agentID, techniqueID, verdict)
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

func TestGetIOCs_FiltersByTechniqueId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCFull(t, pool, "command_line", "cmd-t1059", "agent-1", "sc-1", "T1059", "detected")
		seedIOCFull(t, pool, "command_line", "cmd-t1136", "agent-1", "sc-1", "T1136", "prevented")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?techniqueId=T1059", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 || got[0]["value"] != "cmd-t1059" {
			t.Errorf("got %+v, want exactly 1 IOC (cmd-t1059)", got)
		}
	})
}

func TestGetIOCs_FiltersBySourceOriginStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-src", "agent-1", "sc-1")
		mustExecAPI(t, pool, `UPDATE iocs SET origin = 'openaev', status = 'detected' WHERE value = 'cmd-src'`)

		h := &Handler{db: pool}

		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?source=detection_alert", nil))
		var bySource []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &bySource)
		if len(bySource) != 1 {
			t.Errorf("source filter: got %+v, want exactly 1", bySource)
		}

		rec = httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?origin=openaev", nil))
		var byOrigin []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &byOrigin)
		if len(byOrigin) != 1 {
			t.Errorf("origin filter: got %+v, want exactly 1", byOrigin)
		}

		rec = httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?status=detected", nil))
		var byStatus []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &byStatus)
		if len(byStatus) != 1 {
			t.Errorf("status filter: got %+v, want exactly 1", byStatus)
		}
	})
}

func TestGetIOCs_FiltersBySinceUntil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-old", "agent-1", "sc-1")
		mustExecAPI(t, pool, `UPDATE iocs SET last_seen = '2020-01-01T00:00:00Z' WHERE value = 'cmd-old'`)
		seedIOC(t, pool, "command_line", "cmd-new", "agent-1", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?since=2025-01-01T00:00:00Z", nil))
		var got []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &got)
		if len(got) != 1 || got[0]["value"] != "cmd-new" {
			t.Errorf("since filter: got %+v, want exactly 1 (cmd-new)", got)
		}

		rec = httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?until=2021-01-01T00:00:00Z", nil))
		var got2 []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &got2)
		if len(got2) != 1 || got2[0]["value"] != "cmd-old" {
			t.Errorf("until filter: got %+v, want exactly 1 (cmd-old)", got2)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetIOCs_FiltersByTechniqueId|TestGetIOCs_FiltersBySourceOriginStatus|TestGetIOCs_FiltersBySinceUntil" -v`
Expected: FAIL — `techniqueId`/`source`/`origin`/`status`/`since`/`until` are silently ignored by the current handler, so each test's result count comes back as 2 (both seeded rows), not the expected 1.

- [ ] **Step 3: Add the new filters**

In `orchestrator/internal/api/ioc_handlers.go`, find:

```go
	if value := q.Get("value"); value != "" {
		args = append(args, "%"+value+"%")
		where += " AND i.value ILIKE $" + strconv.Itoa(len(args))
	}

	query += joins + " WHERE true" + where + " ORDER BY i.last_seen DESC LIMIT " + strconv.Itoa(limit)
```

Replace with:

```go
	if value := q.Get("value"); value != "" {
		args = append(args, "%"+value+"%")
		where += " AND i.value ILIKE $" + strconv.Itoa(len(args))
	}
	if techniqueID := q.Get("techniqueId"); techniqueID != "" {
		if joins == "" {
			joins = " JOIN ioc_sightings s ON s.ioc_id = i.id"
		}
		args = append(args, techniqueID)
		where += " AND s.technique_id = $" + strconv.Itoa(len(args))
	}
	if source := q.Get("source"); source != "" {
		args = append(args, source)
		where += " AND i.source = $" + strconv.Itoa(len(args))
	}
	if origin := q.Get("origin"); origin != "" {
		args = append(args, origin)
		where += " AND i.origin = $" + strconv.Itoa(len(args))
	}
	if status := q.Get("status"); status != "" {
		args = append(args, status)
		where += " AND i.status = $" + strconv.Itoa(len(args))
	}
	if since := q.Get("since"); since != "" {
		args = append(args, since)
		where += " AND i.last_seen >= $" + strconv.Itoa(len(args))
	}
	if until := q.Get("until"); until != "" {
		args = append(args, until)
		where += " AND i.last_seen <= $" + strconv.Itoa(len(args))
	}

	query += joins + " WHERE true" + where + " ORDER BY i.last_seen DESC LIMIT " + strconv.Itoa(limit)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run TestGetIOCs -v`
Expected: build/vet clean; all `TestGetIOCs*` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/ioc_handlers.go orchestrator/internal/api/ioc_handlers_test.go
git commit -m "feat(api): add techniqueId/source/origin/status/since/until filters to GET /api/iocs

The §18 search axes Phase 0+A's data actually supports --
severity/confidence/creator stay unfiltered since nothing populates
them yet.

Phase B of the IOC handling initiative, piece 3/5."
git push
```

---

### Task 4: `threatgraph` IOC correlation

**Files:**
- Modify: `orchestrator/internal/threatgraph/types.go` (new node type constants)
- Modify: `orchestrator/internal/threatgraph/assemble.go` (`IOCNeighborhood`, `Lookup` dispatch)
- Modify: `orchestrator/internal/threatgraph/assemble_test.go`

**Interfaces:**
- Consumes: `iocs`/`ioc_sightings` (Task 1), including `technique_id`.
- Produces: `func threatgraph.IOCNeighborhood(ctx context.Context, pool *pgxpool.Pool, iocID string) (Neighborhood, error)`, reachable via `threatgraph.Lookup(ctx, pool, "ioc", iocID)`. Nothing later depends on this directly — it's exposed through the existing `GET /api/knowledge-graph/{type}/{id}` route, unchanged.

- [ ] **Step 1: Write the failing test**

Add to the end of `orchestrator/internal/threatgraph/assemble_test.go`:

```go
func TestIOCNeighborhood_ReturnsScenarioRunAgentTechniqueEdges(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var iocID string
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO iocs (type, value, source) VALUES ('command_line', 'whoami /all', 'detection_alert')
			RETURNING id`).Scan(&iocID); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id)
			VALUES ($1, 'sc-1', 'run-1', 'agent-1', 'T1059')`, iocID); err != nil {
			t.Fatalf("seed sighting: %v", err)
		}

		n, err := IOCNeighborhood(context.Background(), pool, iocID)
		if err != nil {
			t.Fatalf("IOCNeighborhood: %v", err)
		}
		if len(n.Nodes) != 5 { // ioc + scenario + run + agent + technique
			t.Fatalf("Nodes = %+v, want 5", n.Nodes)
		}
		if n.Nodes[0].Type != NodeTypeIOC || n.Nodes[0].ID != "ioc:"+iocID {
			t.Fatalf("Nodes[0] = %+v, want the IOC itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeScenario: false, NodeTypeRun: false, NodeTypeAgent: false, NodeTypeTechnique: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for typ, found := range wantTypes {
			if !found {
				t.Errorf("missing node type %q in %+v", typ, n.Nodes)
			}
		}
	})
}

func TestIOCNeighborhood_UnknownID_ReturnsEmptyNeighborhood(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := IOCNeighborhood(context.Background(), pool, "does-not-exist")
		if err != nil {
			t.Fatalf("IOCNeighborhood: %v", err)
		}
		if len(n.Nodes) != 0 || len(n.Edges) != 0 {
			t.Errorf("Nodes/Edges = %+v/%+v, want both empty for an unknown ID", n.Nodes, n.Edges)
		}
	})
}

func TestLookup_DispatchesIOCType(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var iocID string
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO iocs (type, value, source) VALUES ('process', 'powershell.exe', 'detection_alert')
			RETURNING id`).Scan(&iocID); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		n, err := Lookup(context.Background(), pool, NodeTypeIOC, iocID)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if len(n.Nodes) != 1 || n.Nodes[0].Type != NodeTypeIOC {
			t.Errorf("Lookup(ioc, ...) = %+v, want 1 IOC node", n.Nodes)
		}
	})
}
```

Add `"github.com/jackc/pgx/v5/pgxpool"` to this file's existing import block if not already present (check first — `TechniqueNeighborhood`'s existing tests already take a `pool *pgxpool.Pool` parameter via `sharedDB.RunWithPool`, so the import should already be there).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/threatgraph/... -run "TestIOCNeighborhood|TestLookup_DispatchesIOCType" -v`
Expected: FAIL — build errors (`IOCNeighborhood`, `NodeTypeIOC`, `NodeTypeScenario`, `NodeTypeRun`, `NodeTypeAgent` undefined).

- [ ] **Step 3: Add the new node type constants**

In `orchestrator/internal/threatgraph/types.go`, find:

```go
const (
	NodeTypeActor     = "actor"
	NodeTypeCampaign  = "campaign"
	NodeTypeMalware   = "malware"
	NodeTypeTool      = "tool"
	NodeTypeTechnique = "technique"
	NodeTypeSector    = "sector"
	NodeTypeRegion    = "region"
)
```

Replace with:

```go
const (
	NodeTypeActor     = "actor"
	NodeTypeCampaign  = "campaign"
	NodeTypeMalware   = "malware"
	NodeTypeTool      = "tool"
	NodeTypeTechnique = "technique"
	NodeTypeSector    = "sector"
	NodeTypeRegion    = "region"
	NodeTypeIOC       = "ioc"
	NodeTypeScenario  = "scenario"
	NodeTypeRun       = "run"
	NodeTypeAgent     = "agent"
)
```

- [ ] **Step 4: Implement `IOCNeighborhood` and wire it into `Lookup`**

In `orchestrator/internal/threatgraph/assemble.go`, add this function anywhere after `ToolNeighborhood` and before `Lookup`:

```go
// IOCNeighborhood assembles the 1-hop neighborhood around an IOC registry
// row: one edge per distinct scenario/run/agent/technique found across its
// ioc_sightings rows. Unlike actor/campaign/malware/tool neighborhoods,
// scenario/run/agent have no display-name lookup table -- their raw ID is
// used as both node key and label, same treatment ActorNeighborhood already
// gives sector/region.
func IOCNeighborhood(ctx context.Context, pool *pgxpool.Pool, iocID string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var iocType, value string
	err := pool.QueryRow(ctx, `SELECT type, value FROM iocs WHERE id = $1`, iocID).Scan(&iocType, &value)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	iocNodeID := "ioc:" + iocID
	n.Nodes = append(n.Nodes, Node{ID: iocNodeID, Type: NodeTypeIOC, Label: iocType + ": " + value})

	rows, err := pool.Query(ctx,
		`SELECT DISTINCT scenario_id, run_id, agent_id, technique_id FROM ioc_sightings WHERE ioc_id = $1`, iocID)
	if err != nil {
		return n, err
	}
	defer rows.Close()

	seen := map[string]bool{}
	add := func(nodeType, key, label string) {
		if key == "" || seen[nodeType+":"+key] {
			return
		}
		seen[nodeType+":"+key] = true
		nodeID := nodeType + ":" + key
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: nodeType, Label: label})
		n.Edges = append(n.Edges, Edge{From: iocNodeID, To: nodeID, Relationship: "observed_in"})
	}
	for rows.Next() {
		var scenarioID, runID, agentID, techniqueID string
		if err := rows.Scan(&scenarioID, &runID, &agentID, &techniqueID); err != nil {
			return n, err
		}
		add(NodeTypeScenario, scenarioID, scenarioID)
		add(NodeTypeRun, runID, runID)
		add(NodeTypeAgent, agentID, agentID)
		if techniqueID != "" {
			label, lerr := techniqueLabel(ctx, pool, techniqueID)
			if lerr != nil {
				return n, lerr
			}
			add(NodeTypeTechnique, techniqueID, label)
		}
	}
	return n, rows.Err()
}
```

Then find:

```go
func Lookup(ctx context.Context, pool *pgxpool.Pool, nodeType, id string) (Neighborhood, error) {
	switch nodeType {
	case NodeTypeActor:
		return ActorNeighborhood(ctx, pool, id)
	case NodeTypeCampaign:
		return CampaignNeighborhood(ctx, pool, id)
	case NodeTypeMalware:
		return MalwareNeighborhood(ctx, pool, id)
	case NodeTypeTool:
		return ToolNeighborhood(ctx, pool, id)
	case NodeTypeTechnique:
		return TechniqueNeighborhood(ctx, pool, id)
	default:
		return Neighborhood{}, fmt.Errorf("unknown node type %q", nodeType)
	}
}
```

Replace with:

```go
func Lookup(ctx context.Context, pool *pgxpool.Pool, nodeType, id string) (Neighborhood, error) {
	switch nodeType {
	case NodeTypeActor:
		return ActorNeighborhood(ctx, pool, id)
	case NodeTypeCampaign:
		return CampaignNeighborhood(ctx, pool, id)
	case NodeTypeMalware:
		return MalwareNeighborhood(ctx, pool, id)
	case NodeTypeTool:
		return ToolNeighborhood(ctx, pool, id)
	case NodeTypeTechnique:
		return TechniqueNeighborhood(ctx, pool, id)
	case NodeTypeIOC:
		return IOCNeighborhood(ctx, pool, id)
	default:
		return Neighborhood{}, fmt.Errorf("unknown node type %q", nodeType)
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/threatgraph/... -v`
Expected: build/vet clean; every test in the package PASSES, including the 3 new ones and every pre-existing `*Neighborhood` test.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/threatgraph/
git commit -m "feat(threatgraph): add ioc node type for IOC correlation

IOCNeighborhood reuses the existing Node/Edge/Neighborhood graph and
Lookup dispatch -- no new route, no new engine. Satisfies iochandling.txt
§12 (Correlation) and §20 (Relationships) for the 2 IOC types Phase
0+A currently populates.

Phase B of the IOC handling initiative, piece 4/5."
git push
```

---

### Task 5: IOC analytics dashboard

**Files:**
- Create: `orchestrator/internal/analytics/ioc.go`
- Test: `orchestrator/internal/analytics/ioc_test.go`
- Create: `orchestrator/internal/api/ioc_analytics_handler.go`
- Test: `orchestrator/internal/api/ioc_analytics_handler_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `iocs`/`ioc_sightings` (Task 1).
- Produces: `func analytics.IOCAnalytics(ctx context.Context, pool *pgxpool.Pool, limit int) (IOCAnalyticsResult, error)`; `func (h *Handler) GetIOCAnalytics(w http.ResponseWriter, r *http.Request)`. Terminal task of Phase B — nothing later depends on this.

- [ ] **Step 1: Write the failing analytics test**

Create `orchestrator/internal/analytics/ioc_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedIOCAnalytics(t *testing.T, pool *pgxpool.Pool, iocType, value string, sightingCount int, verdict, status string, firstSeenExpr string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO iocs (type, value, source, status, sighting_count, first_seen)
		VALUES ($1, $2, 'detection_alert', $3, $4, `+firstSeenExpr+`)
		RETURNING id`, iocType, value, status, sightingCount).Scan(&id); err != nil {
		t.Fatalf("seed ioc %s: %v", value, err)
	}
	if verdict != "" {
		mustExec(t, pool, `INSERT INTO ioc_sightings (ioc_id, detection_verdict) VALUES ($1, $2)`, id, verdict)
	}
	return id
}

func TestIOCAnalytics_MostDetected_OrdersBySightingCountAmongDetectedVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "command_line", "cmd-high-detected", 9, "detected", "detected", "NOW()")
		seedIOCAnalytics(t, pool, "command_line", "cmd-low-detected", 2, "detected", "detected", "NOW()")
		seedIOCAnalytics(t, pool, "command_line", "cmd-undetected", 20, "undetected", "missed", "NOW()")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.MostDetected) != 2 {
			t.Fatalf("MostDetected = %+v, want 2 entries (undetected excluded)", got.MostDetected)
		}
		if got.MostDetected[0].Value != "cmd-high-detected" {
			t.Errorf("MostDetected[0] = %+v, want cmd-high-detected first (highest sighting_count)", got.MostDetected[0])
		}
	})
}

func TestIOCAnalytics_HighestBypassRate_OnlyUndetectedVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "command_line", "cmd-bypass", 5, "undetected", "missed", "NOW()")
		seedIOCAnalytics(t, pool, "command_line", "cmd-detected", 5, "detected", "detected", "NOW()")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.HighestBypassRate) != 1 || got.HighestBypassRate[0].Value != "cmd-bypass" {
			t.Errorf("HighestBypassRate = %+v, want exactly [cmd-bypass]", got.HighestBypassRate)
		}
	})
}

func TestIOCAnalytics_FrequentlyReused_OrdersBySightingCountNoVerdictFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "process", "svchost.exe", 15, "", "observed", "NOW()")
		seedIOCAnalytics(t, pool, "process", "cmd.exe", 3, "", "observed", "NOW()")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.FrequentlyReused) != 2 || got.FrequentlyReused[0].Value != "svchost.exe" {
			t.Errorf("FrequentlyReused = %+v, want svchost.exe first", got.FrequentlyReused)
		}
	})
}

func TestIOCAnalytics_LongestSurviving_ExcludesArchivedAndExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "command_line", "cmd-oldest", 1, "", "observed", "'2020-01-01T00:00:00Z'")
		seedIOCAnalytics(t, pool, "command_line", "cmd-newer", 1, "", "observed", "'2025-01-01T00:00:00Z'")
		seedIOCAnalytics(t, pool, "command_line", "cmd-archived-but-oldest", 1, "", "archived", "'2010-01-01T00:00:00Z'")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.LongestSurviving) != 2 {
			t.Fatalf("LongestSurviving = %+v, want 2 entries (archived excluded)", got.LongestSurviving)
		}
		if got.LongestSurviving[0].Value != "cmd-oldest" {
			t.Errorf("LongestSurviving[0] = %+v, want cmd-oldest first (earliest first_seen)", got.LongestSurviving[0])
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/analytics/... -run TestIOCAnalytics -v`
Expected: FAIL — build error, `IOCAnalytics` undefined.

- [ ] **Step 3: Implement `IOCAnalytics`**

Create `orchestrator/internal/analytics/ioc.go`:

```go
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IOCAnalyticsEntry is one ranked row in any of IOCAnalyticsResult's lists.
type IOCAnalyticsEntry struct {
	IOCID         string `json:"iocId"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	SightingCount int    `json:"sightingCount"`
}

// IOCAnalyticsResult is the §24 dashboard summary -- the subset of
// iochandling.txt's requested metrics this registry's current data can
// honestly support. HighestBypassRate is a sighting-count proxy (no
// confidence score exists to compute a true rate from), stated as such in
// its own doc comment, not presented as a percentage.
type IOCAnalyticsResult struct {
	MostDetected      []IOCAnalyticsEntry `json:"mostDetected"`
	HighestBypassRate []IOCAnalyticsEntry `json:"highestBypassRate"`
	FrequentlyReused  []IOCAnalyticsEntry `json:"frequentlyReused"`
	LongestSurviving  []IOCAnalyticsEntry `json:"longestSurviving"`
}

// IOCAnalytics computes the 4 ranked lists behind the IOC dashboard.
func IOCAnalytics(ctx context.Context, pool *pgxpool.Pool, limit int) (IOCAnalyticsResult, error) {
	if limit <= 0 {
		limit = 10
	}
	var result IOCAnalyticsResult

	mostDetected, err := iocsByVerdict(ctx, pool, limit, "detected", "prevented")
	if err != nil {
		return result, err
	}
	result.MostDetected = mostDetected

	bypassed, err := iocsByVerdict(ctx, pool, limit, "undetected")
	if err != nil {
		return result, err
	}
	result.HighestBypassRate = bypassed

	reused, err := scanIOCEntries(ctx, pool, `
		SELECT id, type, value, sighting_count FROM iocs
		ORDER BY sighting_count DESC LIMIT $1`, limit)
	if err != nil {
		return result, err
	}
	result.FrequentlyReused = reused

	surviving, err := scanIOCEntries(ctx, pool, `
		SELECT id, type, value, sighting_count FROM iocs
		WHERE status NOT IN ('archived', 'expired')
		ORDER BY first_seen ASC LIMIT $1`, limit)
	if err != nil {
		return result, err
	}
	result.LongestSurviving = surviving

	return result, nil
}

func iocsByVerdict(ctx context.Context, pool *pgxpool.Pool, limit int, verdicts ...string) ([]IOCAnalyticsEntry, error) {
	return scanIOCEntries(ctx, pool, `
		SELECT DISTINCT i.id, i.type, i.value, i.sighting_count
		FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id
		WHERE s.detection_verdict = ANY($2)
		ORDER BY i.sighting_count DESC LIMIT $1`, limit, verdicts)
}

func scanIOCEntries(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) ([]IOCAnalyticsEntry, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []IOCAnalyticsEntry{}
	for rows.Next() {
		var e IOCAnalyticsEntry
		if err := rows.Scan(&e.IOCID, &e.Type, &e.Value, &e.SightingCount); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run analytics tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestIOCAnalytics -v`
Expected: build succeeds; all 4 tests PASS.

- [ ] **Step 5: Write the failing handler test**

Create `orchestrator/internal/api/ioc_analytics_handler_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGetIOCAnalytics_ReturnsAllFourLists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-analytics", "agent-1", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCAnalytics(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/iocs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"mostDetected", "highestBypassRate", "frequentlyReused", "longestSurviving"} {
			if _, ok := got[key]; !ok {
				t.Errorf("response missing key %q: %+v", key, got)
			}
		}
	})
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetIOCAnalytics -v`
Expected: FAIL — `h.GetIOCAnalytics` undefined (compile error).

- [ ] **Step 7: Implement the handler, route, and RBAC entry**

Create `orchestrator/internal/api/ioc_analytics_handler.go`:

```go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/analytics"
)

// GET /api/analytics/iocs — IOC registry dashboard: most-detected,
// highest-bypass-rate, frequently-reused, longest-surviving. Viewer+.
func (h *Handler) GetIOCAnalytics(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.IOCAnalytics(r.Context(), h.db, 10)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

In `orchestrator/internal/api/routes.go`, find:

```go
		// IOC Registry -- flat search over the canonical IOC model
		// (Phase 0+A of the IOC handling initiative).
		r.Get("/api/iocs", h.GetIOCs)
```

Replace with:

```go
		// IOC Registry -- flat search over the canonical IOC model
		// (Phase 0+A of the IOC handling initiative).
		r.Get("/api/iocs", h.GetIOCs)
		r.Get("/api/analytics/iocs", h.GetIOCAnalytics)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/iocs", tierAny, ""},
```

Replace with:

```go
	{http.MethodGet, "/api/iocs", tierAny, ""},
	{http.MethodGet, "/api/analytics/iocs", tierAny, ""},
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run "TestGetIOCAnalytics|TestRBACMatrix_NoDrift" -v`
Expected: build/vet clean; both tests PASS.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/analytics/ioc.go orchestrator/internal/analytics/ioc_test.go orchestrator/internal/api/ioc_analytics_handler.go orchestrator/internal/api/ioc_analytics_handler_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(analytics): add GET /api/analytics/iocs dashboard

MostDetected, HighestBypassRate (sighting-count proxy, not a computed
rate -- no confidence score exists yet), FrequentlyReused,
LongestSurviving. Follows the exact 7-file pattern internal/analytics
already uses for every other category.

Phase B of the IOC handling initiative, piece 5/5 -- Phase B complete
pending Task 6's full regression."
git push
```

---

### Task 6: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
If down, start Docker Desktop and poll: `timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"`

- [ ] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If any package fails only under full-suite load (Docker resource contention across ~40 concurrent testcontainers was seen repeatedly in Phase 0+A — `internal/api`, `internal/relationships`), re-run that package standalone: `go test ./internal/<pkg>/... -count=1 -timeout 20m`. A standalone pass confirms it was contention, not a regression from this phase's changes.

- [ ] **Step 3: Report completion**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that Phase B (IOC Relationships & Analytics) is complete, and that Phase C (Generation Engine) and Phase D (Intelligence Layer) remain as the next parts of the roadmap, in that order.
