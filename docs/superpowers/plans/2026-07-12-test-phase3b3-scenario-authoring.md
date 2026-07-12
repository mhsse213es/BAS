# Phase 3b.3 — Scenario Authoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add characterization tests locking down the 7 `internal/api` scenario-authoring handlers (List/Get/Create/Update/Clone/Upload/Delete) and 5 targeted `internal/scenario` engine gaps (ID validation, round-trip fidelity, source classification, unsigned-builtin refusal, intel delete-rescan), against a real file-backed `scenario.Engine` over a temp directory.

**Architecture:** Integration-style tests using `httptest` against a real `*api.Handler` wired to a real `scenario.Engine(t.TempDir())` and a real Postgres pool from the existing `sharedDB` test harness (the pool is required only because `auditLog` fires an async `INSERT` goroutine on `h.db` — a nil pool would panic that goroutine; per 3b.2 precedent, audit rows are never asserted on). These are characterization tests against already-correct production code: no new handler/engine code is written in this plan, so every test is expected to pass on first run. A failing test means the test is wrong, not the handler — fix the test.

**Tech Stack:** Go 1.x, `net/http/httptest`, `github.com/go-chi/chi/v5` (via the existing `withURLParam` helper), `gopkg.in/yaml.v3`, `github.com/jackc/pgx/v5/pgxpool`, testcontainers-backed Postgres via `internal/testutil`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-12-test-phase3b3-scenario-authoring-design.md` — read it if anything below is ambiguous.
- No genuinely-signed builtin fixtures anywhere in this plan: the real RSA private key that pairs with the compiled-in `integrity.ScenarioPublicKeyPEM` is not available to tests or CI. Every "non-custom source" test case uses `intel` (no signature required) as the vehicle; builtin is only exercised via its *unsigned-refusal* path (Task 7), never via a successfully-loaded builtin scenario.
- Never assert on the async `auditLog` goroutine (no polling, no sleeping, no DB row checks on `audit_logs`).
- Every test function starts with `if testing.Short() { t.Skip(...) }` and runs inside `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) { ... })` — this project's established container-backed-test pattern (see `internal/api/result_mac_test.go`).
- Reuse `withURLParam` from `internal/api/event_handlers_test.go` — do not redefine it.
- Commit after every task with trailer `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`, then `git push` immediately (per project convention — always push right after committing).
- Minimal changes only: this plan creates 3 new test files and appends 5 tests to one existing test file. It does not touch any non-test production code.

---

### Task 1: Shared helpers + ListScenarios + GetScenario

**Files:**
- Create: `orchestrator/internal/api/scenario_authoring_test.go`

**Interfaces:**
- Produces (consumed by Tasks 2–6): `newFileEngine(t *testing.T) (string, *scenario.Engine)`, `seedCustomScenario(t *testing.T, e *scenario.Engine, sc *scenario.Scenario)`, `seedIntelScenario(t *testing.T, dir string, e *scenario.Engine, sc *scenario.Scenario)`, `minimalScenario(id string) *scenario.Scenario`, `scenarioJSON(t *testing.T, sc *scenario.Scenario) *bytes.Reader`, `readScenarioFile(t *testing.T, path string) []byte`.
- Consumes: `withURLParam(r *http.Request, key, val string) *http.Request` (from `event_handlers_test.go`), `sharedDB.RunWithPool` (from `testmain_test.go`), `New(pool, hub, engine, secret string) *Handler` (`handlers.go:78`), `scenario.NewEngine(dir string) *Engine`, `engine.Load()`, `engine.Save(*Scenario)`, `engine.Get(id string) (*Scenario, bool)`.

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

// newFileEngine creates an Engine rooted at a fresh temp dir and loads it
// (starts empty — no scenarios on disk yet). Returns the dir so callers that
// need to inspect files directly (source-guard checks, round-trip checks)
// don't have to reach into the Engine's private fields.
func newFileEngine(t *testing.T) (string, *scenario.Engine) {
	t.Helper()
	dir := t.TempDir()
	e := scenario.NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty engine: %v", err)
	}
	return dir, e
}

// seedCustomScenario saves sc directly through the engine (bypassing HTTP) so
// tests that aren't about the Create/Upload path itself can set up fixtures.
func seedCustomScenario(t *testing.T, e *scenario.Engine, sc *scenario.Scenario) {
	t.Helper()
	if err := e.Save(sc); err != nil {
		t.Fatalf("seed scenario %q: %v", sc.ID, err)
	}
}

// seedIntelScenario writes sc as YAML directly under <dir>/intel/ (only
// connectors populate this folder in production — there is no Engine method
// for it) and reloads the engine so it's classified source="intel".
func seedIntelScenario(t *testing.T, dir string, e *scenario.Engine, sc *scenario.Scenario) {
	t.Helper()
	intelDir := filepath.Join(dir, "intel")
	if err := os.MkdirAll(intelDir, 0o755); err != nil {
		t.Fatalf("mkdir intel dir: %v", err)
	}
	b, err := yaml.Marshal(sc)
	if err != nil {
		t.Fatalf("marshal intel scenario %q: %v", sc.ID, err)
	}
	dest := filepath.Join(intelDir, sc.ID+".yaml")
	if err := os.WriteFile(dest, b, 0o644); err != nil {
		t.Fatalf("write intel scenario %q: %v", sc.ID, err)
	}
	if err := e.Load(); err != nil {
		t.Fatalf("reload after seeding intel scenario %q: %v", sc.ID, err)
	}
}

// minimalScenario returns a Scenario that passes Validate(): a valid slug id,
// a name, and one step naming a technique (the "steps" execution mode).
func minimalScenario(id string) *scenario.Scenario {
	return &scenario.Scenario{
		ID:   id,
		Name: "Test Scenario " + id,
		Steps: []scenario.Step{
			{Name: "step one", TechniqueID: "T1059.001"},
		},
	}
}

// scenarioJSON marshals sc to a JSON request body reader.
func scenarioJSON(t *testing.T, sc *scenario.Scenario) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("marshal scenario: %v", err)
	}
	return bytes.NewReader(b)
}

// readScenarioFile reads a fixture/output file, failing the test if it's missing.
func readScenarioFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestListScenarios_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios", nil)
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []*scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty list, got %d entries", len(out))
		}
	})
}

func TestListScenarios_OrderedByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("zzz-scenario"))
		seedCustomScenario(t, e, minimalScenario("aaa-scenario"))
		seedCustomScenario(t, e, minimalScenario("mmm-scenario"))
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios", nil)
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, req)
		var out []*scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) != 3 {
			t.Fatalf("expected 3 scenarios, got %d", len(out))
		}
		got := []string{out[0].ID, out[1].ID, out[2].ID}
		want := []string{"aaa-scenario", "mmm-scenario", "zzz-scenario"}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("order mismatch: got %v, want %v", got, want)
			}
		}
	})
}

// TestListScenarios_SourceClassification covers custom and intel only, not
// builtin: a loadable builtin fixture requires a valid signature, and the
// matching private key for the compiled-in integrity.ScenarioPublicKeyPEM is
// not available to tests or CI (see Task 6's file-level comment). The
// unsigned-builtin-refusal path is covered separately in Task 7's
// TestLoad_UnsignedBuiltinRefused.
func TestListScenarios_SourceClassification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("list-custom-sc"))
		seedIntelScenario(t, dir, e, minimalScenario("list-intel-sc"))
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios", nil)
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, req)
		var out []*scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		bySource := map[string]string{}
		for _, sc := range out {
			bySource[sc.ID] = sc.Source
		}
		if bySource["list-custom-sc"] != "custom" {
			t.Fatalf("list-custom-sc source = %q, want custom", bySource["list-custom-sc"])
		}
		if bySource["list-intel-sc"] != "intel" {
			t.Fatalf("list-intel-sc source = %q, want intel", bySource["list-intel-sc"])
		}
	})
}

func TestListScenarios_KeyMetadataPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		sc := minimalScenario("metadata-sc")
		sc.Description = "a scenario used to check metadata passthrough"
		sc.Tags = []string{"tag-x", "tag-y"}
		sc.MITREPhases = []string{"execution"}
		seedCustomScenario(t, e, sc)
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios", nil)
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, req)
		var out []*scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found *scenario.Scenario
		for _, s := range out {
			if s.ID == "metadata-sc" {
				found = s
			}
		}
		if found == nil {
			t.Fatalf("metadata-sc not present in list")
		}
		if found.Description != sc.Description {
			t.Fatalf("description = %q, want %q", found.Description, sc.Description)
		}
		if len(found.Tags) != 2 || found.Tags[0] != "tag-x" || found.Tags[1] != "tag-y" {
			t.Fatalf("tags mismatch: %+v", found.Tags)
		}
		if len(found.MITREPhases) != 1 || found.MITREPhases[0] != "execution" {
			t.Fatalf("mitre phases mismatch: %+v", found.MITREPhases)
		}
	})
}

func TestGetScenario_Found(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("get-found-sc"))
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/get-found-sc", nil), "id", "get-found-sc")
		rec := httptest.NewRecorder()
		h.GetScenario(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "get-found-sc" {
			t.Fatalf("id = %q, want get-found-sc", out.ID)
		}
	})
}

func TestGetScenario_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/missing-sc", nil), "id", "missing-sc")
		rec := httptest.NewRecorder()
		h.GetScenario(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
```

Note: `strings` is imported here for use starting Task 4 (Upload tests appended to
this same file) — Go will flag it unused until then, so run `go vet` only after
Task 4, or ignore the unused-import build failure between Task 1 and Task 4 if
running this file in isolation. In practice you'll do Steps 2–4 of every task in
this file back-to-back, so this never surfaces.

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/api/... -run 'TestListScenarios|TestGetScenario' -v -count=1`

Expected: all 6 tests PASS. This is a characterization test suite against
already-correct handlers — if anything fails, the bug is almost certainly in
the test (wrong assumption about ordering, JSON tag name, etc.), not in
`ListScenarios`/`GetScenario`. Re-read `handlers.go:794-806` and
`engine.go:115-128` before changing test expectations.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/scenario_authoring_test.go
git commit -m "$(cat <<'EOF'
test(api): add ListScenarios/GetScenario tests + scenario-authoring helpers

Phase 3b.3 (Scenario Authoring). Introduces the shared file-backed-engine
fixtures reused by the rest of the phase's test files.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 2: CreateScenario

**Files:**
- Modify: `orchestrator/internal/api/scenario_authoring_test.go` (append)

**Interfaces:**
- Consumes: `newFileEngine`, `seedCustomScenario`, `minimalScenario`, `scenarioJSON` (Task 1).

- [ ] **Step 1: Append the tests**

```go
func TestCreateScenario_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		sc := minimalScenario("create-valid-sc")
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios", scenarioJSON(t, sc))
		rec := httptest.NewRecorder()
		h.CreateScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Source != "custom" {
			t.Fatalf("source = %q, want custom", out.Source)
		}
		want := filepath.Join(dir, "custom", "create-valid-sc.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected file at %s: %v", want, err)
		}
	})
}

func TestCreateScenario_DuplicateID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("dup-sc"))
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios", scenarioJSON(t, minimalScenario("dup-sc")))
		rec := httptest.NewRecorder()
		h.CreateScenario(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})
}

func TestCreateScenario_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios", strings.NewReader(`{"id": "bad", `))
		rec := httptest.NewRecorder()
		h.CreateScenario(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateScenario_FailsValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		sc := &scenario.Scenario{ID: "no-mode-sc", Name: "No Mode"} // no steps/local_check/etc → no execution mode
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios", scenarioJSON(t, sc))
		rec := httptest.NewRecorder()
		h.CreateScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
		if _, ok := e.Get("no-mode-sc"); ok {
			t.Fatalf("scenario should not have been saved")
		}
	})
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/api/... -run TestCreateScenario -v -count=1`

Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/scenario_authoring_test.go
git commit -m "$(cat <<'EOF'
test(api): add CreateScenario tests

Phase 3b.3. Covers valid create, duplicate-id conflict, malformed JSON,
and Validate() failure (no file written on 422).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 3: UpdateScenario (non-guard cases)

**Files:**
- Modify: `orchestrator/internal/api/scenario_authoring_test.go` (append)

**Interfaces:**
- Consumes: `newFileEngine`, `seedCustomScenario`, `minimalScenario`, `scenarioJSON`, `readScenarioFile` (Task 1).

The source-guard rejection case for `UpdateScenario` is intentionally NOT here —
it lives in Task 6 (`scenario_source_guard_test.go`) alongside the equivalent
`DeleteScenario` case, since both exercise the same `source != "custom"` branch
against the same intel fixture pattern.

- [ ] **Step 1: Append the tests**

```go
func TestUpdateScenario_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/missing-sc", nil), "id", "missing-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestUpdateScenario_URLIDAuthoritative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("url-id-sc"))
		h := New(pool, ws.NewHub(), e, "")
		body := minimalScenario("wrong-body-id")
		body.Name = "Renamed"
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/url-id-sc", scenarioJSON(t, body)), "id", "url-id-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "url-id-sc" {
			t.Fatalf("id = %q, want url-id-sc (URL should win over body id)", out.ID)
		}
		if _, ok := e.Get("wrong-body-id"); ok {
			t.Fatalf("body id should never have been saved")
		}
	})
}

func TestUpdateScenario_ValidUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("update-me-sc"))
		h := New(pool, ws.NewHub(), e, "")
		updated := minimalScenario("update-me-sc")
		updated.Name = "Updated Name"
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/update-me-sc", scenarioJSON(t, updated)), "id", "update-me-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		got, ok := e.Get("update-me-sc")
		if !ok || got.Name != "Updated Name" {
			t.Fatalf("in-memory scenario not updated: %+v", got)
		}
		fileBytes := readScenarioFile(t, filepath.Join(dir, "custom", "update-me-sc.yaml"))
		if !strings.Contains(string(fileBytes), "Updated Name") {
			t.Fatalf("file on disk not updated:\n%s", fileBytes)
		}
	})
}

func TestUpdateScenario_FailsValidateLeavesOriginalUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("keep-me-sc"))
		before := readScenarioFile(t, filepath.Join(dir, "custom", "keep-me-sc.yaml"))
		h := New(pool, ws.NewHub(), e, "")
		bad := &scenario.Scenario{} // no name, no execution mode — URL id overrides the empty body id
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/keep-me-sc", scenarioJSON(t, bad)), "id", "keep-me-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
		after := readScenarioFile(t, filepath.Join(dir, "custom", "keep-me-sc.yaml"))
		if string(before) != string(after) {
			t.Fatalf("file mutated despite validation failure:\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/api/... -run TestUpdateScenario -v -count=1`

Expected: all 4 tests PASS. (`TestUpdateScenario_SourceGuardRejectsIntel` doesn't
exist yet — that's Task 6 — so this run only picks up the 4 tests above.)

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/scenario_authoring_test.go
git commit -m "$(cat <<'EOF'
test(api): add UpdateScenario tests

Phase 3b.3. Covers not-found, URL-id-authoritative-over-body-id, a valid
update (memory + disk both reflect the change), and Validate() failure
leaving the original file byte-unchanged.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 4: UploadScenario

**Files:**
- Modify: `orchestrator/internal/api/scenario_authoring_test.go` (append)

**Interfaces:**
- Consumes: `newFileEngine`, `seedCustomScenario` (Task 1).

- [ ] **Step 1: Append the tests**

```go
func TestUploadScenario_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		body := "id: upload-valid-sc\nname: Upload Valid\nsteps:\n  - name: step one\n    technique_id: T1059.001\n"
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Source != "custom" {
			t.Fatalf("source = %q, want custom", out.Source)
		}
		want := filepath.Join(dir, "custom", "upload-valid-sc.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected file at %s: %v", want, err)
		}
	})
}

func TestUploadScenario_SyntacticallyInvalidYAML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		// A tab character in indentation is invalid YAML.
		body := "id: bad-indent-sc\n\tname: bad\n"
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid YAML") {
			t.Fatalf("body = %q, want it to mention invalid YAML", rec.Body.String())
		}
	})
}

func TestUploadScenario_FailsSchemaValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		// Parses fine, but the id fails idPattern (uppercase letters).
		body := "id: Bad-ID\nname: Something\nsteps:\n  - name: step one\n    technique_id: T1059.001\n"
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
		// Same status/message-prefix shape as the syntax-error case above —
		// ParseYAML folds parse and validation errors together (handlers.go:1371-1374).
		if !strings.Contains(rec.Body.String(), "invalid YAML") {
			t.Fatalf("body = %q, want it to mention invalid YAML", rec.Body.String())
		}
	})
}

func TestUploadScenario_EmptyBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(""))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUploadScenario_MissingRequiredFieldsOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		// id and name are present, but no steps/local_check/ART/Caldera mode.
		body := "id: no-mode-upload-sc\nname: No Mode\n"
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "no execution mode") {
			t.Fatalf("body = %q, want it to mention the missing execution mode", rec.Body.String())
		}
	})
}

func TestUploadScenario_DuplicateID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("upload-dup-sc"))
		h := New(pool, ws.NewHub(), e, "")
		body := "id: upload-dup-sc\nname: Duplicate\nsteps:\n  - name: step one\n    technique_id: T1059.001\n"
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUploadScenario_OversizedBodyTruncatedThenRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		// An unterminated quoted scalar padded past the 1 MiB cap: wherever the
		// io.LimitReader cuts it, the quote never closes, so the truncated bytes
		// are guaranteed to fail YAML parsing rather than accidentally parsing
		// as valid (e.g. landing inside a comment would not error).
		body := "id: big-sc\nname: '" + strings.Repeat("x", 2<<20)
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.UploadScenario(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/api/... -run TestUploadScenario -v -count=1`

Expected: all 7 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/scenario_authoring_test.go
git commit -m "$(cat <<'EOF'
test(api): add UploadScenario tests

Phase 3b.3. Covers valid upload, syntactically invalid YAML, YAML that
parses but fails schema validation (same 422/message-shape as the syntax
case — ParseYAML doesn't distinguish them), empty body, missing execution
mode, duplicate id, and an oversized body truncated by the 1 MiB cap.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 5: CloneScenario

**Files:**
- Create: `orchestrator/internal/api/scenario_clone_test.go`

**Interfaces:**
- Consumes: `newFileEngine`, `seedCustomScenario`, `seedIntelScenario`, `minimalScenario`, `scenarioJSON` (Task 1).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloneScenario_IntelSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		src := minimalScenario("intel-clone-src")
		src.IntelSource = "connector-x"
		src.IntelSourceID = "abc123"
		src.IntelActor = "APT99"
		src.IntelConfidence = "high"
		src.IntelGeneratedAt = time.Now().UTC()
		seedIntelScenario(t, dir, e, src)

		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/intel-clone-src/clone", nil), "id", "intel-clone-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}

		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "intel-clone-src-copy" {
			t.Fatalf("id = %q, want intel-clone-src-copy", out.ID)
		}
		if out.Name != "Test Scenario intel-clone-src (copy)" {
			t.Fatalf("name = %q", out.Name)
		}
		if out.Source != "custom" {
			t.Fatalf("source = %q, want custom", out.Source)
		}
		if out.IntelSource != "" || out.IntelSourceID != "" || out.IntelActor != "" || out.IntelConfidence != "" || !out.IntelGeneratedAt.IsZero() {
			t.Fatalf("intel provenance not stripped: %+v", out)
		}

		orig, ok := e.Get("intel-clone-src")
		if !ok || orig.IntelSource != "connector-x" {
			t.Fatalf("original scenario mutated or missing: %+v", orig)
		}
		if _, ok := e.Get("intel-clone-src-copy"); !ok {
			t.Fatalf("clone not present in memory")
		}
		want := filepath.Join(dir, "custom", "intel-clone-src-copy.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected clone file at %s: %v", want, err)
		}
	})
}

func TestCloneScenario_CustomSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("custom-clone-src"))
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/custom-clone-src/clone", nil), "id", "custom-clone-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "custom-clone-src-copy" || out.Source != "custom" {
			t.Fatalf("unexpected clone: %+v", out)
		}
		want := filepath.Join(dir, "custom", "custom-clone-src-copy.yaml")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected clone file at %s: %v", want, err)
		}
	})
}

func TestCloneScenario_ExplicitNewIDAndName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("explicit-src"))
		h := New(pool, ws.NewHub(), e, "")
		body := strings.NewReader(`{"newId":"explicit-target","name":"Custom Clone Name"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/explicit-src/clone", body), "id", "explicit-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out scenario.Scenario
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.ID != "explicit-target" {
			t.Fatalf("id = %q, want explicit-target", out.ID)
		}
		if out.Name != "Custom Clone Name" {
			t.Fatalf("name = %q, want Custom Clone Name", out.Name)
		}
	})
}

func TestCloneScenario_IDCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("collide-src"))
		seedCustomScenario(t, e, minimalScenario("collide-src-copy")) // pre-occupies the default clone id
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/collide-src/clone", nil), "id", "collide-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})
}

func TestCloneScenario_SourceNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/missing-src/clone", nil), "id", "missing-src")
		rec := httptest.NewRecorder()
		h.CloneScenario(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestCloneScenario_IndependentFromOriginal exercises the documented public
// contract only: after cloning, editing the clone through the real API
// (UpdateScenario) must never affect the original. It does NOT assert
// independence of the underlying slice-typed fields (Steps/Tags/MITREPhases/
// SupportedOS/CalderaAbilities/ARTTechniques) — CloneScenario does a shallow
// `clone := *src` (handlers.go:1333) that shares those slices' backing arrays
// with the source until the clone is independently re-saved. That is a
// latent aliasing hazard, recorded as a finding in the phase summary, not a
// contractual guarantee: a future in-place slice mutation on either side
// (e.g. an append within capacity, or `clone.Tags[0] = ...`) could corrupt
// the other. See
// docs/superpowers/specs/2026-07-12-test-phase3b3-scenario-authoring-design.md.
func TestCloneScenario_IndependentFromOriginal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("indep-src"))
		h := New(pool, ws.NewHub(), e, "")

		cloneReq := withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/indep-src/clone", nil), "id", "indep-src")
		cloneRec := httptest.NewRecorder()
		h.CloneScenario(cloneRec, cloneReq)
		if cloneRec.Code != http.StatusCreated {
			t.Fatalf("clone status = %d, want 201", cloneRec.Code)
		}

		updated := minimalScenario("indep-src-copy")
		updated.Name = "Mutated Clone Name"
		updateReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/indep-src-copy", scenarioJSON(t, updated)), "id", "indep-src-copy")
		updateRec := httptest.NewRecorder()
		h.UpdateScenario(updateRec, updateReq)
		if updateRec.Code != http.StatusOK {
			t.Fatalf("update status = %d, want 200", updateRec.Code)
		}

		orig, ok := e.Get("indep-src")
		if !ok {
			t.Fatalf("original scenario missing")
		}
		if orig.Name != "Test Scenario indep-src" {
			t.Fatalf("original mutated by editing its clone: name = %q", orig.Name)
		}
	})
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/api/... -run TestCloneScenario -v -count=1`

Expected: all 6 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/scenario_clone_test.go
git commit -m "$(cat <<'EOF'
test(api): add CloneScenario tests

Phase 3b.3. Covers cloning intel- and custom-sourced scenarios, explicit
newId/name, id collision, source-not-found, and independence of the clone
from the original through the real API. Documents the CloneScenario
shallow-copy (handlers.go:1333) as a finding, not a codified assertion.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 6: Source-guard matrix (UpdateScenario guard + full DeleteScenario)

**Files:**
- Create: `orchestrator/internal/api/scenario_source_guard_test.go`

**Interfaces:**
- Consumes: `newFileEngine`, `seedCustomScenario`, `seedIntelScenario`, `minimalScenario`, `scenarioJSON`, `readScenarioFile` (Task 1).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The source guard on both UpdateScenario and DeleteScenario is a single
// `if source != "custom"` branch. intel is the sole non-custom vehicle used
// here — constructing a genuinely-signed builtin fixture would require the
// offline release-signing private key, which is not available to tests or
// CI (see the spec's "Note" under the DeleteScenario matrix).

func TestUpdateScenario_SourceGuardRejectsIntel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedIntelScenario(t, dir, e, minimalScenario("intel-guard-sc"))
		filePath := filepath.Join(dir, "intel", "intel-guard-sc.yaml")
		before := readScenarioFile(t, filePath)

		h := New(pool, ws.NewHub(), e, "")
		updated := minimalScenario("intel-guard-sc")
		updated.Name = "Should Never Persist"
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/intel-guard-sc", scenarioJSON(t, updated)), "id", "intel-guard-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		after := readScenarioFile(t, filePath)
		if string(before) != string(after) {
			t.Fatalf("intel file mutated despite source guard:\nbefore:\n%s\nafter:\n%s", before, after)
		}
		got, ok := e.Get("intel-guard-sc")
		if !ok || got.Name == "Should Never Persist" {
			t.Fatalf("in-memory scenario mutated despite source guard: %+v", got)
		}
	})
}

func TestDeleteScenario_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/scenarios/missing-sc", nil), "id", "missing-sc")
		rec := httptest.NewRecorder()
		h.DeleteScenario(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestDeleteScenario_SourceGuardRejectsIntel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedIntelScenario(t, dir, e, minimalScenario("intel-delete-guard-sc"))
		filePath := filepath.Join(dir, "intel", "intel-delete-guard-sc.yaml")
		before := readScenarioFile(t, filePath)

		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/scenarios/intel-delete-guard-sc", nil), "id", "intel-delete-guard-sc")
		rec := httptest.NewRecorder()
		h.DeleteScenario(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		after := readScenarioFile(t, filePath)
		if string(before) != string(after) {
			t.Fatalf("intel file removed/mutated despite source guard")
		}
		if _, ok := e.Get("intel-delete-guard-sc"); !ok {
			t.Fatalf("scenario removed from memory despite source guard")
		}
	})
}

func TestDeleteScenario_ValidDeleteOfCustom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("delete-me-sc"))
		filePath := filepath.Join(dir, "custom", "delete-me-sc.yaml")
		if _, err := os.Stat(filePath); err != nil {
			t.Fatalf("fixture file missing before delete: %v", err)
		}

		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/scenarios/delete-me-sc", nil), "id", "delete-me-sc")
		rec := httptest.NewRecorder()
		h.DeleteScenario(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
		}

		if _, ok := e.Get("delete-me-sc"); ok {
			t.Fatalf("scenario still present in memory after delete")
		}
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("file still present on disk after delete: err = %v", err)
		}

		listReq := httptest.NewRequest(http.MethodGet, "/api/scenarios", nil)
		listRec := httptest.NewRecorder()
		h.ListScenarios(listRec, listReq)
		var out []*scenario.Scenario
		if err := json.Unmarshal(listRec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		for _, sc := range out {
			if sc.ID == "delete-me-sc" {
				t.Fatalf("deleted scenario still present in list")
			}
		}
	})
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/api/... -run 'TestUpdateScenario_SourceGuardRejectsIntel|TestDeleteScenario' -v -count=1`

Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/scenario_source_guard_test.go
git commit -m "$(cat <<'EOF'
test(api): add source-guard matrix + DeleteScenario tests

Phase 3b.3. UpdateScenario/DeleteScenario share one `source != "custom"`
branch; intel is the sole test vehicle (no signing key available for a
builtin fixture). Every rejection asserts no mutation in memory or on
disk. Also covers not-found and a valid delete (memory, disk, and a
subsequent list all reflect removal).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 7: Engine-level gaps

**Files:**
- Modify: `orchestrator/internal/scenario/engine_test.go`

**Interfaces:**
- None external — this task is self-contained within package `scenario`, using only exported `Scenario`/`Step`/`PrivSpec`/`LivePolicy`/`Engine` types already defined in `types.go`/`engine.go`.

- [ ] **Step 1: Update the import block**

Change the top of `orchestrator/internal/scenario/engine_test.go` from:

```go
package scenario

import (
	"path/filepath"
	"testing"
)
```

to:

```go
package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Append the tests**

```go
func TestValidate_IDPathTraversal(t *testing.T) {
	cases := []struct {
		name string
		id   string
		ok   bool
	}{
		{"path traversal", "../evil", false},
		{"embedded slash", "a/b", false},
		{"uppercase", "Bad-ID", false},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 65), false},
		{"valid slug", "ok-id-2", true},
	}
	for _, c := range cases {
		sc := Scenario{ID: c.id, Name: "x", LocalCheck: true}
		err := sc.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: expected valid, got %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestSave_RoundTripFidelity(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	sc := &Scenario{
		ID:          "roundtrip-sc",
		Name:        "Round Trip",
		Description: "fidelity check",
		Tags:        []string{"tag-a", "tag-b"},
		MITREPhases: []string{"execution", "persistence"},
		Steps: []Step{
			{Name: "scalar priv", TechniqueID: "T1059.001", RequiresPriv: PrivSpec{Minimum: "admin"}},
			{Name: "minimum only", TechniqueID: "T1059.002", RequiresPriv: PrivSpec{Minimum: "user"}},
			{Name: "minimum and preferred", TechniqueID: "T1059.003", RequiresPriv: PrivSpec{Minimum: "user", Preferred: "admin"}},
		},
		LivePolicy: &LivePolicy{
			BlockOnDomainController: true,
			RequireDCReachable:      true,
			MaxSprayAttempts:        3,
			SprayAccountAllowlist:   []string{"svc-test"},
			ExecutionWindow:         "22:00-06:00",
		},
		Executable:  true,
		SupportedOS: []string{"windows", "linux"},
	}

	if err := e.Save(sc); err != nil {
		t.Fatalf("save: %v", err)
	}

	e2 := NewEngine(dir)
	if err := e2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := e2.Get("roundtrip-sc")
	if !ok {
		t.Fatalf("scenario not found after reload")
	}

	if len(got.Tags) != 2 || got.Tags[0] != "tag-a" || got.Tags[1] != "tag-b" {
		t.Fatalf("tags mismatch: %+v", got.Tags)
	}
	if len(got.MITREPhases) != 2 || got.MITREPhases[0] != "execution" || got.MITREPhases[1] != "persistence" {
		t.Fatalf("mitre phases mismatch: %+v", got.MITREPhases)
	}
	if !got.Executable {
		t.Fatalf("executable not preserved")
	}
	if len(got.SupportedOS) != 2 || got.SupportedOS[0] != "windows" || got.SupportedOS[1] != "linux" {
		t.Fatalf("supported_os mismatch: %+v", got.SupportedOS)
	}
	if got.LivePolicy == nil {
		t.Fatalf("live_policy not preserved (nil)")
	}
	if !got.LivePolicy.BlockOnDomainController || !got.LivePolicy.RequireDCReachable ||
		got.LivePolicy.MaxSprayAttempts != 3 || got.LivePolicy.ExecutionWindow != "22:00-06:00" ||
		len(got.LivePolicy.SprayAccountAllowlist) != 1 || got.LivePolicy.SprayAccountAllowlist[0] != "svc-test" {
		t.Fatalf("live_policy fields mismatch: %+v", got.LivePolicy)
	}
	if len(got.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(got.Steps))
	}
	// PrivSpec has no custom YAML marshaler, so a scalar "admin" on the way in
	// comes back out as the equivalent {minimum: admin} mapping on disk — the
	// parsed VALUE is what must round-trip, not the on-disk byte format.
	if got.Steps[0].RequiresPriv.Effective() != "admin" {
		t.Fatalf("step 0 requires_priv.Effective() = %q, want admin", got.Steps[0].RequiresPriv.Effective())
	}
	if got.Steps[1].RequiresPriv.Effective() != "user" {
		t.Fatalf("step 1 requires_priv.Effective() = %q, want user", got.Steps[1].RequiresPriv.Effective())
	}
	if got.Steps[2].RequiresPriv.Minimum != "user" || got.Steps[2].RequiresPriv.Preferred != "admin" {
		t.Fatalf("step 2 requires_priv = %+v, want {user admin}", got.Steps[2].RequiresPriv)
	}
}

func TestLoad_SourceClassification(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	// custom/ — via the normal Save path.
	if err := e.Save(&Scenario{ID: "custom-src-sc", Name: "Custom", LocalCheck: true}); err != nil {
		t.Fatalf("save custom: %v", err)
	}

	// intel/ — written directly, since only connectors populate this folder.
	intelDir := filepath.Join(dir, "intel")
	if err := os.MkdirAll(intelDir, 0o755); err != nil {
		t.Fatalf("mkdir intel: %v", err)
	}
	intelYAML := []byte("id: intel-src-sc\nname: Intel\nlocal_check: true\n")
	if err := os.WriteFile(filepath.Join(intelDir, "intel-src-sc.yaml"), intelYAML, 0o644); err != nil {
		t.Fatalf("write intel file: %v", err)
	}

	if err := e.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	custom, ok := e.Get("custom-src-sc")
	if !ok || custom.Source != "custom" {
		t.Fatalf("custom scenario source = %+v, want custom", custom)
	}
	intel, ok := e.Get("intel-src-sc")
	if !ok || intel.Source != "intel" {
		t.Fatalf("intel scenario source = %+v, want intel", intel)
	}
}

func TestLoad_UnsignedBuiltinRefused(t *testing.T) {
	dir := t.TempDir()
	// A file placed directly under the engine root (not custom/ or intel/) is
	// classified "builtin" by sourceForPath and therefore requires a valid
	// .sig file. This one has none, so Load must skip it rather than trust it.
	unsigned := []byte("id: unsigned-builtin-sc\nname: Unsigned\nlocal_check: true\n")
	if err := os.WriteFile(filepath.Join(dir, "unsigned-builtin-sc.yaml"), unsigned, 0o644); err != nil {
		t.Fatalf("write unsigned builtin file: %v", err)
	}

	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, ok := e.Get("unsigned-builtin-sc"); ok {
		t.Fatalf("unsigned builtin scenario should have been refused, but was loaded")
	}
	if e.Count() != 0 {
		t.Fatalf("expected 0 loaded scenarios, got %d", e.Count())
	}
}

func TestDelete_IntelRescan(t *testing.T) {
	dir := t.TempDir()
	intelDir := filepath.Join(dir, "intel")
	if err := os.MkdirAll(intelDir, 0o755); err != nil {
		t.Fatalf("mkdir intel: %v", err)
	}
	filePath := filepath.Join(intelDir, "intel-delete-sc.yaml")
	intelYAML := []byte("id: intel-delete-sc\nname: Intel Delete\nlocal_check: true\n")
	if err := os.WriteFile(filePath, intelYAML, 0o644); err != nil {
		t.Fatalf("write intel file: %v", err)
	}

	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := e.Get("intel-delete-sc"); !ok {
		t.Fatalf("fixture not loaded")
	}

	// Engine-level Delete permits removing an intel-sourced scenario — only
	// the API layer restricts intel deletion (see DeleteScenario's source
	// guard, tested in internal/api/scenario_source_guard_test.go).
	if err := e.Delete("intel-delete-sc"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, ok := e.Get("intel-delete-sc"); ok {
		t.Fatalf("scenario still present in memory after delete")
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("file still present on disk after delete: err = %v", err)
	}
}
```

- [ ] **Step 3: Run the new tests**

Run: `go test ./internal/scenario/... -run 'TestValidate_IDPathTraversal|TestSave_RoundTripFidelity|TestLoad_SourceClassification|TestLoad_UnsignedBuiltinRefused|TestDelete_IntelRescan' -v -count=1`

Expected: all 5 tests PASS. (This package has no testcontainer dependency —
`TestSaveAndDelete`/`TestValidate` already run without Docker, and these do too.)

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/scenario/engine_test.go
git commit -m "$(cat <<'EOF'
test(scenario): add idPattern, round-trip, source-classification,
unsigned-builtin-refusal, and intel-delete-rescan tests

Phase 3b.3. Closes the engine-level gaps not already covered by
TestSaveAndDelete/TestValidate.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 8: Final validation and phase close-out

**Files:** none created/modified beyond memory files.

- [ ] **Step 1: Run the full new-test suite together**

Run:
```bash
go test ./internal/api/... ./internal/scenario/... \
  -run 'TestListScenarios|TestGetScenario|TestCreateScenario|TestUpdateScenario|TestUploadScenario|TestCloneScenario|TestDeleteScenario|TestValidate_IDPathTraversal|TestSave_RoundTripFidelity|TestLoad_SourceClassification|TestLoad_UnsignedBuiltinRefused|TestDelete_IntelRescan' \
  -v -count=1
```

Expected: every test from Tasks 1–7 PASSes (31 in `internal/api`, 5 in `internal/scenario`).

- [ ] **Step 2: Targeted determinism stress run**

These tests use per-test `t.TempDir()` (auto-isolated, no shared state) and no
WebSocket/goroutine timing, so flake risk is low — but confirm it. Run the
same `-run` regex from Step 1 with `-count=10` on both packages:

```bash
go test ./internal/api/... ./internal/scenario/... \
  -run 'TestListScenarios|TestGetScenario|TestCreateScenario|TestUpdateScenario|TestUploadScenario|TestCloneScenario|TestDeleteScenario|TestValidate_IDPathTraversal|TestSave_RoundTripFidelity|TestLoad_SourceClassification|TestLoad_UnsignedBuiltinRefused|TestDelete_IntelRescan' \
  -count=10
```

Expected: `ok` for both packages, no `FAIL`, no `-race`-style warnings. If this
times out, don't widen it to the full package — first check `go test ... -v`
output for which specific test is slow (most likely a testcontainer
cold-start on the first `sharedDB.RunWithPool` call, which is expected and
one-time per process) before increasing any timeout.

Note on `-race`: as in Phase 3b.2, the race detector is configured to run in
CI on a Linux runner with CGO/toolchain support; it cannot be executed on
this local host because `CGO_ENABLED=0` and no C toolchain is available here.

- [ ] **Step 3: Coverage review**

Run:
```bash
go test ./internal/api/... \
  -run 'TestListScenarios|TestGetScenario|TestCreateScenario|TestUpdateScenario|TestUploadScenario|TestCloneScenario|TestDeleteScenario' \
  -coverprofile=coverage_3b3_api.out -coverpkg=./internal/api -count=1
go tool cover -func=coverage_3b3_api.out | grep -E 'ListScenarios|GetScenario|CreateScenario|UpdateScenario|UploadScenario|CloneScenario|DeleteScenario'

go test ./internal/scenario/... -coverprofile=coverage_3b3_engine.out -count=1
go tool cover -func=coverage_3b3_engine.out | grep -E 'Validate|Save|Delete|Load|sourceForPath|ParseYAML'
```

Read the annotated source (`go tool cover -html=coverage_3b3_api.out` if a
browser is available, otherwise inspect line numbers manually) for each of
the 7 handlers and confirm every branch is hit **except**:
- the async `auditLog` goroutine body (out of scope by design, per Global
  Constraints)
- `os`-level I/O failure paths inside `Save`/`Delete`/`Load` (out of scope,
  consistent with the "don't chase OS-fault branches" rule from Phases
  3b.1/3b.2)

If any *other* branch is uncovered, add a targeted test case to the relevant
task's file before proceeding — don't skip it silently. Delete the two
`coverage_3b3_*.out` files afterward; they're scratch artifacts, not meant to
be committed.

- [ ] **Step 4: Duplication check**

Skim the 3 new test files plus the `engine_test.go` additions for copy-pasted
setup that could collapse into a helper. Given `newFileEngine`,
`seedCustomScenario`, `seedIntelScenario`, `minimalScenario`, `scenarioJSON`,
and `readScenarioFile` were front-loaded in Task 1 specifically to avoid this,
expect little to nothing to change here. If you do find real duplication,
extract it into Task 1's helper block and update call sites — otherwise leave
the tests as-is (some repetition of the `if testing.Short() { t.Skip(...) }` /
`sharedDB.RunWithPool` scaffolding per test is expected and matches the
established pattern from `result_mac_test.go` / `submit_scenario_result_test.go`).

- [ ] **Step 5: Update memory**

Read `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_test_generation_phase0.md`,
append a "Phase 3b.3 DONE" section summarizing: 7 handlers + 5 engine tests,
36 total test functions, the CloneScenario shallow-copy finding, and the
"no genuinely-signed builtin fixture available" constraint that shaped the
source-guard and clone matrices. Mark **Phase 3b (Scenario & Run Lifecycle)
complete** — 3b.1, 3b.2, and 3b.3 are now all done. Update the frontmatter
`description` field to reflect this. Then update
`C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\MEMORY.md`'s
index line for this memory to say Phase 3b is complete and name whatever
comes next in the Phase 3 roadmap (or "next phase not yet chosen" if none has
been discussed).

- [ ] **Step 6: Final commit**

```bash
git add C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_test_generation_phase0.md \
        C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\MEMORY.md
git commit -m "$(cat <<'EOF'
docs(memory): mark Phase 3b.3 and Phase 3b (Scenario & Run Lifecycle) done

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

Report to the user: total test count, coverage numbers per handler, the
CloneScenario finding, and that Phase 3b is fully complete.
