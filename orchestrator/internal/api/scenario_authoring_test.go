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
// not available to tests or CI (see the source-guard matrix comment in
// scenario_source_guard_test.go). The unsigned-builtin-refusal path is
// covered separately in engine_test.go's TestLoad_UnsignedBuiltinRefused.
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

func TestUpdateScenario_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("update-malformed-sc"))
		before := readScenarioFile(t, filepath.Join(dir, "custom", "update-malformed-sc.yaml"))
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/update-malformed-sc", strings.NewReader(`{"name": `)), "id", "update-malformed-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		after := readScenarioFile(t, filepath.Join(dir, "custom", "update-malformed-sc.yaml"))
		if string(before) != string(after) {
			t.Fatalf("file mutated despite malformed JSON body:\nbefore:\n%s\nafter:\n%s", before, after)
		}
	})
}

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
