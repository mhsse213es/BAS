package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/ws"
)

func registryEngine(t *testing.T, pool *pgxpool.Pool) (*scenario.Engine, *contentregistry.Registry, string) {
	t.Helper()
	dir := t.TempDir()
	e := scenario.NewEngine(dir)
	e.SetVerifier(testutil.DevVerifier())
	reg := contentregistry.New(pool, testutil.DevVerifier())
	e.AttachRegistry(reg)
	return e, reg, dir
}

func seedAgent(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, os_version, state) VALUES ($1,'h','Windows 10','active') ON CONFLICT DO NOTHING`, id); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchRun_DeniesDraftIntelAndRecordsNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-x\nname: I\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "ga")
		h := New(pool, ws.NewHub(), e, "")
		sc, _ := e.Get("intel-x")
		runID, skip, err := h.dispatchRun(context.Background(), sc, "ga", dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || !strings.HasPrefix(skip, "content not executable: ") {
			t.Fatalf("want gate denial, got run=%q skip=%q err=%v", runID, skip, err)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM scenario_runs`).Scan(&n)
		if n != 0 {
			t.Fatalf("a denied dispatch must not create a run row, got %d", n)
		}
	})
}

func TestDispatchRun_ContentRunPinnedBeforeDispatch(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		if err := e.SaveAs(context.Background(), &scenario.Scenario{ID: "pin", Name: "P", LocalCheck: true}, "user:op"); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "pa")
		h := New(pool, ws.NewHub(), e, "")
		sc, _ := e.Get("pin")
		_, _, _ = h.dispatchRun(context.Background(), sc, "pa", dispatchOpts{Mode: "posture"}) // agent offline -> failed run, row still exists
		var kind string
		var vid *string
		if err := pool.QueryRow(context.Background(),
			`SELECT execution_kind, content_version_id FROM scenario_runs WHERE scenario_id='pin'`).Scan(&kind, &vid); err != nil {
			t.Fatal(err)
		}
		if kind != "content" || vid == nil || *vid == "" {
			t.Fatalf("kind=%s version=%v", kind, vid)
		}
	})
}

func TestRunScenario_GateDenialIs409(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-y\nname: I\nlocal_check: true\n"), 0o644)
		_ = e.Load()
		seedAgent(t, pool, "ra")
		h := New(pool, ws.NewHub(), e, "")
		body, _ := json.Marshal(map[string]any{"agentId": "ra"})
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/intel-y/run", bytes.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "intel-y")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.RunScenario(rec, req)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "DRAFT") {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// Review Focus 1: indices are validated against the executed version, not
// the newer disk file.
func TestRunScenario_StepSubsetValidatedAgainstExecutedVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		one := &scenario.Scenario{ID: "sub", Name: "S", Executable: true,
			Steps: []scenario.Step{{Name: "a", TechniqueID: "T1082", Framework: "custom", Command: "a"}}}
		if err := e.SaveAs(context.Background(), one, "user:op"); err != nil {
			t.Fatal(err)
		}
		_, _ = pool.Exec(context.Background(), `INSERT INTO content_registry_state (id) VALUES (1)`)
		// Out-of-band edit adds a second step -> new DRAFT; v1 (one step) still executes.
		_ = os.WriteFile(filepath.Join(dir, "custom", "sub.yaml"), []byte(`id: sub
name: S
executable: true
steps:
  - {name: a, technique_id: T1082, framework: custom, command: a}
  - {name: b, technique_id: T1083, framework: custom, command: b}
`), 0o644)
		_ = e.Load()
		seedAgent(t, pool, "sa")
		h := New(pool, ws.NewHub(), e, "")
		body, _ := json.Marshal(map[string]any{"agentId": "sa", "steps": []int{1}})
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/sub/run", bytes.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "sub")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.RunScenario(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "out of range") {
			t.Fatalf("index 1 does not exist in executed v1: code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// A8 (source half): every INSERT INTO scenario_runs in internal/api sets
// execution_kind explicitly.
func TestEveryRunInsertSetsKind(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		src := string(b)
		for i := strings.Index(src, "INSERT INTO scenario_runs"); i >= 0; {
			end := strings.Index(src[i:], "VALUES")
			if end < 0 {
				end = len(src) - i
			}
			if !strings.Contains(src[i:i+end], "execution_kind") {
				t.Errorf("%s: INSERT INTO scenario_runs without execution_kind near offset %d", f, i)
			}
			next := strings.Index(src[i+1:], "INSERT INTO scenario_runs")
			if next < 0 {
				break
			}
			i = i + 1 + next
		}
	}
}
