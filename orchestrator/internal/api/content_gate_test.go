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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/jobs"
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
		ev, err := e.ResolveExecutable(context.Background(), "pin")
		if err != nil {
			t.Fatal(err)
		}
		if *vid != ev.VersionID {
			t.Fatalf("stored content_version_id=%s, want the resolved version %s", *vid, ev.VersionID)
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

// Fix round 1: a campaign's live-safety policy is judged on the pinned
// (approved) version, never on a newer out-of-band DRAFT on disk.
func TestCreateCampaign_LivePolicyJudgedOnPinnedVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		v1 := &scenario.Scenario{ID: "camp-pin", Name: "C", LocalCheck: true} // posture-only
		if err := e.SaveAs(context.Background(), v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		_, _ = pool.Exec(context.Background(), `INSERT INTO content_registry_state (id) VALUES (1)`)
		// Out-of-band edit makes the disk copy executable -> new DRAFT v2.
		if err := os.WriteFile(filepath.Join(dir, "custom", "camp-pin.yaml"), []byte(`id: camp-pin
name: C
local_check: true
executable: true
steps:
  - {name: a, technique_id: T1082, framework: custom, command: a}
`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		if d, _ := e.Get("camp-pin"); d == nil || !d.Executable {
			t.Fatal("precondition: the disk DRAFT should be executable")
		}
		seedAgent(t, pool, "ca")
		h := New(pool, ws.NewHub(), e, "")
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{
			"name": "x", "scenarioId": "camp-pin", "agentIds": []string{"ca"},
			"mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "does not support live execution") {
			t.Fatalf("v1 (posture-only) must govern: code=%d body=%s", rec.Code, rec.Body.String())
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM campaigns`).Scan(&n)
		if n != 0 {
			t.Fatalf("a refused campaign must not create a campaigns row, got %d", n)
		}
	})
}

func TestCreateCampaign_GateDenialIs409BeforeCampaignRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-c\nname: I\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "cb")
		h := New(pool, ws.NewHub(), e, "")
		rec := httptest.NewRecorder()
		h.CreateCampaign(rec, createCampaignReq(map[string]any{"name": "x", "scenarioId": "intel-c", "agentIds": []string{"cb"}}))
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "DRAFT") {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM campaigns`).Scan(&n)
		if n != 0 {
			t.Fatalf("a denied campaign must not create a campaigns row, got %d", n)
		}
	})
}

func TestScheduledAssessment_GateDenialReturnsContentNotExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-s\nname: I\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "sd")
		h := New(pool, ws.NewHub(), e, "")
		payload, _ := json.Marshal(scheduledAssessmentPayload{ScenarioID: "intel-s", Mode: "posture"})
		job := jobs.Job{ID: "job-g", Type: "scheduled_assessment", CreatedBy: "sched-g", Payload: payload}
		target := jobs.JobTarget{ID: "target-g", JobID: "job-g", AgentID: "sd"}
		runID, err := h.dispatchScheduledAssessmentTarget(context.Background(), job, target)
		if err == nil || !strings.Contains(err.Error(), "content not executable") || runID != "" {
			t.Fatalf("want gate denial, got run=%q err=%v", runID, err)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM scenario_runs`).Scan(&n)
		if n != 0 {
			t.Fatalf("a denied scheduled dispatch must not create a run row, got %d", n)
		}
	})
}

// Fix round 1 (spec §10): a gate denial is terminal for auto-revalidation --
// the ticket is not reset for retry, and the denial is audited.
func TestRevalidation_GateDenialIsTerminal(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-r\nname: I\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		findingID := seedFindingForTicketing(t, pool, "rv", "T1082", "High")
		var cfgID, ticketID string
		if err := pool.QueryRow(ctx, `INSERT INTO ticketing_configs (name, provider) VALUES ('c','jira') RETURNING id`).Scan(&cfgID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO finding_tickets (finding_id, config_id, ticket_id, status, revalidation_required)
			 VALUES ($1,$2,'T-1','resolved',true) RETURNING id`, findingID, cfgID).Scan(&ticketID); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), e, "")
		h.dispatchRevalidation(ctx, revalidationCandidate{
			ticketID: ticketID, findingID: findingID, agentID: "rv",
			techniqueID: "T1082", lastScenarioID: "intel-r",
		})
		var dispatchedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT revalidation_dispatched_at FROM finding_tickets WHERE id=$1`, ticketID).Scan(&dispatchedAt); err != nil {
			t.Fatal(err)
		}
		if dispatchedAt == nil {
			t.Fatal("a gate denial must not reset the ticket for retry")
		}
		var runs int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM scenario_runs`).Scan(&runs)
		if runs != 0 {
			t.Fatalf("no run may be created, got %d", runs)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx,
				`SELECT count(*) FROM audit_logs WHERE action='revalidation.content_not_executable' AND resource=$1 AND outcome='error'`,
				findingID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("want 1 revalidation.content_not_executable audit row, got %d", n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// A9 end-to-end: result interpretation uses the pinned version's step names
// even after the disk YAML changed.
func TestSubmitResult_InterpretsAgainstPinnedVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, _ := registryEngine(t, pool)
		v1 := &scenario.Scenario{ID: "hp", Name: "HP", Executable: true,
			Steps: []scenario.Step{{Name: "Original step", TechniqueID: "T1082", Framework: "custom", Command: "a"}}}
		if err := e.SaveAs(context.Background(), v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		ev, _ := reg.ResolveExecutable(context.Background(), "hp")
		seedAgent(t, pool, "hpa")
		var runID string
		_ = pool.QueryRow(context.Background(), `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('hp','hpa','content',$1) RETURNING id`, ev.VersionID).Scan(&runID)
		v2 := *v1
		v2.Steps = []scenario.Step{{Name: "Renamed step", TechniqueID: "T1082", Framework: "custom", Command: "a"}}
		_ = e.SaveAs(context.Background(), &v2, "user:op")
		h := New(pool, ws.NewHub(), e, "")
		rc := h.runContent(context.Background(), runID)
		if rc.Scenario == nil || rc.Scenario.Steps[0].Name != "Original step" {
			t.Fatalf("pinned interpretation lost: %+v", rc.Scenario)
		}
	})
}
