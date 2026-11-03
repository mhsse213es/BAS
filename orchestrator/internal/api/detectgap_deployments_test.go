package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/verification"
)

type depItem struct {
	ID            string `json:"id"`
	TechniqueID   string `json:"techniqueId"`
	RuleID        string `json:"ruleId"`
	Backend       string `json:"backend"`
	Note          string `json:"note"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
	RetestRunID   string `json:"retestRunId"`
	DeployedBy    string `json:"deployedBy"`
	RuleInLibrary bool   `json:"ruleInLibrary"`
}

type depList struct {
	Retest struct {
		ScenarioID string `json:"scenarioId"`
		AgentID    string `json:"agentId"`
		Mode       string `json:"mode"`
	} `json:"retest"`
	Deployments []depItem `json:"deployments"`
}

func postDep(h *Handler, runID string, body map[string]any) (*httptest.ResponseRecorder, depItem) {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.CreateRuleDeployment(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(b)), "runId", runID))
	var it depItem
	json.Unmarshal(rec.Body.Bytes(), &it)
	return rec, it
}

func listDeps(t *testing.T, h *Handler, runID string) depList {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ListRuleDeployments(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", rec.Code, rec.Body.String())
	}
	var out depList
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func linkRetest(h *Handler, runID, depID, retestRun string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"retestRunId": retestRun})
	rec := httptest.NewRecorder()
	h.LinkDeploymentRetest(rec, withURLParams(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(b)),
		map[string]string{"runId": runID, "deploymentId": depID}))
	return rec
}

// seedRetestRun inserts another run of the same scenario; agent "" means the origin agent a1.
func seedRetestRun(t *testing.T, pool *pgxpool.Pool, agent, status string, results []models.SimulationResult) string {
	t.Helper()
	if agent == "" {
		agent = "a1"
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ($1, 'other', 'active') ON CONFLICT DO NOTHING`, agent); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(results)
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scenario_runs (scenario_id, agent_id, status, execution_kind, results) VALUES ('scn-gap', $1, $2, 'legacy', $3) RETURNING id`,
		agent, status, raw).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// otherTechniqueRule finds a library rule that is not tagged with the technique (nor its parent).
func otherTechniqueRule(t *testing.T, h *Handler) string {
	t.Helper()
	for _, other := range []string{"T1003", "T1547", "T1218", "T1053"} {
		if rs, _ := h.rulesFor(other); len(rs) > 0 {
			return rs[0].ID
		}
	}
	t.Fatal("no unrelated rule found")
	return ""
}

func TestRuleDeployments_RecordOnlyForARealGapWithARuleThatTargetsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail), res("T1003.001", models.ResultFail)})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		attest(t, pool, runID, "T1003.001", verification.ResultDetected, verification.StateApproved)

		rules, _ := h.rulesFor("T1059.001")
		rule, backend := rules[0].ID, rules[0].Translations[0].Backend

		rec, it := postDep(h, runID, map[string]any{"techniqueId": "T1059.001", "ruleId": rule, "backend": backend, "note": "pushed to prod"})
		if rec.Code != http.StatusCreated || it.ID == "" || it.Status != "Deployed" || it.Detail == "" {
			t.Fatalf("record = %d %+v %s", rec.Code, it, rec.Body.String())
		}
		got := listDeps(t, h, runID)
		if len(got.Deployments) != 1 || got.Deployments[0].Note != "pushed to prod" || !got.Deployments[0].RuleInLibrary {
			t.Fatalf("list = %+v", got)
		}
		if got.Retest.ScenarioID != "scn-gap" || got.Retest.AgentID != "a1" {
			t.Errorf("retest parameters = %+v (the console starts the re-test from these)", got.Retest)
		}

		cases := map[string]struct {
			body map[string]any
			want int
		}{
			"missing fields":                            {map[string]any{"techniqueId": "T1059.001"}, http.StatusBadRequest},
			"a technique that was detected":             {map[string]any{"techniqueId": "T1003.001", "ruleId": rule, "backend": backend}, http.StatusConflict},
			"a technique not in the run":                {map[string]any{"techniqueId": "T1047", "ruleId": rule, "backend": backend}, http.StatusConflict},
			"a rule not in the library":                 {map[string]any{"techniqueId": "T1059.001", "ruleId": "AUDRULE-999999", "backend": backend}, http.StatusNotFound},
			"a rule that does not target the technique": {map[string]any{"techniqueId": "T1059.001", "ruleId": otherTechniqueRule(t, h), "backend": backend}, http.StatusUnprocessableEntity},
			"a backend the rule lacks":                  {map[string]any{"techniqueId": "T1059.001", "ruleId": rule, "backend": "nosuchsiem"}, http.StatusUnprocessableEntity},
		}
		for name, c := range cases {
			if rec, _ := postDep(h, runID, c.body); rec.Code != c.want {
				t.Errorf("%s: status = %d, want %d (%s)", name, rec.Code, c.want, rec.Body.String())
			}
		}
		if rec, _ := postDep(h, "no-such-run", map[string]any{"techniqueId": "T1059.001", "ruleId": rule, "backend": backend}); rec.Code != http.StatusNotFound {
			t.Errorf("unknown run = %d", rec.Code)
		}
		if n := len(listDeps(t, h, runID).Deployments); n != 1 {
			t.Errorf("rejected requests must not be recorded: %d deployments", n)
		}
	})
}

func TestRuleDeployments_RetestOutcomeComesOnlyFromTheRetestRunsReviewedEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := gapHandler(pool, t)
		runID := seedGapRun(t, pool, []models.SimulationResult{res("T1059.001", models.ResultFail)})
		attest(t, pool, runID, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		earlier := seedRetestRun(t, pool, "", "completed", []models.SimulationResult{res("T1059.001", models.ResultFail)}) // before the deployment
		rules, _ := h.rulesFor("T1059.001")
		_, dep := postDep(h, runID, map[string]any{"techniqueId": "T1059.001", "ruleId": rules[0].ID, "backend": rules[0].Translations[0].Backend})

		status := func() depItem { return listDeps(t, h, runID).Deployments[0] }

		// Linking validates the run: another run of the same scenario on the same agent, started after the deployment.
		if rec := linkRetest(h, runID, dep.ID, runID); rec.Code != http.StatusBadRequest {
			t.Errorf("linking the origin run as its own re-test = %d", rec.Code)
		}
		if rec := linkRetest(h, runID, dep.ID, "no-such-run"); rec.Code != http.StatusNotFound {
			t.Errorf("unknown re-test run = %d", rec.Code)
		}
		if rec := linkRetest(h, runID, dep.ID, earlier); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("a run that started before the deployment cannot be its re-test: %d", rec.Code)
		}
		otherAgent := seedRetestRun(t, pool, "a2", "completed", nil)
		if rec := linkRetest(h, runID, dep.ID, otherAgent); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("a run on a different agent cannot be its re-test: %d", rec.Code)
		}
		if rec := linkRetest(h, "no-such-run", dep.ID, otherAgent); rec.Code != http.StatusNotFound {
			t.Errorf("unknown origin run = %d", rec.Code)
		}
		if status().Status != "Deployed" {
			t.Fatalf("failed links must change nothing: %+v", status())
		}

		running := seedRetestRun(t, pool, "", "running", nil)
		if rec := linkRetest(h, runID, dep.ID, running); rec.Code != http.StatusOK {
			t.Fatalf("link = %d %s", rec.Code, rec.Body.String())
		}
		if s := status(); s.Status != "Re-test running" || s.RetestRunID != running {
			t.Errorf("running re-test: %+v", s)
		}

		// A finished re-test nobody has verified is not a closed gap.
		done := seedRetestRun(t, pool, "", "completed", []models.SimulationResult{res("T1059.001", models.ResultFail)})
		linkRetest(h, runID, dep.ID, done)
		if s := status(); s.Status != "Re-test awaiting verification" {
			t.Errorf("unverified re-test: %+v", s)
		}
		attest(t, pool, done, "T1059.001", verification.ResultNotDetected, verification.StateApproved)
		if s := status(); s.Status != "Still a gap" {
			t.Errorf("re-test missed again: %+v", s)
		}
		attest(t, pool, done, "T1059.001", verification.ResultDetected, verification.StateApproved)
		if s := status(); s.Status != "Closed on re-test" || s.Detail == "" {
			t.Errorf("re-test detected: %+v", s)
		}
	})
}
