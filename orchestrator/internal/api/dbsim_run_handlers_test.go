package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Without a loaded scenario engine and database the run route must refuse and start
// nothing, never fall through to a partially built service.
func TestStartDBSimRunAnswers503WhenNotConfigured(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/dbsim-targets/lab-db/runs", strings.NewReader(`{"scenarioIds":["x"]}`))
	rec := httptest.NewRecorder()
	h.StartDBSimRun(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if h.dbsimRunSvc != nil {
		t.Fatal("a service was built without an engine or database")
	}
}

// A database run's result never reaches the scenario grader. With no database
// simulation service loaded, it is refused (503), not graded as a scenario.
func TestSubmitScenarioResultRoutesDBSimRunsAwayFromScenarioGrader(t *testing.T) {
	h := &Handler{}
	body := []byte(`{"runId":"bas-dbsim-run:0123456789abcdef","agentId":"0123456789abcdef","results":[]}`)
	rec := httptest.NewRecorder()
	h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (refused, not graded as a scenario)", rec.Code)
	}
}
