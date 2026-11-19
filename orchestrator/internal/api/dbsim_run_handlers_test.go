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
