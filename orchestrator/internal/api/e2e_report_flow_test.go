package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestE2E_AuthoringToReporting proves the seams between the already-tested
// phases compose: author a scenario, dispatch it to a connected agent, ingest a
// MAC-signed result, then render the report. Every assertion here is covered in
// depth elsewhere — this test exists ONLY to prove composition. Do not grow it.
func TestE2E_AuthoringToReporting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// 1. Authoring: a live scenario with one T1059.001 step.
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059.001", Framework: "custom", Command: "echo hi"}}
		sc, engine := minimalLiveScenario(t, "e2e-sc", steps...)

		hub := ws.NewHub()
		t.Setenv("CHROME_WS_URL", "")
		h := New(pool, hub, engine, "").
			WithReporting(reporting.NewEngine(pool).WithScenarios(engine)).
			WithCompliance(mustMapper(t))

		// 2. Dispatch: connect a fake agent, run the scenario, capture runId.
		agentID := "e2e-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, hub, agentID)
		defer fake.Disconnect(t)

		runRec := httptest.NewRecorder()
		h.RunScenario(runRec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if runRec.Code != http.StatusOK {
			t.Fatalf("dispatch status = %d, body = %s", runRec.Code, runRec.Body.String())
		}
		var dispatch map[string]any
		_ = json.Unmarshal(runRec.Body.Bytes(), &dispatch)
		runID, _ := dispatch["runId"].(string)
		if runID == "" {
			t.Fatal("dispatch returned no runId")
		}
		fake.WaitForMessage(t, 3*time.Second) // agent received the command

		// 3. Ingestion: submit a result for the dispatched step (fail verdict).
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059.001", "step-0"), ExitCode: 0, Stdout: "FAIL: technique not blocked"}},
		})

		// 4. Reporting: the run report reflects the submitted technique.
		htmlRec := httptest.NewRecorder()
		h.GetRunReport(htmlRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if htmlRec.Code != http.StatusOK {
			t.Fatalf("report status = %d", htmlRec.Code)
		}
		if !strings.Contains(htmlRec.Body.String(), "T1059.001") {
			t.Fatal("report HTML missing the technique that flowed through the whole pipeline")
		}

		csvRec := httptest.NewRecorder()
		h.GetRunForensicCSV(csvRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if !strings.Contains(csvRec.Body.String(), "T1059.001") {
			t.Fatal("forensic CSV missing the technique")
		}

		pdfRec := httptest.NewRecorder()
		h.GetRunPDF(pdfRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if pdfRec.Code != http.StatusOK || !strings.HasPrefix(pdfRec.Body.String(), "%PDF") {
			t.Fatalf("PDF not generated (status=%d)", pdfRec.Code)
		}
	})
}
