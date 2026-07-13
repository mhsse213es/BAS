package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func detectionsReq(runID, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/detections", strings.NewReader(body))
	return withURLParam(req, "runId", runID)
}

func TestSubmitRunDetections_Unauthorized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil).WithAgentSecret("s3cr3t")
		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, detectionsReq("srd-run", `{"alerts":[]}`))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestSubmitRunDetections_InvalidBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, detectionsReq("srd-run", `{"alerts":`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSubmitRunDetections_RunNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, detectionsReq("nope", `{"alerts":[]}`))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestSubmitRunDetections_Success posts one alert that correlates (by
// timestamp + non-empty threatName) against a FAIL step, and pins: the
// response's rate/count fields, that scenario_runs persists the raw+summary
// detection columns, and that the technique's DetectionVerdict is merged
// into the stored results.
func TestSubmitRunDetections_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "srd-ok-run", "agent-srd-ok", reportRunOpts{
			Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)

		alertTS := at.Add(1 * time.Minute)
		body := `{"alerts":[{"channel":"Microsoft-Windows-Windows Defender/Operational","provider":"Windows Defender","eventId":1116,"timestamp":"` +
			alertTS.Format(time.RFC3339) + `","threatName":"Test-Malware"}]}`

		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, detectionsReq("srd-ok-run", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["runId"] != "srd-ok-run" {
			t.Fatalf("runId = %v", out["runId"])
		}
		if dr, _ := out["detectionRate"].(float64); dr != 100 {
			t.Errorf("detectionRate = %v, want 100 (the only FAIL step was detected)", out["detectionRate"])
		}
		if af, _ := out["alertsTotal"].(float64); af != 1 {
			t.Errorf("alertsTotal = %v, want 1", out["alertsTotal"])
		}

		var detRaw, detSum, resultsRaw []byte
		var alertsTotal, alertsHigh int
		if err := pool.QueryRow(context.Background(),
			`SELECT detections_raw, detection_summary, results, alerts_total, alerts_high_fidelity
			   FROM scenario_runs WHERE id = 'srd-ok-run'`,
		).Scan(&detRaw, &detSum, &resultsRaw, &alertsTotal, &alertsHigh); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if len(detRaw) == 0 || string(detRaw) == "null" {
			t.Error("detections_raw not persisted")
		}
		if len(detSum) == 0 || string(detSum) == "null" {
			t.Error("detection_summary not persisted")
		}
		if alertsTotal != 1 || alertsHigh != 1 {
			t.Errorf("alerts_total/alerts_high_fidelity = %d/%d, want 1/1 (Defender detect ID + threatName)", alertsTotal, alertsHigh)
		}
		var mergedResults []map[string]any
		if err := json.Unmarshal(resultsRaw, &mergedResults); err != nil {
			t.Fatalf("decode stored results: %v", err)
		}
		if len(mergedResults) != 1 || mergedResults[0]["detectionVerdict"] != "detected" {
			t.Errorf("results should have the merged detectionVerdict=detected; got %s", resultsRaw)
		}
	})
}

// TestSubmitRunDetections_Idempotent pins the documented REPLACE semantics:
// re-submitting detections for the same run overwrites the row rather than
// appending, and the second (empty-alerts) submission clears the first
// submission's counts.
func TestSubmitRunDetections_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "srd-idem-run", "agent-srd-idem", reportRunOpts{
			Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)

		alertTS := at.Add(1 * time.Minute)
		body1 := `{"alerts":[{"provider":"Windows Defender","eventId":1116,"timestamp":"` +
			alertTS.Format(time.RFC3339) + `","threatName":"Test-Malware"}]}`
		rec1 := httptest.NewRecorder()
		h.SubmitRunDetections(rec1, detectionsReq("srd-idem-run", body1))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first submit: status = %d", rec1.Code)
		}

		rec2 := httptest.NewRecorder()
		h.SubmitRunDetections(rec2, detectionsReq("srd-idem-run", `{"alerts":[]}`))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second submit: status = %d", rec2.Code)
		}

		var alertsTotal int
		if err := pool.QueryRow(context.Background(),
			`SELECT alerts_total FROM scenario_runs WHERE id = 'srd-idem-run'`,
		).Scan(&alertsTotal); err != nil {
			t.Fatalf("query: %v", err)
		}
		if alertsTotal != 0 {
			t.Fatalf("alerts_total = %d, want 0 (second submission should replace, not append)", alertsTotal)
		}
	})
}

// TestSubmitRunDetections_TriggersFindingsRefresh pins the same-run
// refinement contract with findings: submitting a detection that correlates
// a FAIL technique must flip the already-created finding's exposure_state
// from missed to detected_only (upsertFindingsForRun is called at the end of
// the handler).
func TestSubmitRunDetections_TriggersFindingsRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "srd-find-run", "agent-srd-find", reportRunOpts{
			StartedAt: at, Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "srd-find-run")

		f, ok := queryFinding(t, pool, "agent-srd-find", "T1059.001")
		if !ok || f.ExposureState != "missed" {
			t.Fatalf("precondition: finding = %+v (ok=%v), want exposure=missed before detections arrive", f, ok)
		}

		alertTS := at.Add(1 * time.Minute)
		body := `{"alerts":[{"provider":"Windows Defender","eventId":1116,"timestamp":"` +
			alertTS.Format(time.RFC3339) + `","threatName":"Test-Malware"}]}`
		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, detectionsReq("srd-find-run", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		f, ok = queryFinding(t, pool, "agent-srd-find", "T1059.001")
		if !ok {
			t.Fatal("finding disappeared")
		}
		if f.ExposureState != "detected_only" {
			t.Fatalf("exposure_state = %q, want detected_only after correlated detections arrived", f.ExposureState)
		}
	})
}
