package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

// fakeQRadar serves the three Ariel endpoints Correlate uses. events is the
// result set returned for any search; resultsStatus overrides the status of
// the results endpoint (0 = 200).
func fakeQRadar(t *testing.T, events []map[string]any, resultsStatus int) (Config, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/console/restapi/api/ariel/searches", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"search_id": "s1"})
	})
	mux.HandleFunc("/console/restapi/api/ariel/searches/s1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "COMPLETED"})
	})
	mux.HandleFunc("/console/restapi/api/ariel/searches/s1/results", func(w http.ResponseWriter, r *http.Request) {
		if resultsStatus >= 400 {
			w.WriteHeader(resultsStatus)
			_, _ = w.Write([]byte(`{"message":"boom"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	})
	srv := httptest.NewServer(mux)
	return Config{ID: "c1", Provider: ProviderQRadar, ConsoleURL: srv.URL, Token: "t"}, srv.Close
}

func event(ts time.Time, rule string) map[string]any {
	return map[string]any{"starttime": float64(ts.UnixMilli()), "rule_name": rule, "sourceip": "10.0.0.5"}
}

func result(id string, verdict models.CheckResult, at time.Time, durMs int64) models.SimulationResult {
	return models.SimulationResult{
		Technique:  models.AttackTechnique{ID: id, Name: "name " + id},
		Result:     verdict,
		ExecutedAt: at,
		DurationMs: durMs,
	}
}

func TestCorrelate_VerdictsAndStepWindow(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	// T1: alert 29s before the step start, inside the -30s lead.
	// T2: alert 31s before the step start, outside it.
	// T3: alert exactly at step end (start + 1s duration + 60s), inclusive.
	events := []map[string]any{
		event(t0.Add(-29*time.Second), "r1"),
		event(t1.Add(-31*time.Second), "r2"),
		event(t2.Add(61*time.Second), "r3"),
	}
	cfg, stop := fakeQRadar(t, events, 0)
	defer stop()
	results := []models.SimulationResult{
		result("T1", models.ResultFail, t0, 1000),
		result("T2", models.ResultFail, t1, 1000),
		result("T3", models.ResultFail, t2, 1000),
		result("T4", models.ResultPass, t0.Add(3*time.Hour), 0),
		result("T5", models.ResultError, t0.Add(4*time.Hour), 0),
		result("T6", models.ResultBlocked, t0.Add(5*time.Hour), 0),
	}
	rep, err := Correlate(context.Background(), cfg, "run1", "agent1", "10.0.0.5",
		t0.Add(-10*time.Minute), t0.Add(6*time.Hour), results)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	want := map[string]string{"T1": "detected", "T2": "undetected", "T3": "detected",
		"T4": "not_applicable", "T5": "not_executed", "T6": "not_applicable"}
	for _, tc := range rep.Techniques {
		if tc.SIEMVerdict != want[tc.TechniqueID] {
			t.Errorf("%s verdict = %q, want %q", tc.TechniqueID, tc.SIEMVerdict, want[tc.TechniqueID])
		}
	}
	if rep.Detected != 2 || rep.Undetected != 1 || rep.NotExecuted != 1 {
		t.Errorf("counts detected=%d undetected=%d notExecuted=%d, want 2/1/1", rep.Detected, rep.Undetected, rep.NotExecuted)
	}
	// Rates are over executed techniques only: 2 of 3.
	if rep.DetectionRate != 66 || rep.UndetectedRate != 33 {
		t.Errorf("rates = %d/%d, want 66/33", rep.DetectionRate, rep.UndetectedRate)
	}
}

func TestCorrelate_CapsAlertsKeptPerTechnique(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	var events []map[string]any
	for i := 0; i < 7; i++ {
		events = append(events, event(t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("r%d", i)))
	}
	cfg, stop := fakeQRadar(t, events, 0)
	defer stop()
	rep, err := Correlate(context.Background(), cfg, "run1", "agent1", "10.0.0.5",
		t0.Add(-time.Minute), t0.Add(time.Minute), []models.SimulationResult{result("T1", models.ResultFail, t0, 0)})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if got := len(rep.Techniques[0].Alerts); got != maxAlertsPerTech {
		t.Fatalf("kept %d alerts, want %d", got, maxAlertsPerTech)
	}
}

func TestCorrelate_RejectsEmptyAndNonIPAgent(t *testing.T) {
	cfg := Config{Provider: ProviderQRadar, ConsoleURL: "http://127.0.0.1:1", Token: "t"}
	now := time.Now()
	for _, ip := range []string{"", "10.0.0.5' OR '1'='1", "not-an-ip", "10.0.0.5 OR 1=1"} {
		_, err := Correlate(context.Background(), cfg, "run1", "agent1", ip, now, now, nil)
		// Must fail on the IP itself, before any network call: a connection
		// error to the dead console URL would be a false pass.
		if err == nil || !strings.Contains(err.Error(), "agent IP") {
			t.Errorf("agent IP %q: err = %v, want an agent IP validation error", ip, err)
		}
	}
}

func TestCorrelate_UnsupportedProviderIsAnError(t *testing.T) {
	now := time.Now()
	_, err := Correlate(context.Background(), Config{Provider: ProviderSplunk, ConsoleURL: "http://x"}, "r", "a", "10.0.0.5", now, now, nil)
	if err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Fatalf("err = %v, want a not-yet-supported error", err)
	}
}

// A failed results fetch must not look like "no alerts": that would score
// every executed technique as undetected.
func TestCorrelate_QRadarResultsHTTPErrorIsNotSilent(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	cfg, stop := fakeQRadar(t, nil, http.StatusInternalServerError)
	defer stop()
	_, err := Correlate(context.Background(), cfg, "run1", "agent1", "10.0.0.5",
		t0, t0.Add(time.Minute), []models.SimulationResult{result("T1", models.ResultFail, t0, 0)})
	if err == nil {
		t.Fatal("Correlate returned no error for a 500 from QRadar results")
	}
}

func TestQRadarPing_AuthFailureIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := newQRadarClient(Config{ConsoleURL: srv.URL, Token: "bad"}).Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("Ping err = %v, want authentication failed", err)
	}
}
