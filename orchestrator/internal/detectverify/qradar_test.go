package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestQRadarConnector(t *testing.T, baseURL string) *qradarConnector {
	t.Helper()
	c := newQRadarConnector(Config{Provider: "qradar", BaseURL: baseURL, APIToken: "tok"})
	c.pollInterval = time.Millisecond
	return c
}

func qradarServer(t *testing.T, statuses []string, results map[string]any) *httptest.Server {
	t.Helper()
	pollCount := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/ariel/searches":
			json.NewEncoder(w).Encode(map[string]any{"search_id": "s1", "status": "WAIT"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/ariel/searches/s1":
			status := statuses[len(statuses)-1]
			if pollCount < len(statuses) {
				status = statuses[pollCount]
			}
			pollCount++
			json.NewEncoder(w).Encode(map[string]any{"search_id": "s1", "status": status})
		case r.Method == http.MethodGet && r.URL.Path == "/api/ariel/searches/s1/results":
			json.NewEncoder(w).Encode(results)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestQRadarVerify_TechniqueTaggedEvent_Detected(t *testing.T) {
	stepTime := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(30 * time.Second)
	results := map[string]any{
		"events": []map[string]any{
			{"starttime": alertTime.UnixMilli(), "rulename": "Suspicious PowerShell", "magnitude": 7, "mitre_technique": "T1059.001"},
			{"starttime": alertTime.Add(time.Second).UnixMilli(), "rulename": "Generic Event", "magnitude": 3},
		},
	}
	srv := qradarServer(t, []string{"WAIT", "COMPLETED"}, results)
	defer srv.Close()

	c := newTestQRadarConnector(t, srv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1059.001", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if result.DetectionLatency != 30*time.Second {
		t.Fatalf("DetectionLatency = %v, want 30s", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 2 {
		t.Fatalf("MatchedAlerts = %+v, want 2", result.MatchedAlerts)
	}
}

func TestQRadarVerify_NoEvents_NotDetected(t *testing.T) {
	srv := qradarServer(t, []string{"COMPLETED"}, map[string]any{"events": []map[string]any{}})
	defer srv.Close()

	c := newTestQRadarConnector(t, srv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestQRadarVerify_SearchError_ReturnsError(t *testing.T) {
	srv := qradarServer(t, []string{"ERROR"}, nil)
	defer srv.Close()

	c := newTestQRadarConnector(t, srv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from an ERROR search status, not a fabricated NotDetected")
	}
}

func TestQRadarVerify_SubmitHTTPError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestQRadarConnector(t, srv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 500 submit response, not a fabricated NotDetected")
	}
}

// QRadar's events table has no built-in MITRE technique column -- it's
// IBM's Use Case Manager/Cyber Adversary Framework that maps rules to
// ATT&CK, not a queryable AQL field. mitre_technique only resolves if the
// customer has created a Custom Event Property with exactly that name, an
// undocumented prerequisite. QRadar fails this loudly (confirmed: an
// unknown AQL column returns "Field ... does not exist in catalog"), so
// this isn't a silent-failure bug like the others -- but the raw vendor
// error gives no hint that a setup step is missing, so it's wrapped with
// one.
func TestQRadarVerify_MitreTechniqueFieldMissing_ErrorExplainsSetup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"message": `Field "mitre_technique" does not exist in catalog "events"`,
			"code":    2000,
		})
	}))
	defer srv.Close()

	c := newTestQRadarConnector(t, srv.URL)
	_, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Custom Event Property") {
		t.Fatalf("error = %q, want it to explain the mitre_technique Custom Event Property setup step", err.Error())
	}
}

func TestQRadarTestConnection_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"buildVersion": "7.5"})
	}))
	defer srv.Close()

	c := newTestQRadarConnector(t, srv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
