package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestCrowdStrikeConnector(t *testing.T, tokenURL, apiURL string) *crowdstrikeConnector {
	t.Helper()
	c := newCrowdStrikeConnector(Config{Provider: "crowdstrike", BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	c.tokens.tokenURL = tokenURL
	c.queryURL = apiURL + "/alerts/queries/alerts/v2"
	c.detailURL = apiURL + "/alerts/entities/alerts/v2"
	return c
}

func TestCrowdStrikeVerify_TechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(20 * time.Second)
	var detailCalled bool
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/alerts/queries/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []string{"a1", "a2"}})
		case r.Method == http.MethodPost && r.URL.Path == "/alerts/entities/alerts/v2":
			detailCalled = true
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{
				{
					"composite_id":      "a1",
					"name":              "Suspicious PowerShell",
					"severity":          80,
					"created_timestamp": alertTime.Format(time.RFC3339),
					"behaviors":         []map[string]any{{"technique_id": "T1059.001"}},
				},
				{
					"composite_id":      "a2",
					"name":              "Generic Alert",
					"severity":          20,
					"created_timestamp": alertTime.Add(time.Second).Format(time.RFC3339),
					"behaviors":         []map[string]any{},
				},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1059.001", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !detailCalled {
		t.Fatal("expected the detail endpoint to be called when resources is non-empty")
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if result.DetectionLatency != 20*time.Second {
		t.Fatalf("DetectionLatency = %v, want 20s", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 2 {
		t.Fatalf("MatchedAlerts = %+v, want 2", result.MatchedAlerts)
	}
}

func TestCrowdStrikeVerify_NoResources_NotDetected_SkipsDetail(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var detailCalled bool
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/alerts/queries/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
		case r.Method == http.MethodPost && r.URL.Path == "/alerts/entities/alerts/v2":
			detailCalled = true
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{}})
		}
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
	if detailCalled {
		t.Fatal("detail endpoint should not be called when the query returns no resources")
	}
}

func TestCrowdStrikeVerify_QueryHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 500 query response, not a fabricated NotDetected")
	}
}

func TestCrowdStrikeTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
