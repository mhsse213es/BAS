package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestSentinelConnector(t *testing.T, tokenURL, queryURL string) *sentinelConnector {
	t.Helper()
	c := newSentinelConnector(Config{
		Provider: "microsoft_sentinel", TenantID: "t1", ClientID: "c1", ClientSecret: "s1", WorkspaceID: "w1",
	})
	c.tokens.tokenURL = tokenURL
	c.queryURL = queryURL
	return c
}

func TestSentinelVerify_TechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(90 * time.Second)
	queryResp := map[string]any{
		"tables": []map[string]any{
			{
				"columns": []map[string]string{
					{"name": "TimeGenerated"}, {"name": "AlertName"}, {"name": "AlertSeverity"},
					{"name": "SystemAlertId"}, {"name": "Techniques"},
				},
				"rows": [][]any{
					{alertTime.Format(time.RFC3339), "Suspicious PowerShell", "High", "alert-1", "T1059.001"},
				},
			},
		},
	}
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(queryResp)
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
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
	if result.DetectionLatency != 90*time.Second {
		t.Fatalf("DetectionLatency = %v, want 90s", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 1 || result.MatchedAlerts[0].AlertID != "alert-1" {
		t.Fatalf("MatchedAlerts = %+v", result.MatchedAlerts)
	}
}

func TestSentinelVerify_NoAlerts_NotDetected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"tables": []map[string]any{{"columns": []map[string]string{}, "rows": [][]any{}}},
		})
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestSentinelVerify_QueryHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 500 query response, not a fabricated NotDetected")
	}
}

func TestSentinelTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tables": []map[string]any{}})
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
