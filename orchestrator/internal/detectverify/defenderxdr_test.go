package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestDefenderXDRConnector(t *testing.T, tokenURL, graphURL string) *defenderXDRConnector {
	t.Helper()
	c := newDefenderXDRConnector(Config{Provider: "microsoft_defender", TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.client.TokenURL() = tokenURL
	c.client.BaseURL = graphURL
	return c
}

func TestDefenderXDRVerify_HostMatchedTechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(2 * time.Minute)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Suspicious process", "severity": "high",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "HOST1"}},
				},
				{
					"id": "alert-2", "title": "Unrelated host alert", "severity": "low",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "OTHERHOST"}},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1055", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if len(result.MatchedAlerts) != 1 || result.MatchedAlerts[0].AlertID != "alert-1" {
		t.Fatalf("MatchedAlerts = %+v, want only alert-1 (the OTHERHOST alert must be filtered out)", result.MatchedAlerts)
	}
}

func TestDefenderXDRVerify_NoMatchingHost_NotDetected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "alert-1", "createdDateTime": time.Now().Format(time.RFC3339), "evidence": []map[string]any{{"deviceDnsName": "OTHERHOST"}}},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1055", HostName: "HOST1", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestDefenderXDRVerify_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1055", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 403 Graph response, not a fabricated NotDetected")
	}
}
