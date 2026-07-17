package detectverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestSplunkConnector(t *testing.T, exportURL string) *splunkConnector {
	t.Helper()
	c := newSplunkConnector(Config{Provider: "splunk", BaseURL: "https://splunk.example:8089", APIToken: "tok"})
	c.exportURL = exportURL
	return c
}

func TestSplunkVerify_TechniqueTaggedAlert_Detected(t *testing.T) {
	stepTime := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(45 * time.Second)
	body := `{"result":{"_time":"` + alertTime.Format(time.RFC3339) + `","rule_title":"Suspicious PowerShell","severity":"high","event_id":"evt-1","annotations.mitre_attack":["T1059.001"]}}
{"result":{"_time":"` + alertTime.Add(time.Second).Format(time.RFC3339) + `","rule_title":"Generic Notable","severity":"medium","event_id":"evt-2"}}
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c := newTestSplunkConnector(t, srv.URL)
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
	if result.DetectionLatency != 45*time.Second {
		t.Fatalf("DetectionLatency = %v, want 45s", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 2 {
		t.Fatalf("MatchedAlerts = %+v, want 2", result.MatchedAlerts)
	}
	if result.MatchedAlerts[0].AlertID != "evt-1" {
		t.Fatalf("MatchedAlerts[0].AlertID = %q, want evt-1", result.MatchedAlerts[0].AlertID)
	}
}

func TestSplunkVerify_NoAlerts_NotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	}))
	defer srv.Close()

	c := newTestSplunkConnector(t, srv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestSplunkVerify_QueryHTTPError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestSplunkConnector(t, srv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 500 query response, not a fabricated NotDetected")
	}
}

func TestSplunkTestConnection_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{}}` + "\n"))
	}))
	defer srv.Close()

	c := newTestSplunkConnector(t, srv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
