package emailgwefficacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/defender"
)

func defenderTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func TestDefenderDetectionProvider_HTTPTestServer_MapsAlertsToDetectionEvidence(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Phish delivered to finance-test@example-lab.test",
					"severity": "medium", "createdDateTime": alertTime.Format(time.RFC3339),
				},
				{
					"id": "alert-2", "title": "Unrelated malware alert",
					"severity": "high", "createdDateTime": alertTime.Format(time.RFC3339),
				},
			},
		})
	}))
	defer graphSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	provider := NewDefenderDetectionProviderFromClient(client)

	msg := MessageRef{SenderProfile: "spoofed-exec-display-name", Recipient: "finance-test@example-lab.test", MessageClass: "spf-fail"}
	window := TimeWindow{Start: alertTime.Add(-time.Hour), End: alertTime.Add(time.Hour)}
	records, err := provider.DetectionEvidenceFor(msg, window)
	if err != nil {
		t.Fatalf("DetectionEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want exactly 1 (only the correlated alert)", records)
	}
	rec := records[0]
	if !rec.AlertGenerated {
		t.Error("AlertGenerated = false, want true -- a matched Graph alert is a positive detection signal")
	}
	if rec.CorrelationID != "alert-1" {
		t.Errorf("CorrelationID = %q, want %q", rec.CorrelationID, "alert-1")
	}
	if rec.Source != SourceLive {
		t.Errorf("Source = %q, want %q", rec.Source, SourceLive)
	}
	if rec.Provenance.Kind != ProvenanceObserved {
		t.Errorf("Provenance.Kind = %q, want %q", rec.Provenance.Kind, ProvenanceObserved)
	}
}

func TestDefenderDetectionProvider_HTTPError_ReturnsError(t *testing.T) {
	tokenSrv := defenderTokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	client := defender.New(defender.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	provider := NewDefenderDetectionProviderFromClient(client)

	_, err := provider.DetectionEvidenceFor(MessageRef{Recipient: "finance-test@example-lab.test"}, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if err == nil {
		t.Fatal("expected an error from a 403 Graph response")
	}
}

// TestDefenderDetectionProvider_RealAPI_SkipsWithoutCredentials is the
// live-tenant integration test. It skips, not fails, when tenant
// credentials aren't provided -- see docs/emailgw-mastery-qa-log.md
// item #1. Setting all three env vars exercises it against a real
// Microsoft 365 Defender for Office 365 tenant with zero code changes.
func TestDefenderDetectionProvider_RealAPI_SkipsWithoutCredentials(t *testing.T) {
	tenantID := os.Getenv("AUDSPECT_EMAILGW_DEFENDER_TENANT_ID")
	clientID := os.Getenv("AUDSPECT_EMAILGW_DEFENDER_CLIENT_ID")
	clientSecret := os.Getenv("AUDSPECT_EMAILGW_DEFENDER_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		t.Skip("AUDSPECT_EMAILGW_DEFENDER_{TENANT_ID,CLIENT_ID,CLIENT_SECRET} not set -- skipping real Graph API test (docs/emailgw-mastery-qa-log.md item #1)")
	}

	provider := NewDefenderDetectionProvider(defender.Config{TenantID: tenantID, ClientID: clientID, ClientSecret: clientSecret})
	_, err := provider.DetectionEvidenceFor(
		MessageRef{Recipient: "smoke-test@example-lab.test"},
		TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()},
	)
	if err != nil {
		t.Fatalf("DetectionEvidenceFor against the real tenant: %v", err)
	}
}
