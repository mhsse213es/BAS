package defender

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

func newTestClient(t *testing.T, tokenURL, graphURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.BaseURL = graphURL
	return c
}

func TestQueryAlerts_ReturnsNormalizedAlerts(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Suspicious process", "severity": "high",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "HOST1"}},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if alerts[0].ID != "alert-1" || alerts[0].DeviceDNSName != "HOST1" || len(alerts[0].Techniques) != 1 {
		t.Fatalf("alerts[0] = %+v, want alert-1/HOST1/[T1055]", alerts[0])
	}
}

func TestQueryAlerts_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.QueryAlerts(context.Background(), time.Now().Add(-time.Hour), time.Now()); err == nil {
		t.Fatal("expected an error from a 403 Graph response")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
