package crowdstrike

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
		w.Write([]byte(`{"access_token":"tok","expires_in":1800}`))
	}))
}

func newTestClient(t *testing.T, tokenURL, apiURL string) *Client {
	t.Helper()
	c := New(Config{BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.QueryURL = apiURL + "/alerts/queries/alerts/v2"
	c.DetailURL = apiURL + "/alerts/entities/alerts/v2"
	return c
}

func TestQueryAlerts_TechniqueTaggedAlert_Returned(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 17, 10, 0, 20, 0, time.UTC)
	var detailCalled bool
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/alerts/queries/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []string{"a1", "a2"}})
		case r.Method == http.MethodPost && r.URL.Path == "/alerts/entities/alerts/v2":
			detailCalled = true
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{
				{
					"composite_id": "a1", "name": "Suspicious PowerShell", "severity": 80,
					"created_timestamp": alertTime.Format(time.RFC3339),
					"behaviors":         []map[string]any{{"technique_id": "T1059.001"}},
				},
				{
					"composite_id": "a2", "name": "Generic Alert", "severity": 20,
					"created_timestamp": alertTime.Add(time.Second).Format(time.RFC3339),
					"behaviors":         []map[string]any{},
				},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), AlertQuery{
		Hostname: "HOST1", WindowStart: alertTime.Add(-time.Hour), WindowEnd: alertTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if !detailCalled {
		t.Fatal("expected the detail endpoint to be called when resources is non-empty")
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v, want 2", alerts)
	}
	if alerts[0].AlertID != "a1" || len(alerts[0].Techniques) != 1 || alerts[0].Techniques[0] != "T1059.001" {
		t.Fatalf("alerts[0] = %+v, want a1 tagged with T1059.001", alerts[0])
	}
}

func TestQueryAlerts_NoResources_SkipsDetail(t *testing.T) {
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

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), AlertQuery{Hostname: "HOST1"})
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("alerts = %+v, want none", alerts)
	}
	if detailCalled {
		t.Fatal("detail endpoint should not be called when the query returns no resources")
	}
}

func TestQueryAlerts_QueryHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	if _, err := c.QueryAlerts(context.Background(), AlertQuery{Hostname: "HOST1"}); err == nil {
		t.Fatal("expected an error from a 500 query response")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
