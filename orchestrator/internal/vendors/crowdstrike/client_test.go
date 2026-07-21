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

func newTestClientWithDeviceAndActionURLs(t *testing.T, tokenURL, deviceURL, actionURL string) *Client {
	t.Helper()
	c := New(Config{BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.DeviceQueryURL = deviceURL
	c.ActionURL = actionURL
	return c
}

func TestResolveDevice_FindsAndCaches(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var queryCalls int
	deviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCalls++
		if r.URL.Query().Get("filter") != `hostname:'HOST1'` {
			t.Errorf("filter = %q", r.URL.Query().Get("filter"))
		}
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{"device-123"}})
	}))
	defer deviceSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, deviceSrv.URL, "")
	id, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if id != "device-123" {
		t.Fatalf("id = %q, want device-123", id)
	}

	// Second call within the TTL must hit the cache, not the API again.
	id2, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice (cached): %v", err)
	}
	if id2 != "device-123" {
		t.Fatalf("cached id = %q, want device-123", id2)
	}
	if queryCalls != 1 {
		t.Fatalf("queryCalls = %d, want 1 (second ResolveDevice should reuse the cache)", queryCalls)
	}
}

func TestResolveDevice_NoMatch_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	deviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer deviceSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, deviceSrv.URL, "")
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); err == nil {
		t.Fatal("expected an error when no device matches the hostname")
	}
}

func TestIsolate_SendsContainAction(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotActionName string
	var gotBody map[string][]string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActionName = r.URL.Query().Get("action_name")
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"trace_id": "trace-abc"}})
	}))
	defer actionSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", actionSrv.URL)
	traceID, err := c.Isolate(context.Background(), "device-123")
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if traceID != "trace-abc" {
		t.Fatalf("traceID = %q, want trace-abc", traceID)
	}
	if gotActionName != "contain" {
		t.Fatalf("action_name = %q, want contain", gotActionName)
	}
	if len(gotBody["ids"]) != 1 || gotBody["ids"][0] != "device-123" {
		t.Fatalf("body ids = %v, want [device-123]", gotBody["ids"])
	}
}

func TestRelease_SendsLiftContainmentAction(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotActionName string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActionName = r.URL.Query().Get("action_name")
		json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"trace_id": "trace-def"}})
	}))
	defer actionSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", actionSrv.URL)
	traceID, err := c.Release(context.Background(), "device-123")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if traceID != "trace-def" {
		t.Fatalf("traceID = %q, want trace-def", traceID)
	}
	if gotActionName != "lift_containment" {
		t.Fatalf("action_name = %q, want lift_containment", gotActionName)
	}
}

func TestDeviceAction_VendorReportsError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"message": "device not found"}}})
	}))
	defer actionSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", actionSrv.URL)
	if _, err := c.Isolate(context.Background(), "device-999"); err == nil {
		t.Fatal("expected an error when the vendor response body carries an errors[] entry")
	}
}
