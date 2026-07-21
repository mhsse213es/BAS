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

func newTestClientWithActionURLs(t *testing.T, tokenURL, actionTokenURL, actionBaseURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	*c.ActionTokenURL() = actionTokenURL
	c.ActionBaseURL = actionBaseURL
	return c
}

func TestResolveDevice_FindsAndCaches(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var queryCalls int
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCalls++
		if r.URL.Query().Get("$filter") != "computerDnsName eq 'HOST1'" {
			t.Errorf("$filter = %q", r.URL.Query().Get("$filter"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "machine-123", "computerDnsName": "HOST1"}},
		})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	id, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if id != "machine-123" {
		t.Fatalf("id = %q, want machine-123", id)
	}

	id2, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice (cached): %v", err)
	}
	if id2 != "machine-123" {
		t.Fatalf("cached id = %q, want machine-123", id2)
	}
	if queryCalls != 1 {
		t.Fatalf("queryCalls = %d, want 1 (second ResolveDevice should reuse the cache)", queryCalls)
	}
}

func TestResolveDevice_NoMatch_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); err == nil {
		t.Fatal("expected an error when no machine matches the hostname")
	}
}

func TestIsolate_CallsIsolateEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	var gotBody map[string]any
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "action-abc"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.Isolate(context.Background(), "machine-123")
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if actionID != "action-abc" {
		t.Fatalf("actionID = %q, want action-abc", actionID)
	}
	if gotPath != "/machines/machine-123/isolate" {
		t.Fatalf("path = %q, want /machines/machine-123/isolate", gotPath)
	}
	if gotBody["IsolationType"] != "Full" {
		t.Fatalf("body = %v, want IsolationType=Full", gotBody)
	}
}

func TestRelease_CallsUnisolateEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"id": "action-def"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.Release(context.Background(), "machine-123")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if actionID != "action-def" {
		t.Fatalf("actionID = %q, want action-def", actionID)
	}
	if gotPath != "/machines/machine-123/unisolate" {
		t.Fatalf("path = %q, want /machines/machine-123/unisolate", gotPath)
	}
}

func TestMachineAction_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.Isolate(context.Background(), "machine-999"); err == nil {
		t.Fatal("expected an error from a 403 machine action response")
	}
}

func TestQuarantineFile_CallsStopAndQuarantineFileEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	var gotBody map[string]any
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "action-quarantine-1"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.QuarantineFile(context.Background(), "machine-123", "aabbccddeeff00112233445566778899aabbccdd")
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if actionID != "action-quarantine-1" {
		t.Fatalf("actionID = %q, want action-quarantine-1", actionID)
	}
	if gotPath != "/machines/machine-123/StopAndQuarantineFile" {
		t.Fatalf("path = %q, want /machines/machine-123/StopAndQuarantineFile", gotPath)
	}
	if gotBody["Sha1"] != "aabbccddeeff00112233445566778899aabbccdd" {
		t.Fatalf("body Sha1 = %v, want the test sha1", gotBody["Sha1"])
	}
}

func TestQuarantineFile_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.QuarantineFile(context.Background(), "machine-123", "badhash"); err == nil {
		t.Fatal("expected an error from a 400 StopAndQuarantineFile response")
	}
}
